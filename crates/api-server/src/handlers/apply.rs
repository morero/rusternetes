//! Server-Side Apply handler for Kubernetes API compatibility
//!
//! Provides /apply endpoints that implement server-side apply semantics
//! with field manager tracking and conflict detection.

#![allow(dead_code)]

use crate::{middleware::AuthContext, state::ApiServerState};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    Extension, Json,
};
use rusternetes_common::{
    authz::{Decision, RequestAttributes},
    server_side_apply::{server_side_apply, ApplyParams, ApplyResult},
    Result,
};
use rusternetes_storage::{build_key, Storage};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tracing::info;

/// Server-side apply's create path deserializes the applied JSON straight
/// into the caller's generic `T` and saves it — unlike every dedicated
/// typed create handler (e.g. `service_account::create_service_account`),
/// which explicitly calls `ObjectMeta::ensure_uid()`/
/// `ensure_creation_timestamp()` before saving. A client never sets these
/// itself, so on first creation via apply they were silently left empty:
/// confirmed live (a `ServiceAccount` created this way had `metadata.uid:
/// ""`), and consequential beyond just an odd status field — the
/// kubelet-minted service-account token for a pod using that
/// `ServiceAccount` embeds its UID, and the api-server's own token
/// verification rejects a token whose embedded UID doesn't match a real,
/// non-empty `ServiceAccount` UID ("Invalid token", indistinguishable
/// from a genuinely bad token). Fixed by enriching the same way the typed
/// handlers do, applied directly to the JSON value (this function is
/// generic over `T`, so it can't call `ObjectMeta` methods without a
/// trait bound every call site would need) — only on the create path;
/// update-path objects already have real values from their first create.
///
/// Shared with `handlers::generic_patch`'s `patch_namespaced_resource`/
/// `patch_cluster_resource` — this module's own `apply_namespaced_resource`/
/// `apply_cluster_resource` turned out to be *dead code*: real built-in
/// resource types (confirmed for `ServiceAccount`) route their SSA-typed
/// `PATCH` requests to `generic_patch`'s content-type-dispatching
/// handlers instead (see `router.rs` — `.patch(handlers::service_account::patch)`,
/// not anything in this file), which independently reimplement the exact
/// same create-vs-update logic and had the exact same gap. Fixing only
/// this file's copy was verified live to do nothing at all.
pub(crate) fn ensure_metadata_defaults_on_create(applied_json: &mut serde_json::Value) {
    let Some(metadata) = applied_json.get_mut("metadata") else {
        return;
    };
    let Some(metadata) = metadata.as_object_mut() else {
        return;
    };
    let uid_is_empty = metadata
        .get("uid")
        .and_then(|v| v.as_str())
        .is_none_or(str::is_empty);
    if uid_is_empty {
        metadata.insert(
            "uid".to_string(),
            serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
        );
    }
    if !metadata.contains_key("creationTimestamp") || metadata["creationTimestamp"].is_null() {
        metadata.insert(
            "creationTimestamp".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );
    }
}

/// Query parameters for server-side apply
#[derive(Debug, serde::Deserialize)]
pub struct ApplyQueryParams {
    /// Field manager name (required)
    #[serde(rename = "fieldManager")]
    field_manager: String,

    /// Force apply (override conflicts)
    #[serde(default)]
    force: bool,
}

/// Generic Server-Side Apply handler for namespaced resources
///
/// # Type Parameters
/// - `T`: The resource type (must implement Serialize + DeserializeOwned)
///
/// # Parameters
/// - `state`: API server state
/// - `auth_ctx`: Authentication context
/// - `namespace`: Resource namespace
/// - `name`: Resource name
/// - `query`: Query parameters (fieldManager, force)
/// - `body`: Resource manifest to apply
/// - `resource_type`: Resource type name (e.g., "deployments", "services")
/// - `api_group`: API group (e.g., "apps", "" for core)
///
/// # Returns
/// Resource after applying changes with managed fields updated
pub async fn apply_namespaced_resource<T>(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((namespace, name)): Path<(String, String)>,
    Query(query): Query<ApplyQueryParams>,
    body: Bytes,
    resource_type: &str,
    api_group: &str,
) -> Result<Json<T>>
where
    T: Serialize + DeserializeOwned + Send + Sync,
{
    info!(
        "Server-side apply {} {}/{} by manager {}",
        resource_type, namespace, name, query.field_manager
    );

    // Check authorization - use 'patch' verb for RBAC (apply is similar to patch)
    let attrs = RequestAttributes::new(auth_ctx.user, "patch", resource_type)
        .with_namespace(&namespace)
        .with_api_group(api_group)
        .with_name(&name);

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Parse desired resource
    let desired_json: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("Invalid resource: {}", e))
    })?;

    // Get current resource (if exists)
    let key = build_key(resource_type, Some(&namespace), &name);
    let current_json = match state.storage.get::<T>(&key).await {
        Ok(current) => Some(
            serde_json::to_value(&current)
                .map_err(|e| rusternetes_common::Error::Internal(e.to_string()))?,
        ),
        Err(rusternetes_common::Error::NotFound(_)) => None,
        Err(e) => return Err(e),
    };

    // Apply with server-side apply semantics
    let apply_params = if query.force {
        ApplyParams::new(query.field_manager).with_force()
    } else {
        ApplyParams::new(query.field_manager)
    };

    let result = server_side_apply(current_json.as_ref(), &desired_json, &apply_params)
        .map_err(|e| rusternetes_common::Error::InvalidResource(e.to_string()))?;

    match result {
        ApplyResult::Success(mut applied_json) => {
            let is_create = current_json.is_none();
            if is_create {
                ensure_metadata_defaults_on_create(&mut applied_json);
            }
            // Convert to resource type
            let applied_resource: T = serde_json::from_value(applied_json).map_err(|e| {
                rusternetes_common::Error::InvalidResource(format!("Invalid result: {}", e))
            })?;

            // Save to storage (create or update)
            let saved = if is_create {
                state.storage.create(&key, &applied_resource).await?
            } else {
                state.storage.update(&key, &applied_resource).await?
            };

            Ok(Json(saved))
        }
        ApplyResult::Conflicts(conflicts) => {
            // Return 409 Conflict with details
            let conflict_details: Vec<String> = conflicts
                .iter()
                .map(|c| {
                    format!(
                        "Field '{}' is owned by '{}' (applying as '{}')",
                        c.field, c.current_manager, c.applying_manager
                    )
                })
                .collect();

            Err(rusternetes_common::Error::Conflict(format!(
                "Apply conflict: {}. Use force=true to override.",
                conflict_details.join("; ")
            )))
        }
    }
}

/// Generic Server-Side Apply handler for cluster-scoped resources
///
/// # Type Parameters
/// - `T`: The resource type (must implement Serialize + DeserializeOwned)
///
/// # Parameters
/// - `state`: API server state
/// - `auth_ctx`: Authentication context
/// - `name`: Resource name
/// - `query`: Query parameters (fieldManager, force)
/// - `body`: Resource manifest to apply
/// - `resource_type`: Resource type name (e.g., "nodes", "clusterroles")
/// - `api_group`: API group (e.g., "rbac.authorization.k8s.io", "" for core)
///
/// # Returns
/// Resource after applying changes with managed fields updated
pub async fn apply_cluster_resource<T>(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(name): Path<String>,
    Query(query): Query<ApplyQueryParams>,
    body: Bytes,
    resource_type: &str,
    api_group: &str,
) -> Result<Json<T>>
where
    T: Serialize + DeserializeOwned + Send + Sync,
{
    info!(
        "Server-side apply cluster-scoped {} {} by manager {}",
        resource_type, name, query.field_manager
    );

    // Check authorization
    let attrs = RequestAttributes::new(auth_ctx.user, "patch", resource_type)
        .with_api_group(api_group)
        .with_name(&name);

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Parse desired resource
    let desired_json: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("Invalid resource: {}", e))
    })?;

    // Get current resource (if exists)
    let key = build_key(resource_type, None, &name);
    let current_json = match state.storage.get::<T>(&key).await {
        Ok(current) => Some(
            serde_json::to_value(&current)
                .map_err(|e| rusternetes_common::Error::Internal(e.to_string()))?,
        ),
        Err(rusternetes_common::Error::NotFound(_)) => None,
        Err(e) => return Err(e),
    };

    // Apply with server-side apply semantics
    let apply_params = if query.force {
        ApplyParams::new(query.field_manager).with_force()
    } else {
        ApplyParams::new(query.field_manager)
    };

    let result = server_side_apply(current_json.as_ref(), &desired_json, &apply_params)
        .map_err(|e| rusternetes_common::Error::InvalidResource(e.to_string()))?;

    match result {
        ApplyResult::Success(mut applied_json) => {
            let is_create = current_json.is_none();
            if is_create {
                ensure_metadata_defaults_on_create(&mut applied_json);
            }
            // Convert to resource type
            let applied_resource: T = serde_json::from_value(applied_json).map_err(|e| {
                rusternetes_common::Error::InvalidResource(format!("Invalid result: {}", e))
            })?;

            // Save to storage (create or update)
            let saved = if is_create {
                state.storage.create(&key, &applied_resource).await?
            } else {
                state.storage.update(&key, &applied_resource).await?
            };

            Ok(Json(saved))
        }
        ApplyResult::Conflicts(conflicts) => {
            // Return 409 Conflict with details
            let conflict_details: Vec<String> = conflicts
                .iter()
                .map(|c| {
                    format!(
                        "Field '{}' is owned by '{}' (applying as '{}')",
                        c.field, c.current_manager, c.applying_manager
                    )
                })
                .collect();

            Err(rusternetes_common::Error::Conflict(format!(
                "Apply conflict: {}. Use force=true to override.",
                conflict_details.join("; ")
            )))
        }
    }
}

/// Macro to create a Server-Side Apply handler for a namespaced resource
///
/// This macro generates a handler function that calls the generic apply implementation
/// with the appropriate resource type and metadata.
///
/// # Example
/// ```ignore
/// apply_handler_namespaced!(apply_deployment, Deployment, "deployments", "apps");
/// ```
#[macro_export]
macro_rules! apply_handler_namespaced {
    ($handler_name:ident, $resource_type:ty, $resource_name:expr, $api_group:expr) => {
        pub async fn $handler_name(
            state: axum::extract::State<std::sync::Arc<$crate::state::ApiServerState>>,
            auth_ctx: axum::Extension<$crate::middleware::AuthContext>,
            path: axum::extract::Path<(String, String)>,
            query: axum::extract::Query<$crate::handlers::apply::ApplyQueryParams>,
            body: axum::body::Bytes,
        ) -> rusternetes_common::Result<axum::Json<$resource_type>> {
            $crate::handlers::apply::apply_namespaced_resource::<$resource_type>(
                state,
                auth_ctx,
                path,
                query,
                body,
                $resource_name,
                $api_group,
            )
            .await
        }
    };
}

/// Macro to create a Server-Side Apply handler for a cluster-scoped resource
///
/// This macro generates a handler function that calls the generic apply implementation
/// with the appropriate resource type and metadata.
///
/// # Example
/// ```ignore
/// apply_handler_cluster!(apply_node, Node, "nodes", "");
/// ```
#[macro_export]
macro_rules! apply_handler_cluster {
    ($handler_name:ident, $resource_type:ty, $resource_name:expr, $api_group:expr) => {
        pub async fn $handler_name(
            state: axum::extract::State<std::sync::Arc<$crate::state::ApiServerState>>,
            auth_ctx: axum::Extension<$crate::middleware::AuthContext>,
            path: axum::extract::Path<String>,
            query: axum::extract::Query<$crate::handlers::apply::ApplyQueryParams>,
            body: axum::body::Bytes,
        ) -> rusternetes_common::Result<axum::Json<$resource_type>> {
            $crate::handlers::apply::apply_cluster_resource::<$resource_type>(
                state,
                auth_ctx,
                path,
                query,
                body,
                $resource_name,
                $api_group,
            )
            .await
        }
    };
}

#[cfg(test)]
mod ensure_metadata_defaults_tests {
    use super::ensure_metadata_defaults_on_create;
    use serde_json::json;

    #[test]
    fn fills_in_empty_uid_and_missing_creation_timestamp() {
        let mut applied = json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "cnpg-operator", "namespace": "default", "uid": ""}
        });
        ensure_metadata_defaults_on_create(&mut applied);
        let uid = applied["metadata"]["uid"].as_str().unwrap();
        assert!(!uid.is_empty());
        assert!(uuid::Uuid::parse_str(uid).is_ok());
        assert!(applied["metadata"]["creationTimestamp"].is_string());
    }

    #[test]
    fn leaves_an_already_set_uid_untouched() {
        let mut applied = json!({
            "metadata": {"name": "x", "uid": "existing-uid", "creationTimestamp": "2026-01-01T00:00:00Z"}
        });
        ensure_metadata_defaults_on_create(&mut applied);
        assert_eq!(applied["metadata"]["uid"], "existing-uid");
        assert_eq!(
            applied["metadata"]["creationTimestamp"],
            "2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn missing_metadata_object_does_not_panic() {
        let mut applied = json!({"apiVersion": "v1", "kind": "ServiceAccount"});
        ensure_metadata_defaults_on_create(&mut applied);
        assert!(applied.get("metadata").is_none());
    }
}
