//! Custom Resource (CR) API handlers for dynamically created CRDs
//!
//! This module handles CRUD operations for custom resources defined by CRDs.

#![allow(dead_code)]

use crate::{middleware::AuthContext, state::ApiServerState};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use rusternetes_common::{
    authz::{Decision, RequestAttributes},
    resources::{CustomResource, CustomResourceDefinition},
    schema_validation::SchemaValidator,
    List, Result,
};
use rusternetes_storage::{build_key, build_prefix, Storage};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Whether an update/patch to a custom resource just cleared its last
/// finalizer while a deletion was already pending. Real Kubernetes'
/// generic apiserver store completes a pending deletion the instant a
/// controller's update removes the last finalizer — it doesn't wait for a
/// fresh DELETE request (see k8s.io/apiserver's
/// registry/generic/registry/store.go, shouldDeleteDuringUpdate). Without
/// this check, an object whose finalizers all get cleared via UPDATE/PATCH
/// (rather than a client re-issuing DELETE) sits in storage forever with
/// deletionTimestamp set and an empty finalizers list — live-hit: a Release
/// stayed listable indefinitely after release-operator removed its own
/// `platform.ertia.io/release-bindings` finalizer via a merge patch.
fn should_complete_pending_deletion(cr: &CustomResource) -> bool {
    cr.metadata.deletion_timestamp.is_some()
        && cr
            .metadata
            .finalizers
            .as_ref()
            .is_none_or(|f| f.is_empty())
}

/// Create a new custom resource instance
pub async fn create_custom_resource(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace)): Path<(String, String, String, Option<String>)>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<(StatusCode, Json<CustomResource>)> {
    // Parse the body manually so we can do strict field validation against the raw bytes
    let mut cr: CustomResource = serde_json::from_slice(&body).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("failed to decode: {}", e))
    })?;

    // Names must be RFC 1123 subdomains, exactly as for built-in kinds.
    // Custom resources skipped this entirely until now, and the failure is a
    // one-way door rather than a cosmetic one: a name containing a space was
    // accepted, and the object then became permanently unreachable — the
    // space percent-encodes on the way out, is not decoded on the way back
    // in, so every get/delete returns NotFound while the object still shows
    // up in list output. It cannot be removed through the API at all.
    //
    // `validate_resource_name` already existed for this; it was simply never
    // called here (only `configmap` and `secret` used it).
    crate::handlers::validation::validate_resource_name(&cr.metadata.name)?;

    let cr_name = cr.metadata.name.clone();
    info!(
        "Creating custom resource {}/{}/{}: {}",
        group, version, plural, cr_name
    );

    // Look up the CRD first — we need it to check preserve-unknown-fields
    // before strict validation. CRDs with preserve-unknown-fields allow
    // arbitrary top-level fields even with fieldValidation=Strict.
    let crd_name_for_lookup = format!("{}.{}", plural, group);
    let crd_for_validation = get_crd_for_resource(&state, &crd_name_for_lookup).await?;
    let crd_preserves = crd_for_validation.spec.preserve_unknown_fields == Some(true);
    let schema_preserves = crd_for_validation
        .spec
        .versions
        .iter()
        .find(|v| v.name == version)
        .and_then(|v| v.schema.as_ref())
        .map(|s| s.open_apiv3_schema.x_kubernetes_preserve_unknown_fields == Some(true))
        .unwrap_or(false);

    // Strict field validation for CRDs:
    // K8s ref: staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/customresource_handler.go
    if params.get("fieldValidation").map(|v| v.as_str()) == Some("Strict") {
        // Check unknown top-level fields — but SKIP if CRD preserves unknown fields
        if !cr.extra.is_empty() && !crd_preserves && !schema_preserves {
            let unknown: Vec<&String> = cr.extra.keys().collect();
            return Err(rusternetes_common::Error::InvalidResource(format!(
                "strict decoding error: unknown field \"{}\"",
                unknown[0]
            )));
        }
        // Check unknown metadata fields — K8s validates ObjectMeta strictly,
        // BOTH at root AND in embedded objects (x-kubernetes-embedded-resource).
        // K8s ref: apiextensions-apiserver/pkg/apiserver/schema/objectmeta/validation.go
        if let Ok(body_json) = serde_json::from_slice::<serde_json::Value>(&body) {
            const KNOWN_META: &[&str] = &[
                "name",
                "generateName",
                "namespace",
                "selfLink",
                "uid",
                "resourceVersion",
                "generation",
                "creationTimestamp",
                "deletionTimestamp",
                "deletionGracePeriodSeconds",
                "labels",
                "annotations",
                "ownerReferences",
                "finalizers",
                "managedFields",
                "clusterName",
            ];

            // Recursively find all "metadata" objects in the body and validate them
            fn check_metadata_fields(
                value: &serde_json::Value,
                path: &str,
                known: &[&str],
            ) -> Option<String> {
                if let Some(obj) = value.as_object() {
                    // Check if this object has a "metadata" field
                    if let Some(meta) = obj.get("metadata").and_then(|m| m.as_object()) {
                        let meta_path = if path.is_empty() {
                            ".metadata".to_string()
                        } else {
                            format!("{}.metadata", path)
                        };
                        for key in meta.keys() {
                            if !known.contains(&key.as_str()) {
                                return Some(format!(
                                    "{}.{}: field not declared in schema",
                                    meta_path, key
                                ));
                            }
                        }
                    }
                    // Recurse into all nested objects
                    for (key, val) in obj {
                        if key == "metadata" {
                            continue; // Already checked above
                        }
                        let child_path = if path.is_empty() {
                            format!(".{}", key)
                        } else {
                            format!("{}.{}", path, key)
                        };
                        if let Some(err) = check_metadata_fields(val, &child_path, known) {
                            return Some(err);
                        }
                    }
                } else if let Some(arr) = value.as_array() {
                    for item in arr {
                        if let Some(err) = check_metadata_fields(item, path, known) {
                            return Some(err);
                        }
                    }
                }
                None
            }

            if let Some(err_msg) = check_metadata_fields(&body_json, "", KNOWN_META) {
                return Err(rusternetes_common::Error::InvalidResource(err_msg));
            }
        }
    }
    crate::handlers::validation::validate_strict_fields(&params, &body, &cr)?;

    // Use the CRD we already looked up for preserve-unknown-fields check
    let crd = crd_for_validation;

    // Strict schema validation for nested unknown fields.
    // When fieldValidation=Strict, validate nested fields against the CRD schema
    // and reject unknown fields with K8s-format errors.
    // K8s ref: apiextensions-apiserver/pkg/apiserver/schema/pruning — PruneWithOptions
    if params.get("fieldValidation").map(|v| v.as_str()) == Some("Strict")
        && !crd_preserves
        && !schema_preserves
    {
        if let Some(crd_version) = crd.spec.versions.iter().find(|v| v.name == version) {
            if let Some(ref validation) = crd_version.schema {
                if let Some(ref properties) = validation.open_apiv3_schema.properties {
                    if let Some(spec_schema) = properties.get("spec") {
                        if let Some(ref spec) = cr.spec {
                            SchemaValidator::validate_strict(spec_schema, spec, "spec")?;
                        }
                    }
                }
            }
        }
    }

    // Apply schema defaults before validation
    apply_schema_defaults(&crd, &version, &mut cr);

    // Validate the resource against CRD schema
    validate_custom_resource(&crd, &version, &cr)?;

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "create", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
    } else {
        RequestAttributes::new(auth_ctx.user.clone(), "create", &plural).with_api_group(&group)
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Ensure metadata fields
    cr.metadata.ensure_uid();
    cr.metadata.ensure_creation_timestamp();
    crate::handlers::lifecycle::set_initial_generation(&mut cr.metadata);

    // Set API version and kind
    let kind = crd.spec.names.kind.clone();
    cr.api_version = format!("{}/{}", group, version);
    cr.kind = kind.clone();

    // Run admission webhooks (mutating + validating) for custom resources
    // K8s runs webhooks for ALL resource types including CRDs
    let cr_is_dry_run = crate::handlers::dryrun::is_dry_run(&params);
    {
        let gvk = rusternetes_common::admission::GroupVersionKind {
            group: group.clone(),
            version: version.clone(),
            kind: kind.clone(),
        };
        let gvr = rusternetes_common::admission::GroupVersionResource {
            group: group.clone(),
            version: version.clone(),
            resource: plural.clone(),
        };
        let user_info = rusternetes_common::admission::UserInfo {
            username: auth_ctx.user.username.clone(),
            uid: auth_ctx.user.uid.clone(),
            groups: auth_ctx.user.groups.clone(),
        };
        let cr_val = serde_json::to_value(&cr).ok();
        // Run mutating webhooks
        let (mutation_response, mutated_obj) = state
            .webhook_manager
            .run_mutating_webhooks_with_dryrun(
                &rusternetes_common::admission::Operation::Create,
                &gvk,
                &gvr,
                namespace.as_deref(),
                &cr_name,
                cr_val.clone(),
                None,
                &user_info,
                cr_is_dry_run,
            )
            .await?;
        // K8s mutating webhooks CAN deny — enforce the denial.
        if let rusternetes_common::admission::AdmissionResponse::Deny(reason) = &mutation_response {
            return Err(rusternetes_common::Error::Forbidden(format!(
                "admission webhook denied the request: {}",
                reason
            )));
        }
        if let Some(mutated) = mutated_obj {
            if let Ok(m) = serde_json::from_value::<CustomResource>(mutated) {
                cr = m;
            }
        }
        // Run validating webhooks
        if let rusternetes_common::admission::AdmissionResponse::Deny(reason) = state
            .webhook_manager
            .run_validating_webhooks_with_dryrun(
                &rusternetes_common::admission::Operation::Create,
                &gvk,
                &gvr,
                namespace.as_deref(),
                &cr_name,
                serde_json::to_value(&cr).ok(),
                None,
                &user_info,
                cr_is_dry_run,
            )
            .await?
        {
            return Err(rusternetes_common::Error::Forbidden(format!(
                "admission webhook denied the request: {}",
                reason
            )));
        }
    }

    // K8s structural pruning: remove unknown fields from the CR based on
    // the CRD schema, unless x-kubernetes-preserve-unknown-fields is set.
    // This happens AFTER webhook mutation so webhook-added fields not in
    // the schema are pruned. K8s ref: apiextensions-apiserver/pkg/apiserver/schema/pruning
    prune_custom_resource(&crd, &version, &mut cr);

    // Check for dry-run
    if cr_is_dry_run {
        return Ok((StatusCode::OK, Json(cr)));
    }

    // Build storage key
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &cr_name)
    } else {
        build_key(&resource_type, None, &cr_name)
    };

    let created = state.storage.create(&key, &cr).await?;

    Ok((StatusCode::CREATED, Json(created)))
}

/// Core "fetch one custom resource, checking authz and applying schema
/// defaults" logic, shared by the public HTTP handler below and internal
/// callers (e.g. `get_custom_resource_status`) that want the typed
/// `CustomResource` directly rather than an HTTP response — those callers
/// have no `Accept` header to branch on and never want Table format.
/// Also returns the matched `CustomResourceDefinition`, since callers that
/// *do* need Table format (the HTTP handler) need it for
/// `additionalPrinterColumns` without a second lookup.
async fn fetch_custom_resource(
    state: &ApiServerState,
    auth_ctx: AuthContext,
    group: &str,
    version: &str,
    plural: &str,
    namespace: Option<&str>,
    name: &str,
) -> Result<(CustomResource, CustomResourceDefinition)> {
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(state, &crd_name).await?;

    let attrs = if let Some(ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "get", plural)
            .with_api_group(group)
            .with_namespace(ns)
            .with_name(name)
    } else {
        RequestAttributes::new(auth_ctx.user, "get", plural)
            .with_api_group(group)
            .with_name(name)
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ns) = namespace {
        build_key(&resource_type, Some(ns), name)
    } else {
        build_key(&resource_type, None, name)
    };

    let mut cr: CustomResource = state.storage.get(&key).await?;
    apply_schema_defaults(&crd, version, &mut cr);

    Ok((cr, crd))
}

/// Get a specific custom resource instance
pub async fn get_custom_resource(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    info!(
        "Getting custom resource {}/{}/{}: {}",
        group, version, plural, name
    );

    let (cr, crd) = fetch_custom_resource(
        &state,
        auth_ctx,
        &group,
        &version,
        &plural,
        namespace.as_deref(),
        &name,
    )
    .await?;

    // Table format (kubectl get <cr> <name>) — use the CRD version's own
    // additionalPrinterColumns when declared, same as list_custom_resources.
    let accept = headers.get("accept").and_then(|v| v.to_str().ok());
    if crate::handlers::table::wants_table(accept) {
        let columns = crd
            .spec
            .versions
            .iter()
            .find(|v| v.name == version)
            .and_then(|v| v.additional_printer_columns.as_deref());
        let table = crate::handlers::table::custom_resource_table(
            columns,
            vec![cr],
            None,
            &crd.spec.names.kind,
        );
        return Ok(Json(table).into_response());
    }

    Ok(Json(cr).into_response())
}

/// List custom resource instances
pub async fn list_custom_resources(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace)): Path<(String, String, String, Option<String>)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    debug!("Listing custom resources {}/{}/{}", group, version, plural);

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "list", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
    } else {
        RequestAttributes::new(auth_ctx.user, "list", &plural).with_api_group(&group)
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Build storage prefix
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let prefix = if let Some(ref ns) = namespace {
        build_prefix(&resource_type, Some(ns))
    } else {
        build_prefix(&resource_type, None)
    };

    let mut crs: Vec<CustomResource> = state.storage.list(&prefix).await?;

    // Apply schema defaults on read (K8s "defaulting on read")
    for cr in &mut crs {
        apply_schema_defaults(&crd, &version, cr);
    }

    // `labelSelector` was ignored entirely for custom resources until now:
    // this handler never called `filtering::` at all, so a selector was
    // silently a no-op and every object came back. That is worse than being
    // unsupported — a selector matching nothing returned everything, so a
    // query written against it looks like it succeeded. (Built-in kinds
    // filter correctly; only the CR path was missing it.)
    //
    // Applied here, before the table conversion below, so `kubectl get <cr>
    // -l ...` and a raw JSON list agree.
    crate::handlers::filtering::apply_label_selector(&mut crs, &params)?;

    // Table format (kubectl get <cr>) — use the CRD version's own
    // additionalPrinterColumns when declared, instead of always falling
    // back to a generic NAME+AGE view. Previously never checked at all:
    // kubectl always requests Table format, and getting a plain JSON List
    // back instead means kubectl falls back to its own client-side
    // default columns, never showing a CRD author's declared columns —
    // found live wanting to see CNPG's Cluster status/instances columns
    // on `kubectl get cluster.postgresql.cnpg.io`.
    let accept = headers.get("accept").and_then(|v| v.to_str().ok());
    if crate::handlers::table::wants_table(accept) {
        let columns = crd
            .spec
            .versions
            .iter()
            .find(|v| v.name == version)
            .and_then(|v| v.additional_printer_columns.as_deref());
        let resource_version = match state.storage.current_revision().await {
            Ok(rev) => Some(rev.to_string()),
            Err(_) => None,
        };
        let table = crate::handlers::table::custom_resource_table(
            columns,
            crs,
            resource_version,
            &crd.spec.names.kind,
        );
        return Ok(Json(table).into_response());
    }

    let list = List::new("List", "v1", crs);
    Ok(Json(list).into_response())
}

/// Update a custom resource instance
pub async fn update_custom_resource(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Json<CustomResource>> {
    // Parse the body manually so we can do strict field validation against the raw bytes
    let mut cr: CustomResource = serde_json::from_slice(&body).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("failed to decode: {}", e))
    })?;

    info!(
        "Updating custom resource {}/{}/{}: {}",
        group, version, plural, name
    );

    // Strict field validation: reject unknown top-level fields for CRDs
    let is_strict = params.get("fieldValidation").map(|v| v.as_str()) == Some("Strict");
    if is_strict && !cr.extra.is_empty() {
        let unknown: Vec<&String> = cr.extra.keys().collect();
        return Err(rusternetes_common::Error::InvalidResource(format!(
            "strict decoding error: unknown field \"{}\"",
            unknown[0]
        )));
    }
    crate::handlers::validation::validate_strict_fields(&params, &body, &cr)?;

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Strict schema validation for nested unknown fields
    if is_strict {
        let crd_preserves = crd.spec.preserve_unknown_fields == Some(true);
        let schema_preserves = crd
            .spec
            .versions
            .iter()
            .find(|v| v.name == version)
            .and_then(|v| v.schema.as_ref())
            .map(|s| s.open_apiv3_schema.x_kubernetes_preserve_unknown_fields == Some(true))
            .unwrap_or(false);
        if !crd_preserves && !schema_preserves {
            if let Some(crd_version) = crd.spec.versions.iter().find(|v| v.name == version) {
                if let Some(ref validation) = crd_version.schema {
                    if let Some(ref properties) = validation.open_apiv3_schema.properties {
                        if let Some(spec_schema) = properties.get("spec") {
                            if let Some(ref spec) = cr.spec {
                                SchemaValidator::validate_strict(spec_schema, spec, "spec")?;
                            }
                        }
                    }
                }
            }
        }
    }

    // Apply schema defaults before validation
    apply_schema_defaults(&crd, &version, &mut cr);

    // Validate the resource against CRD schema
    validate_custom_resource(&crd, &version, &cr)?;

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "update", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
    } else {
        RequestAttributes::new(auth_ctx.user, "update", &plural)
            .with_api_group(&group)
            .with_name(&name)
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Ensure name matches
    cr.metadata.name = name.clone();
    cr.api_version = format!("{}/{}", group, version);
    cr.kind = crd.spec.names.kind.clone();

    // Increment metadata.generation only when spec changes — same fix as
    // generic_patch.rs's typed-resource PUT/PATCH handlers already have;
    // this custom-resource (CRD instance) path never got it, silently
    // breaking every operator's `generation != observedGeneration`
    // resync-detection (e.g. workflow-operator design.md W3) for any CRD
    // instance replaced via PUT — found live re-testing
    // `platform-db-real-cluster`'s render Workflow, whose edited spec
    // never re-triggered a render because generation never moved.
    //
    // Also captures the pre-update object as `old_object_for_webhook`: real
    // Kubernetes always populates AdmissionRequest.oldObject for UPDATE (not
    // just DELETE), and some webhooks — live-hit via CNPG's own Cluster
    // validating webhook — decode oldObject unconditionally to compare
    // against the new spec. Passing `None` for it here (this handler's
    // previous behavior) meant CNPG's own webhook server rejected the
    // request outright with "there is no content to decode" (its decoder's
    // literal message for an empty oldObject.Raw), which this handler
    // enforcement path had no way to distinguish from a real validation
    // failure — the request was silently getting denied on every single
    // Cluster update.
    let mut old_object_for_webhook: Option<serde_json::Value> = None;
    {
        let resource_type_for_gen = format!("{}_{}", group.replace('.', "_"), plural);
        let key_for_gen = if let Some(ref ns) = namespace {
            build_key(&resource_type_for_gen, Some(ns), &name)
        } else {
            build_key(&resource_type_for_gen, None, &name)
        };
        if let Ok(current) = state.storage.get::<CustomResource>(&key_for_gen).await {
            if let (Ok(old_json), Ok(new_json)) =
                (serde_json::to_value(&current), serde_json::to_value(&cr))
            {
                crate::handlers::lifecycle::maybe_increment_generation(
                    &old_json,
                    &new_json,
                    &mut cr.metadata,
                );
                old_object_for_webhook = Some(old_json);
            }
        }
    }

    let cr_is_dry_run = crate::handlers::dryrun::is_dry_run(&params);

    // Run validating webhooks for UPDATE operations.
    // K8s runs webhooks on all mutating operations (CREATE, UPDATE, DELETE),
    // and webhooks fire even for dry-run requests so deny decisions are honored.
    {
        use rusternetes_common::admission::{
            AdmissionResponse, GroupVersionKind, GroupVersionResource, Operation,
        };
        let gvk = GroupVersionKind {
            group: group.clone(),
            version: version.clone(),
            kind: cr.kind.clone(),
        };
        let gvr = GroupVersionResource {
            group: group.clone(),
            version: version.clone(),
            resource: plural.clone(),
        };
        let user_info = rusternetes_common::admission::UserInfo {
            username: "admin".to_string(),
            uid: "system:admin".to_string(),
            groups: vec!["system:masters".to_string()],
        };
        let cr_value = serde_json::to_value(&cr).ok();
        if let AdmissionResponse::Deny(reason) = state
            .webhook_manager
            .run_validating_webhooks_with_dryrun(
                &Operation::Update,
                &gvk,
                &gvr,
                namespace.as_deref(),
                &name,
                cr_value,
                old_object_for_webhook,
                &user_info,
                cr_is_dry_run,
            )
            .await?
        {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Skip persistence for dry-run after webhooks have run.
    if cr_is_dry_run {
        return Ok(Json(cr));
    }

    // Build storage key
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };

    if should_complete_pending_deletion(&cr) {
        state.storage.delete(&key).await?;
        return Ok(Json(cr));
    }

    let updated = state.storage.update(&key, &cr).await?;

    Ok(Json(updated))
}

/// Patch a custom resource instance (JSON Patch, JSON Merge Patch, or Strategic Merge Patch)
pub async fn patch_custom_resource(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    req: axum::extract::Request,
) -> Result<Json<CustomResource>> {
    use axum::body::to_bytes;

    info!(
        "Patching custom resource {}/{}/{}: {}",
        group, version, plural, name
    );

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "patch", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
    } else {
        RequestAttributes::new(auth_ctx.user, "patch", &plural)
            .with_api_group(&group)
            .with_name(&name)
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Get the current resource
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };
    // Server-side apply (Content-Type: application/apply-patch+yaml) —
    // same real, field-manager-aware implementation generic_patch.rs's
    // typed-resource handlers already use
    // (rusternetes_common::server_side_apply), just never wired up here.
    // Without this, any client using kube-rs's standard `Api::patch` with
    // `PatchParams::apply(...)` against an *existing* custom resource
    // (any platform.ertia.io CRD instance, or any third-party CRD like
    // CNPG's `Cluster`) hit "Unsupported content type" on every apply
    // after the first — found live: release-operator applies a rendered
    // chart's resources with server-side apply, and a chart that renders
    // more than one object (a ConfigMap alongside the Cluster CNPG's
    // "cluster" chart does) hit this on the ConfigMap's second-and-later
    // reconcile, well before ever reaching the Cluster object itself.
    {
        use axum::body::to_bytes;
        let headers = req.headers();
        let content_type = headers
            .get("x-original-content-type")
            .or_else(|| headers.get(axum::http::header::CONTENT_TYPE))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let is_apply = content_type.contains("apply-patch");
        let query: HashMap<String, String> = req
            .uri()
            .query()
            .map(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_default();
        // SSA is only taken when `fieldManager` is present — same
        // requirement as generic_patch.rs's typed-resource handlers
        // (`if let Some(field_manager) = params.get("fieldManager")`).
        // Without it, apply-patch+yaml falls through to the regular patch
        // dispatcher below, which correctly 4xxs since it isn't a
        // recognized `PatchType`.
        if let (true, Some(field_manager)) = (is_apply, query.get("fieldManager").cloned()) {
            let force = query
                .get("force")
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(false);

            let current_json = match state.storage.get::<CustomResource>(&key).await {
                Ok(current) => Some(
                    serde_json::to_value(&current)
                        .map_err(|e| rusternetes_common::Error::Internal(e.to_string()))?,
                ),
                Err(rusternetes_common::Error::NotFound(_)) => None,
                Err(e) => return Err(e),
            };

            let body_bytes = to_bytes(req.into_body(), usize::MAX).await.map_err(|e| {
                rusternetes_common::Error::InvalidResource(format!(
                    "Failed to read patch body: {}",
                    e
                ))
            })?;
            let desired_json: serde_json::Value = if content_type.contains("yaml") {
                serde_yaml::from_slice(&body_bytes).map_err(|e| {
                    rusternetes_common::Error::InvalidResource(format!(
                        "Invalid patch YAML: {}",
                        e
                    ))
                })?
            } else {
                serde_json::from_slice(&body_bytes).map_err(|e| {
                    rusternetes_common::Error::InvalidResource(format!(
                        "Invalid patch JSON: {}",
                        e
                    ))
                })?
            };

            let apply_params = if force {
                rusternetes_common::server_side_apply::ApplyParams::new(field_manager)
                    .with_force()
            } else {
                rusternetes_common::server_side_apply::ApplyParams::new(field_manager)
            };

            let result = rusternetes_common::server_side_apply::server_side_apply(
                current_json.as_ref(),
                &desired_json,
                &apply_params,
            )
            .map_err(|e| rusternetes_common::Error::InvalidResource(e.to_string()))?;

            return match result {
                rusternetes_common::server_side_apply::ApplyResult::Success(mut applied_json) => {
                    let is_create = current_json.is_none();
                    if let Some(obj) = applied_json.as_object_mut() {
                        obj.insert(
                            "apiVersion".to_string(),
                            serde_json::json!(format!("{}/{}", group, version)),
                        );
                        obj.insert(
                            "kind".to_string(),
                            serde_json::json!(crd.spec.names.kind.clone()),
                        );
                    }
                    let mut applied: CustomResource = serde_json::from_value(applied_json)
                        .map_err(|e| {
                            rusternetes_common::Error::InvalidResource(format!(
                                "Invalid result: {}",
                                e
                            ))
                        })?;
                    validate_custom_resource(&crd, &version, &applied)?;
                    let saved = if is_create {
                        applied.metadata.ensure_uid();
                        applied.metadata.ensure_creation_timestamp();
                        crate::handlers::lifecycle::set_initial_generation(&mut applied.metadata);
                        state.storage.create(&key, &applied).await?
                    } else if should_complete_pending_deletion(&applied) {
                        state.storage.delete(&key).await?;
                        applied
                    } else {
                        state.storage.update(&key, &applied).await?
                    };
                    Ok(Json(saved))
                }
                rusternetes_common::server_side_apply::ApplyResult::Conflicts(conflicts) => {
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
            };
        }
    }

    // Get current resource (may not exist for server-side apply)
    let current_result: rusternetes_common::Result<CustomResource> = state.storage.get(&key).await;

    // Split request into parts to avoid borrow/move conflict
    let (parts, body) = req.into_parts();

    // Get Content-Type header to determine patch type
    // Check X-Original-Content-Type first (set by middleware when normalizing)
    let content_type = parts
        .headers
        .get("x-original-content-type")
        .or_else(|| parts.headers.get(axum::http::header::CONTENT_TYPE))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json-patch+json");

    // Read the patch body
    let body_bytes = to_bytes(body, usize::MAX).await.map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("Failed to read patch body: {}", e))
    })?;

    // Parse body as JSON or YAML depending on content type
    let patch_value: serde_json::Value = if content_type.contains("yaml") {
        // YAML body (server-side apply uses application/apply-patch+yaml)
        // Check for duplicate keys in strict mode (K8s uses Go yaml.v2 which
        // reports "key already set in map")
        let is_strict = parts
            .uri
            .query()
            .and_then(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == "fieldValidation")
                    .map(|(_, v)| v.to_string())
            })
            .as_deref()
            == Some("Strict");
        if is_strict {
            if let Ok(yaml_str) = std::str::from_utf8(&body_bytes) {
                // Simple duplicate key detection: parse YAML lines looking for
                // repeated keys at the same indentation level
                let mut seen_keys: std::collections::HashMap<(usize, String), usize> =
                    std::collections::HashMap::new();
                for (line_num, line) in yaml_str.lines().enumerate() {
                    let trimmed = line.trim_start();
                    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
                        continue;
                    }
                    let indent = line.len() - trimmed.len();
                    if let Some(colon_pos) = trimmed.find(':') {
                        let key = trimmed[..colon_pos].trim().trim_matches('"');
                        if !key.is_empty() && !key.contains(' ') {
                            let map_key = (indent, key.to_string());
                            if let Some(_prev_line) = seen_keys.get(&map_key) {
                                return Err(rusternetes_common::Error::InvalidResource(format!(
                                    "line {}: key {:?} already set in map",
                                    line_num + 1,
                                    key
                                )));
                            }
                            // Clear keys at deeper indentation when we encounter a new key
                            seen_keys.retain(|(ind, _), _| *ind <= indent);
                            seen_keys.insert(map_key, line_num + 1);
                        }
                    }
                }
            }
        }
        serde_yaml::from_slice(&body_bytes).map_err(|e| {
            rusternetes_common::Error::InvalidResource(format!("Invalid patch YAML: {}", e))
        })?
    } else {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            rusternetes_common::Error::InvalidResource(format!("Invalid patch JSON: {}", e))
        })?
    };

    // For server-side apply (application/apply-patch+yaml), create if not found
    let is_apply = content_type.contains("apply-patch");

    let mut patched_json = if let Ok(current) = &current_result {
        // Resource exists — apply patch
        let current_json = serde_json::to_value(current).map_err(|e| {
            rusternetes_common::Error::Internal(format!(
                "Failed to serialize current resource: {}",
                e
            ))
        })?;
        let patch_type = crate::patch::PatchType::from_content_type(content_type).map_err(|e| {
            rusternetes_common::Error::InvalidResource(format!(
                "Unsupported patch content type: {}",
                e
            ))
        })?;
        crate::patch::apply_patch(&current_json, &patch_value, patch_type).map_err(|e| {
            rusternetes_common::Error::InvalidResource(format!("Failed to apply patch: {}", e))
        })?
    } else if is_apply {
        // Resource doesn't exist + server-side apply = create from patch body
        patch_value.clone()
    } else {
        // Resource doesn't exist + regular patch = error
        return Err(current_result.unwrap_err());
    };

    // Increment metadata.generation only when spec changes — same logic
    // as generic_patch.rs's typed-resource PATCH handlers already apply;
    // this custom-resource (CRD instance) path never had it, so `kubectl
    // apply` on any platform.ertia.io CRD instance (Workflow, Release,
    // Bundle, ...) never bumped generation, silently breaking every
    // operator's `generation != observedGeneration` resync-detection.
    // Found live re-testing `platform-db-real-cluster`'s render Workflow:
    // an edited spec applied via `kubectl apply` never re-triggered a
    // render, because workflow-operator never saw generation move.
    if let Ok(current) = &current_result {
        let old_json = serde_json::to_value(current).ok();
        let new_spec = patched_json.get("spec").cloned();
        let old_spec = old_json.as_ref().and_then(|v| v.get("spec")).cloned();
        let spec_changed = match (&old_spec, &new_spec) {
            (Some(old), Some(new)) => old != new,
            (None, Some(_)) | (Some(_), None) => true,
            (None, None) => false,
        };
        if spec_changed {
            if let Some(metadata) = patched_json.get_mut("metadata") {
                if let Some(meta_obj) = metadata.as_object_mut() {
                    let current_gen = meta_obj
                        .get("generation")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    meta_obj.insert("generation".to_string(), serde_json::json!(current_gen + 1));
                }
            }
        }
    }

    // Deserialize the patched JSON back to CustomResource
    let mut patched: CustomResource = serde_json::from_value(patched_json).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!(
            "Failed to deserialize patched resource: {}",
            e
        ))
    })?;

    // Strict field validation for patched CRDs: reject unknown top-level fields
    // when the CRD does NOT have preserveUnknownFields.
    // K8s prunes unknown fields and returns them as errors with fieldValidation=Strict.
    let is_strict = parts
        .uri
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "fieldValidation")
                .map(|(_, v)| v.to_string())
        })
        .as_deref()
        == Some("Strict");
    if is_strict && !patched.extra.is_empty() {
        let crd_preserves = crd.spec.preserve_unknown_fields == Some(true);
        if !crd_preserves {
            let unknown: Vec<&String> = patched.extra.keys().collect();
            return Err(rusternetes_common::Error::InvalidResource(format!(
                ".{}: field not declared in schema",
                unknown[0]
            )));
        }
    }
    // Also validate embedded metadata fields in the patched result
    if is_strict {
        let patched_value = serde_json::to_value(&patched).unwrap_or_default();
        const KNOWN_META: &[&str] = &[
            "name",
            "generateName",
            "namespace",
            "selfLink",
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
            "deletionTimestamp",
            "deletionGracePeriodSeconds",
            "labels",
            "annotations",
            "ownerReferences",
            "finalizers",
            "managedFields",
            "clusterName",
        ];
        fn check_embedded_meta(
            value: &serde_json::Value,
            path: &str,
            known: &[&str],
        ) -> Option<String> {
            if let Some(obj) = value.as_object() {
                if let Some(meta) = obj.get("metadata").and_then(|m| m.as_object()) {
                    let mp = if path.is_empty() {
                        ".metadata".to_string()
                    } else {
                        format!("{}.metadata", path)
                    };
                    for key in meta.keys() {
                        if !known.contains(&key.as_str()) {
                            return Some(format!("{}.{}: field not declared in schema", mp, key));
                        }
                    }
                }
                for (key, val) in obj {
                    if key == "metadata" {
                        continue;
                    }
                    let cp = if path.is_empty() {
                        format!(".{}", key)
                    } else {
                        format!("{}.{}", path, key)
                    };
                    if let Some(err) = check_embedded_meta(val, &cp, known) {
                        return Some(err);
                    }
                }
            } else if let Some(arr) = value.as_array() {
                for item in arr {
                    if let Some(err) = check_embedded_meta(item, path, known) {
                        return Some(err);
                    }
                }
            }
            None
        }
        if let Some(err_msg) = check_embedded_meta(&patched_value, "", KNOWN_META) {
            return Err(rusternetes_common::Error::InvalidResource(err_msg));
        }
    }

    // Strict schema validation for nested unknown fields in patched resource
    if is_strict {
        let crd_preserves = crd.spec.preserve_unknown_fields == Some(true);
        let schema_preserves = crd
            .spec
            .versions
            .iter()
            .find(|v| v.name == version)
            .and_then(|v| v.schema.as_ref())
            .map(|s| s.open_apiv3_schema.x_kubernetes_preserve_unknown_fields == Some(true))
            .unwrap_or(false);
        if !crd_preserves && !schema_preserves {
            if let Some(crd_version) = crd.spec.versions.iter().find(|v| v.name == version) {
                if let Some(ref validation) = crd_version.schema {
                    if let Some(ref properties) = validation.open_apiv3_schema.properties {
                        if let Some(spec_schema) = properties.get("spec") {
                            if let Some(ref spec) = patched.spec {
                                SchemaValidator::validate_strict(spec_schema, spec, "spec")?;
                            }
                        }
                    }
                }
            }
        }
    }

    // Validate the patched resource against CRD schema
    validate_custom_resource(&crd, &version, &patched)?;

    // Ensure name matches
    patched.metadata.name = name.clone();
    patched.api_version = format!("{}/{}", group, version);
    patched.kind = crd.spec.names.kind.clone();

    // Update or create the resource in storage
    let updated = if current_result.is_ok() {
        if should_complete_pending_deletion(&patched) {
            state.storage.delete(&key).await?;
            return Ok(Json(patched));
        }
        state.storage.update(&key, &patched).await?
    } else {
        // Server-side apply creates new resource
        patched.metadata.ensure_uid();
        patched.metadata.ensure_creation_timestamp();
        crate::handlers::lifecycle::set_initial_generation(&mut patched.metadata);
        state.storage.create(&key, &patched).await?
    };

    Ok(Json(updated))
}

/// Patch the status subresource of a custom resource
pub async fn patch_custom_resource_status(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    req: axum::extract::Request,
) -> Result<Json<CustomResource>> {
    use axum::body::to_bytes;

    info!(
        "Patching custom resource status {}/{}/{}: {}",
        group, version, plural, name
    );

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check if status subresource is enabled
    let version_spec = crd
        .spec
        .versions
        .iter()
        .find(|v| v.name == version)
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(format!(
                "Version {} not found in CRD",
                version
            ))
        })?;

    if version_spec.subresources.is_none()
        || version_spec.subresources.as_ref().unwrap().status.is_none()
    {
        return Err(rusternetes_common::Error::InvalidResource(
            "Status subresource not enabled for this CRD".to_string(),
        ));
    }

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "patch", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
            .with_subresource("status")
    } else {
        RequestAttributes::new(auth_ctx.user, "patch", &plural)
            .with_api_group(&group)
            .with_name(&name)
            .with_subresource("status")
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Get the current resource
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };

    let mut current: CustomResource = state.storage.get(&key).await?;

    // Split request into parts to avoid borrow/move conflict
    let (parts, body) = req.into_parts();

    // Get Content-Type header to determine patch type
    // Check X-Original-Content-Type first (set by middleware when normalizing)
    let content_type = parts
        .headers
        .get("x-original-content-type")
        .or_else(|| parts.headers.get(axum::http::header::CONTENT_TYPE))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json-patch+json");

    // Read the patch body
    let body_bytes = to_bytes(body, usize::MAX).await.map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("Failed to read patch body: {}", e))
    })?;
    let patch_value: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("Invalid patch JSON: {}", e))
    })?;

    // Real Kubernetes clients (including `kubectl patch --subresource=status`)
    // shape a status-subresource merge/strategic-merge patch as the FULL
    // object structure — `{"status": {...partial status fields...}}` — even
    // though the subresource URL already scopes the patch target to
    // `.status`; only fields under that key are meant to apply. `current_status`
    // below is the *unwrapped* content of `.status` (`{"appliedResources":
    // [...], "conditions": [...], ...}`), so merging the still-wrapped
    // `patch_value` against it inserted a spurious nested `status.status` key
    // instead of merging `appliedResources` directly — a real, confirmed bug
    // (reproduced live: `PATCH .../releases/platform-db/status` with body
    // `{"status":{"appliedResources":[]}}` produced
    // `status: {appliedResources: [...unchanged...], ..., status:
    // {appliedResources: []}}`). A JSON Patch (RFC 6902) document is an array
    // of `{op, path, value}` operations with paths already relative to
    // `.status`, not an object with a `status` key, so this unwrap is only
    // ever applicable to the object-shaped patch types.
    let patch_value = match &patch_value {
        serde_json::Value::Object(obj) if obj.contains_key("status") => {
            obj.get("status").cloned().unwrap_or(serde_json::Value::Null)
        }
        other => other.clone(),
    };

    // Apply the patch to the status field only
    let current_status = current
        .status
        .as_ref()
        .unwrap_or(&serde_json::Value::Null)
        .clone();

    let patch_type = crate::patch::PatchType::from_content_type(content_type).map_err(|e| {
        rusternetes_common::Error::InvalidResource(format!("Unsupported patch content type: {}", e))
    })?;

    let patched_status = crate::patch::apply_patch(&current_status, &patch_value, patch_type)
        .map_err(|e| {
            rusternetes_common::Error::InvalidResource(format!(
                "Failed to apply status patch: {}",
                e
            ))
        })?;

    // Update only the status field
    current.status = Some(patched_status);

    // Save the updated resource
    let updated = state.storage.update(&key, &current).await?;

    Ok(Json(updated))
}

/// Delete a custom resource instance
pub async fn delete_custom_resource(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<CustomResource>> {
    info!(
        "Deleting custom resource {}/{}/{}: {}",
        group, version, plural, name
    );

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check authorization
    let user_for_webhook = auth_ctx.user.clone();
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "delete", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
    } else {
        RequestAttributes::new(auth_ctx.user, "delete", &plural)
            .with_api_group(&group)
            .with_name(&name)
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Build storage key
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };

    // Get the resource to check if it exists
    let cr: CustomResource = state.storage.get(&key).await?;

    // Run validating webhooks for DELETE operations.
    // K8s runs validating admission (including webhooks) before deletion.
    // Mutating webhooks are NOT called on DELETE in K8s — only validating.
    {
        let kind = crd.spec.names.kind.clone();
        let gvk = rusternetes_common::admission::GroupVersionKind {
            group: group.clone(),
            version: version.clone(),
            kind: kind.clone(),
        };
        let gvr = rusternetes_common::admission::GroupVersionResource {
            group: group.clone(),
            version: version.clone(),
            resource: plural.clone(),
        };
        let user_info = rusternetes_common::admission::UserInfo {
            username: user_for_webhook.username.clone(),
            uid: user_for_webhook.uid.clone(),
            groups: user_for_webhook.groups.clone(),
        };
        let cr_value = serde_json::to_value(&cr).ok();
        // K8s DELETE AdmissionReview: object is nil, oldObject has the resource being deleted.
        // The webhook inspects oldObject to decide whether to allow deletion.
        let is_dry_run = crate::handlers::dryrun::is_dry_run(&params);
        if let rusternetes_common::admission::AdmissionResponse::Deny(reason) = state
            .webhook_manager
            .run_validating_webhooks_with_dryrun(
                &rusternetes_common::admission::Operation::Delete,
                &gvk,
                &gvr,
                namespace.as_deref(),
                &name,
                None,
                cr_value,
                &user_info,
                is_dry_run,
            )
            .await?
        {
            return Err(rusternetes_common::Error::Forbidden(format!(
                "admission webhook denied the request: {}",
                reason
            )));
        }
    }

    // Check for dry-run
    if crate::handlers::dryrun::is_dry_run(&params) {
        info!(
            "Dry-run: CustomResource {}/{}/{} validated successfully (not deleted)",
            group, plural, name
        );
        return Ok(Json(cr));
    }

    let has_finalizers =
        crate::handlers::finalizers::handle_delete_with_finalizers(&*state.storage, &key, &cr)
            .await?;

    if has_finalizers {
        // Resource has finalizers, re-read to get updated version with deletionTimestamp
        let updated: CustomResource = state.storage.get(&key).await?;
        Ok(Json(updated))
    } else {
        Ok(Json(cr))
    }
}

/// Helper to get CRD from storage
pub(crate) async fn get_crd_for_resource(
    state: &ApiServerState,
    crd_name: &str,
) -> Result<CustomResourceDefinition> {
    let key = build_key("customresourcedefinitions", None, crd_name);
    state.storage.get(&key).await
}

/// Apply schema defaults from the CRD to a custom resource's spec.
/// Walks the CRD's JSONSchemaProps and for each property with a `default`
/// value, sets it on the CR if the field is missing.
fn apply_schema_defaults(crd: &CustomResourceDefinition, version: &str, cr: &mut CustomResource) {
    // Find the version in the CRD
    let crd_version = match crd.spec.versions.iter().find(|v| v.name == version) {
        Some(v) => v,
        None => return,
    };

    // Apply defaults from schema if present
    if let Some(ref validation) = crd_version.schema {
        // The CRD schema's top-level properties typically include "spec", "status", etc.
        // We need to find the "spec" property schema and apply defaults to cr.spec.
        if let Some(ref properties) = validation.open_apiv3_schema.properties {
            if let Some(spec_schema) = properties.get("spec") {
                let spec = cr.spec.get_or_insert_with(|| serde_json::json!({}));
                SchemaValidator::apply_defaults(spec_schema, spec);
            }
        }
        // Also apply defaults at the top level for the whole object
        // (handles cases where the schema defines defaults for top-level fields like "a")
        let mut cr_value = serde_json::to_value(&*cr).unwrap_or_default();
        SchemaValidator::apply_defaults(&validation.open_apiv3_schema, &mut cr_value);
        // Update spec from applied defaults
        if let Some(spec_val) = cr_value.get("spec") {
            cr.spec = Some(spec_val.clone());
        }
        // Update extra fields from applied defaults (top-level fields beyond
        // apiVersion/kind/metadata/spec/status)
        if let Some(obj) = cr_value.as_object() {
            for (k, v) in obj {
                if k != "apiVersion"
                    && k != "kind"
                    && k != "metadata"
                    && k != "spec"
                    && k != "status"
                {
                    cr.extra.insert(k.clone(), v.clone());
                }
            }
        }
    }
}

/// Test-only re-export of `prune_custom_resource` so admission webhook tests
/// can verify the pruning path applied after mutating webhooks.
#[cfg(test)]
pub(crate) fn test_prune_custom_resource(
    crd: &CustomResourceDefinition,
    version: &str,
    cr: &mut CustomResource,
) {
    prune_custom_resource(crd, version, cr)
}

/// Prune unknown fields from a CR based on the CRD schema.
/// K8s removes fields not in the schema unless x-kubernetes-preserve-unknown-fields is set.
/// This runs AFTER webhook mutation so webhook-added fields not in the schema are removed.
/// K8s ref: staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning
fn prune_custom_resource(crd: &CustomResourceDefinition, version: &str, cr: &mut CustomResource) {
    let crd_version = match crd.spec.versions.iter().find(|v| v.name == version) {
        Some(v) => v,
        None => return,
    };

    // Check if the CRD preserves unknown fields globally
    if crd.spec.preserve_unknown_fields == Some(true) {
        return;
    }

    let schema = match &crd_version.schema {
        Some(s) => &s.open_apiv3_schema,
        None => return,
    };

    // Check if root schema preserves unknown fields
    if schema.x_kubernetes_preserve_unknown_fields == Some(true) {
        return;
    }

    // Get the schema properties for the "data" field (or whatever top-level fields exist)
    // K8s prunes against spec/status/metadata + any additional properties
    let schema_properties: std::collections::HashSet<String> = schema
        .properties
        .as_ref()
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default();

    // Prune extra fields on the CR that aren't in the schema
    // K8s preserves: apiVersion, kind, metadata (always)
    // Everything else is checked against schema properties
    let known_top_level: std::collections::HashSet<&str> =
        ["apiVersion", "kind", "metadata"].iter().copied().collect();

    let cr_keys: Vec<String> = cr.extra.keys().cloned().collect();
    for key in cr_keys {
        if !known_top_level.contains(key.as_str()) && !schema_properties.contains(&key) {
            tracing::debug!("Pruning unknown field '{}' from CR", key);
            cr.extra.remove(&key);
        }
    }

    // Also prune within known fields like "data", "spec", "status"
    // by checking their nested schema properties.
    if let Some(schema_props) = &schema.properties {
        for (field_name, field_schema) in schema_props {
            // Check if this field preserves unknown fields
            if field_schema.x_kubernetes_preserve_unknown_fields == Some(true) {
                continue;
            }
            // The CustomResource type lifts "spec" and "status" out of the flat
            // map and stores them on their own fields. Walk those as well so
            // webhook-injected unknown fields under spec/status get pruned.
            if field_name == "spec" {
                if let Some(spec_val) = cr.spec.as_mut() {
                    prune_value_against_schema(spec_val, field_schema, "spec");
                }
                continue;
            }
            if field_name == "status" {
                if let Some(status_val) = cr.status.as_mut() {
                    prune_value_against_schema(status_val, field_schema, "status");
                }
                continue;
            }
            if let Some(field_props) = &field_schema.properties {
                let allowed_keys: std::collections::HashSet<String> =
                    field_props.keys().cloned().collect();

                // Prune from cr.extra if this field is there
                if let Some(field_val) = cr.extra.get_mut(field_name) {
                    if let Some(obj) = field_val.as_object_mut() {
                        let obj_keys: Vec<String> = obj.keys().cloned().collect();
                        for k in obj_keys {
                            if !allowed_keys.contains(&k) {
                                tracing::debug!(
                                    "Pruning unknown field '{}.{}' from CR",
                                    field_name,
                                    k
                                );
                                obj.remove(&k);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Recursively prune unknown fields from a JSON value against a JSONSchema.
/// Fields not declared as a property are removed unless the schema (or the
/// enclosing object) carries x-kubernetes-preserve-unknown-fields.
///
/// K8s ref: staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning/prune.go
fn prune_value_against_schema(
    value: &mut serde_json::Value,
    schema: &rusternetes_common::resources::JSONSchemaProps,
    path: &str,
) {
    if schema.x_kubernetes_preserve_unknown_fields == Some(true) {
        return;
    }
    match value {
        serde_json::Value::Object(obj) => {
            let Some(props) = schema.properties.as_ref() else {
                return;
            };
            obj.retain(|k, _| {
                let keep = props.contains_key(k);
                if !keep {
                    tracing::debug!("Pruning unknown field '{}.{}'", path, k);
                }
                keep
            });
            for (k, child_schema) in props {
                if let Some(child_val) = obj.get_mut(k) {
                    prune_value_against_schema(child_val, child_schema, &format!("{}.{}", path, k));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            use rusternetes_common::resources::JSONSchemaPropsOrArray;
            if let Some(JSONSchemaPropsOrArray::Schema(item_schema)) = schema.items.as_deref() {
                for (i, item) in arr.iter_mut().enumerate() {
                    prune_value_against_schema(item, item_schema, &format!("{}[{}]", path, i));
                }
            }
        }
        _ => {}
    }
}

/// Validate a custom resource against its CRD schema
fn validate_custom_resource(
    crd: &CustomResourceDefinition,
    version: &str,
    cr: &CustomResource,
) -> Result<()> {
    // Find the version in the CRD
    let crd_version = crd
        .spec
        .versions
        .iter()
        .find(|v| v.name == version)
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(format!(
                "Version {} not found in CRD",
                version
            ))
        })?;

    // Check if version is served
    if !crd_version.served {
        warn!("Version {} is not served", version);
        return Err(rusternetes_common::Error::InvalidResource(format!(
            "Version {} is not served",
            version
        )));
    }

    // Validate against schema if present.
    // K8s skips structural pruning/validation when CRD has preserveUnknownFields: true
    // (line 1432 in customresource_handler.go). Only metadata coercion runs.
    // Also skip if the schema root has x-kubernetes-preserve-unknown-fields: true.
    let crd_preserves = crd.spec.preserve_unknown_fields == Some(true);
    if let Some(ref validation) = crd_version.schema {
        let schema_preserves = validation
            .open_apiv3_schema
            .x_kubernetes_preserve_unknown_fields
            == Some(true);

        if !crd_preserves && !schema_preserves {
            // Validate ALL top-level properties against the schema, not just spec.
            // K8s validates the entire CR object. Some CRDs define enum fields
            // at the top level (e.g., cronies), not under spec.
            if let Some(ref properties) = validation.open_apiv3_schema.properties {
                // Validate spec if present
                if let Some(ref spec) = cr.spec {
                    if let Some(spec_schema) = properties.get("spec") {
                        SchemaValidator::validate_no_unknown_check(spec_schema, spec)?;
                    }
                }
                // Validate status if present
                if let Some(ref status) = cr.status {
                    if let Some(status_schema) = properties.get("status") {
                        SchemaValidator::validate_no_unknown_check(status_schema, status)?;
                    }
                }
                // Validate extra top-level fields (e.g., cronies, hostPort)
                for (key, value) in &cr.extra {
                    if key == "metadata" || key == "apiVersion" || key == "kind" {
                        continue;
                    }
                    if let Some(field_schema) = properties.get(key) {
                        SchemaValidator::validate_no_unknown_check(field_schema, value)?;
                    }
                }
            }
        }
        // When preserveUnknownFields is true, skip structural validation.
        // K8s only runs metadata coercion (CoerceWithOptions) in this case.
    }

    Ok(())
}

/// Get the status subresource of a custom resource
pub async fn get_custom_resource_status(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
) -> Result<Json<serde_json::Value>> {
    info!(
        "Getting custom resource status {}/{}/{}: {}",
        group, version, plural, name
    );

    // Get the full resource first
    let (cr, _crd) = fetch_custom_resource(
        &state,
        auth_ctx,
        &group,
        &version,
        &plural,
        namespace.as_deref(),
        &name,
    )
    .await?;

    // Extract and return just the status field
    let status = cr.status.unwrap_or(serde_json::Value::Null);
    Ok(Json(status))
}

/// Update the status subresource of a custom resource
pub async fn update_custom_resource_status(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    Json(status): Json<serde_json::Value>,
) -> Result<Json<CustomResource>> {
    info!(
        "Updating custom resource status {}/{}/{}: {}",
        group, version, plural, name
    );

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check if status subresource is enabled
    let version_spec = crd
        .spec
        .versions
        .iter()
        .find(|v| v.name == version)
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(format!(
                "Version {} not found in CRD",
                version
            ))
        })?;

    if version_spec.subresources.is_none()
        || version_spec.subresources.as_ref().unwrap().status.is_none()
    {
        return Err(rusternetes_common::Error::InvalidResource(
            "Status subresource not enabled for this CRD".to_string(),
        ));
    }

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "update", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
            .with_subresource("status")
    } else {
        RequestAttributes::new(auth_ctx.user, "update", &plural)
            .with_api_group(&group)
            .with_name(&name)
            .with_subresource("status")
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Get the existing resource
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };

    let mut cr: CustomResource = state.storage.get(&key).await?;

    // A PUT to a status subresource sends the FULL resource object in the
    // body (real clients read the object, mutate `.status` in-memory, then
    // PUT the whole thing back) — the API server is responsible for
    // extracting just `.status` and ignoring changes to spec/metadata, since
    // the subresource scopes what this write is authorized to touch. This
    // used to store the raw whole-body value directly as `.status` — a real
    // bug, confirmed live: CNPG's `Status().Update()` calls silently wiped
    // `Cluster.status` fields (`image`, `phase`, `phaseReason`, ...) on every
    // PUT, since the stored status became a copy of the entire incoming
    // object (metadata+spec+status nested inside itself) rather than just
    // its `.status` portion — compounding across repeated reconciles as CNPG
    // read back its own corrupted status and built the next update from it.
    // Mirrors the same unwrap already applied in `patch_custom_resource_status`.
    let status = match &status {
        serde_json::Value::Object(obj) if obj.contains_key("status") => {
            obj.get("status").cloned().unwrap_or(serde_json::Value::Null)
        }
        other => other.clone(),
    };

    // Update only the status field (optimistic concurrency control)
    cr.status = Some(status);

    // Save the updated resource
    let updated = state.storage.update(&key, &cr).await?;

    Ok(Json(updated))
}

/// Get the scale subresource of a custom resource
pub async fn get_custom_resource_scale(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
) -> Result<Json<Scale>> {
    info!(
        "Getting custom resource scale {}/{}/{}: {}",
        group, version, plural, name
    );

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check if scale subresource is enabled and get the configuration
    let version_spec = crd
        .spec
        .versions
        .iter()
        .find(|v| v.name == version)
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(format!(
                "Version {} not found in CRD",
                version
            ))
        })?;

    let scale_config = version_spec
        .subresources
        .as_ref()
        .and_then(|s| s.scale.as_ref())
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(
                "Scale subresource not enabled for this CRD".to_string(),
            )
        })?;

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "get", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
            .with_subresource("scale")
    } else {
        RequestAttributes::new(auth_ctx.user, "get", &plural)
            .with_api_group(&group)
            .with_name(&name)
            .with_subresource("scale")
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Get the existing resource
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };

    let cr: CustomResource = state.storage.get(&key).await?;

    // Extract scale information using JSONPath
    let spec_replicas = extract_json_path(&cr.spec, &scale_config.spec_replicas_path)
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;

    let status_replicas = extract_json_path(&cr.status, &scale_config.status_replicas_path)
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;

    let label_selector = if let Some(ref selector_path) = scale_config.label_selector_path {
        extract_json_path(&cr.status, selector_path)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };

    let scale = Scale {
        api_version: "autoscaling/v1".to_string(),
        kind: "Scale".to_string(),
        metadata: cr.metadata.clone(),
        spec: ScaleSpec {
            replicas: spec_replicas,
        },
        status: Some(ScaleStatus {
            replicas: status_replicas,
            selector: label_selector,
        }),
    };

    Ok(Json(scale))
}

/// Update the scale subresource of a custom resource
pub async fn update_custom_resource_scale(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((group, version, plural, namespace, name)): Path<(
        String,
        String,
        String,
        Option<String>,
        String,
    )>,
    Json(scale): Json<Scale>,
) -> Result<Json<Scale>> {
    info!(
        "Updating custom resource scale {}/{}/{}: {}",
        group, version, plural, name
    );

    // Find the CRD for this resource type
    let crd_name = format!("{}.{}", plural, group);
    let crd = get_crd_for_resource(&state, &crd_name).await?;

    // Check if scale subresource is enabled and get the configuration
    let version_spec = crd
        .spec
        .versions
        .iter()
        .find(|v| v.name == version)
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(format!(
                "Version {} not found in CRD",
                version
            ))
        })?;

    let scale_config = version_spec
        .subresources
        .as_ref()
        .and_then(|s| s.scale.as_ref())
        .ok_or_else(|| {
            rusternetes_common::Error::InvalidResource(
                "Scale subresource not enabled for this CRD".to_string(),
            )
        })?;

    // Check authorization
    let attrs = if let Some(ref ns) = namespace {
        RequestAttributes::new(auth_ctx.user.clone(), "update", &plural)
            .with_api_group(&group)
            .with_namespace(ns)
            .with_name(&name)
            .with_subresource("scale")
    } else {
        RequestAttributes::new(auth_ctx.user.clone(), "update", &plural)
            .with_api_group(&group)
            .with_name(&name)
            .with_subresource("scale")
    };

    match state.authorizer.authorize(&attrs).await? {
        Decision::Allow => {}
        Decision::Deny(reason) => {
            return Err(rusternetes_common::Error::Forbidden(reason));
        }
    }

    // Get the existing resource
    let resource_type = format!("{}_{}", group.replace('.', "_"), plural);
    let key = if let Some(ref ns) = namespace {
        build_key(&resource_type, Some(ns), &name)
    } else {
        build_key(&resource_type, None, &name)
    };

    let mut cr: CustomResource = state.storage.get(&key).await?;

    // Update the replica count in the spec using JSONPath
    if let Some(ref mut spec) = cr.spec {
        set_json_path(spec, &scale_config.spec_replicas_path, scale.spec.replicas);
    }

    // Save the updated resource
    let _updated = state.storage.update(&key, &cr).await?;

    // Return the updated scale representation
    get_custom_resource_scale(
        State(state),
        Extension(auth_ctx),
        Path((group, version, plural, namespace, name)),
    )
    .await
}

/// Helper to extract a value from a JSON object using a simple JSONPath
fn extract_json_path<'a>(
    json: &'a Option<serde_json::Value>,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let json = json.as_ref()?;
    let parts: Vec<&str> = path.trim_start_matches('.').split('.').collect();

    let mut current = json;
    for part in parts {
        current = current.get(part)?;
    }

    Some(current)
}

/// Helper to set a value in a JSON object using a simple JSONPath
fn set_json_path(json: &mut serde_json::Value, path: &str, value: i32) {
    let parts: Vec<&str> = path.trim_start_matches('.').split('.').collect();

    if parts.is_empty() {
        return;
    }

    // Ensure we're working with an object
    if !json.is_object() {
        *json = serde_json::json!({});
    }

    let mut current = json;
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last part - set the value
            if let Some(obj) = current.as_object_mut() {
                obj.insert(part.to_string(), serde_json::Value::Number(value.into()));
            }
        } else {
            // Intermediate part - navigate or create
            let obj = current.as_object_mut().unwrap();
            current = obj
                .entry(part.to_string())
                .or_insert_with(|| serde_json::json!({}));
        }
    }
}

/// Scale represents the scale subresource of a custom resource
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scale {
    pub api_version: String,
    pub kind: String,
    pub metadata: rusternetes_common::types::ObjectMeta,
    pub spec: ScaleSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ScaleStatus>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScaleSpec {
    pub replicas: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScaleStatus {
    pub replicas: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_common::resources::{
        CustomResourceDefinitionNames, CustomResourceDefinitionSpec,
        CustomResourceDefinitionVersion, ResourceScope,
    };
    use rusternetes_common::types::ObjectMeta;
    use serde_json::json;

    fn create_test_crd() -> CustomResourceDefinition {
        CustomResourceDefinition {
            api_version: "apiextensions.k8s.io/v1".to_string(),
            kind: "CustomResourceDefinition".to_string(),
            metadata: ObjectMeta::new("crontabs.stable.example.com"),
            spec: CustomResourceDefinitionSpec {
                group: "stable.example.com".to_string(),
                names: CustomResourceDefinitionNames {
                    plural: "crontabs".to_string(),
                    singular: Some("crontab".to_string()),
                    kind: "CronTab".to_string(),
                    short_names: Some(vec!["ct".to_string()]),
                    categories: None,
                    list_kind: Some("CronTabList".to_string()),
                },
                scope: ResourceScope::Namespaced,
                versions: vec![CustomResourceDefinitionVersion {
                    name: "v1".to_string(),
                    served: true,
                    storage: true,
                    deprecated: None,
                    deprecation_warning: None,
                    schema: None,
                    subresources: None,
                    additional_printer_columns: None,
                }],
                conversion: None,
                preserve_unknown_fields: None,
            },
            status: None,
        }
    }

    fn create_test_custom_resource() -> CustomResource {
        CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: {
                let mut meta = ObjectMeta::new("my-crontab");
                meta.namespace = Some("default".to_string());
                meta
            },
            spec: Some(json!({
                "cronSpec": "* * * * */5",
                "image": "my-cron-image"
            })),
            status: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn test_validate_custom_resource_success() {
        let crd = create_test_crd();
        let cr = create_test_custom_resource();

        assert!(validate_custom_resource(&crd, "v1", &cr).is_ok());
    }

    #[test]
    fn test_should_complete_pending_deletion_when_last_finalizer_removed() {
        let mut cr = create_test_custom_resource();
        cr.metadata.deletion_timestamp = Some(chrono::Utc::now());
        cr.metadata.finalizers = None;
        assert!(should_complete_pending_deletion(&cr));

        cr.metadata.finalizers = Some(vec![]);
        assert!(should_complete_pending_deletion(&cr));
    }

    #[test]
    fn test_should_not_complete_pending_deletion_with_finalizers_remaining() {
        let mut cr = create_test_custom_resource();
        cr.metadata.deletion_timestamp = Some(chrono::Utc::now());
        cr.metadata.finalizers = Some(vec!["platform.ertia.io/release-bindings".to_string()]);
        assert!(!should_complete_pending_deletion(&cr));
    }

    #[test]
    fn test_should_not_complete_pending_deletion_without_deletion_timestamp() {
        // No finalizers and no deletionTimestamp — an ordinary object,
        // not one mid-deletion. Must not be treated as ready to purge.
        let mut cr = create_test_custom_resource();
        cr.metadata.deletion_timestamp = None;
        cr.metadata.finalizers = None;
        assert!(!should_complete_pending_deletion(&cr));
    }

    #[test]
    fn test_validate_custom_resource_invalid_version() {
        let crd = create_test_crd();
        let cr = create_test_custom_resource();

        let result = validate_custom_resource(&crd, "v2", &cr);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_custom_resource_not_served() {
        let mut crd = create_test_crd();
        crd.spec.versions[0].served = false;
        let cr = create_test_custom_resource();

        let result = validate_custom_resource(&crd, "v1", &cr);
        assert!(result.is_err());
    }

    /// Helper: create a CRD with a schema that has default values
    fn create_crd_with_defaults() -> CustomResourceDefinition {
        use rusternetes_common::resources::crd::JSONSchemaProps;
        use rusternetes_common::resources::CustomResourceValidation;

        let mut spec_properties = std::collections::HashMap::new();
        spec_properties.insert(
            "cronSpec".to_string(),
            JSONSchemaProps {
                type_: Some("string".to_string()),
                ..Default::default()
            },
        );
        spec_properties.insert(
            "image".to_string(),
            JSONSchemaProps {
                type_: Some("string".to_string()),
                default: Some(json!("default-image:latest")),
                ..Default::default()
            },
        );
        spec_properties.insert(
            "replicas".to_string(),
            JSONSchemaProps {
                type_: Some("integer".to_string()),
                default: Some(json!(1)),
                ..Default::default()
            },
        );
        // Nested object with defaults
        let mut nested_props = std::collections::HashMap::new();
        nested_props.insert(
            "enabled".to_string(),
            JSONSchemaProps {
                type_: Some("boolean".to_string()),
                default: Some(json!(true)),
                ..Default::default()
            },
        );
        spec_properties.insert(
            "logging".to_string(),
            JSONSchemaProps {
                type_: Some("object".to_string()),
                properties: Some(nested_props),
                ..Default::default()
            },
        );

        let spec_schema = JSONSchemaProps {
            type_: Some("object".to_string()),
            properties: Some(spec_properties),
            ..Default::default()
        };

        let mut top_properties = std::collections::HashMap::new();
        top_properties.insert("spec".to_string(), spec_schema);

        let top_schema = JSONSchemaProps {
            type_: Some("object".to_string()),
            properties: Some(top_properties),
            ..Default::default()
        };

        let mut crd = create_test_crd();
        crd.spec.versions[0].schema = Some(CustomResourceValidation {
            open_apiv3_schema: top_schema,
        });
        crd
    }

    #[test]
    fn test_schema_defaults_applied_to_missing_fields() {
        let crd = create_crd_with_defaults();
        // CR with only cronSpec set — image and replicas should get defaults
        let mut cr = CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(json!({
                "cronSpec": "* * * * */5"
            })),
            status: None,
            extra: Default::default(),
        };

        apply_schema_defaults(&crd, "v1", &mut cr);

        let spec = cr.spec.unwrap();
        assert_eq!(spec["cronSpec"], json!("* * * * */5"));
        assert_eq!(
            spec["image"],
            json!("default-image:latest"),
            "Default for 'image' should be applied"
        );
        assert_eq!(
            spec["replicas"],
            json!(1),
            "Default for 'replicas' should be applied"
        );
    }

    #[test]
    fn test_schema_defaults_do_not_overwrite_existing() {
        let crd = create_crd_with_defaults();
        let mut cr = CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(json!({
                "cronSpec": "0 0 * * *",
                "image": "my-custom-image:v2",
                "replicas": 3
            })),
            status: None,
            extra: Default::default(),
        };

        apply_schema_defaults(&crd, "v1", &mut cr);

        let spec = cr.spec.unwrap();
        assert_eq!(
            spec["image"],
            json!("my-custom-image:v2"),
            "Existing value should not be overwritten"
        );
        assert_eq!(
            spec["replicas"],
            json!(3),
            "Existing value should not be overwritten"
        );
    }

    #[test]
    fn test_schema_defaults_nested_objects() {
        let crd = create_crd_with_defaults();
        // CR has a logging object but without 'enabled' — default should be applied
        let mut cr = CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(json!({
                "cronSpec": "* * * * */5",
                "logging": {}
            })),
            status: None,
            extra: Default::default(),
        };

        apply_schema_defaults(&crd, "v1", &mut cr);

        let spec = cr.spec.unwrap();
        assert_eq!(
            spec["logging"]["enabled"],
            json!(true),
            "Nested default for 'logging.enabled' should be applied"
        );
    }

    #[test]
    fn test_strict_field_validation_rejects_unknown_cr_fields() {
        // Simulate strict field validation on a CR body with an unknown top-level field
        let cr = CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(json!({"cronSpec": "* * * * */5"})),
            status: None,
            extra: Default::default(),
        };

        // Body includes an unknown field "unknownTopLevel"
        let body = br#"{"apiVersion":"stable.example.com/v1","kind":"CronTab","metadata":{"name":"my-crontab"},"spec":{"cronSpec":"* * * * */5"},"unknownTopLevel":"bad"}"#;

        let mut params = HashMap::new();
        params.insert("fieldValidation".to_string(), "Strict".to_string());

        let result = crate::handlers::validation::validate_strict_fields(&params, body, &cr);
        assert!(
            result.is_err(),
            "Strict validation should reject unknown fields"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("strict decoding error"),
            "Error should mention strict decoding: {}",
            err_msg
        );
        assert!(
            err_msg.contains("unknownTopLevel"),
            "Error should mention the unknown field name: {}",
            err_msg
        );
    }

    #[test]
    fn test_strict_field_validation_allows_valid_cr() {
        let cr = CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(json!({"cronSpec": "* * * * */5"})),
            status: None,
            extra: Default::default(),
        };

        let body = br#"{"apiVersion":"stable.example.com/v1","kind":"CronTab","metadata":{"name":"my-crontab"},"spec":{"cronSpec":"* * * * */5"}}"#;

        let mut params = HashMap::new();
        params.insert("fieldValidation".to_string(), "Strict".to_string());

        let result = crate::handlers::validation::validate_strict_fields(&params, body, &cr);
        assert!(
            result.is_ok(),
            "Strict validation should pass for valid CR: {:?}",
            result
        );
    }
}
