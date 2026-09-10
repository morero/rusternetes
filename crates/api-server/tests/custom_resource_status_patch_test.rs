//! `PATCH .../status` on a custom resource — merge-patch body unwrapping.
//!
//! Found live building `guts-shell-bundle`: `PATCH
//! .../releases/platform-db/status` with body `{"status":{"appliedResources":[]}}`
//! (the shape real Kubernetes clients — including `kubectl patch
//! --subresource=status` — actually send, wrapped under a `status` key even
//! though the subresource URL already scopes the patch to `.status`) produced
//! a spurious nested `status.status.appliedResources` instead of merging
//! `appliedResources` directly into `.status`. `patch_custom_resource_status`
//! merged the still-wrapped patch body against the *already-unwrapped*
//! `current.status` content — this test pins the fix (unwrap a top-level
//! `status` key before merging) and the pre-existing unwrapped-body case
//! (some other real client sending the merge patch already unwrapped, which
//! must keep working identically).

use axum::{
    body::Body,
    http::{Method, Request},
};
use rusternetes_api_server::{router::build_router, state::ApiServerState};
use rusternetes_common::{
    auth::TokenManager,
    authz::AlwaysAllowAuthorizer,
    observability::MetricsRegistry,
    resources::{
        CustomResource, CustomResourceDefinition, CustomResourceDefinitionNames,
        CustomResourceDefinitionSpec, CustomResourceDefinitionVersion, CustomResourceSubresourceStatus,
        CustomResourceSubresources, ResourceScope,
    },
    types::ObjectMeta,
};
use rusternetes_storage::{build_key, memory::MemoryStorage, Storage, StorageBackend};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const TEST_NS: &str = "default";
const GROUP: &str = "stable.example.com";
const PLURAL: &str = "crontabs";

fn make_state(mem: Arc<MemoryStorage>) -> Arc<ApiServerState> {
    let backend = Arc::new(StorageBackend::Memory(mem));
    let token_manager = Arc::new(TokenManager::new(b"test-secret"));
    let authorizer = Arc::new(AlwaysAllowAuthorizer);
    let metrics = Arc::new(MetricsRegistry::new());
    Arc::new(ApiServerState::new(
        backend,
        token_manager,
        authorizer,
        metrics,
        true, // skip_auth
    ))
}

fn spawn_router() -> (Arc<MemoryStorage>, axum::Router) {
    let mem = Arc::new(MemoryStorage::new());
    let router = build_router(make_state(mem.clone()), None);
    (mem, router)
}

async fn send_with_ct(
    router: axum::Router,
    method: Method,
    uri: &str,
    content_type: &str,
    body: Vec<u8>,
) -> (u16, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, v)
}

/// CRD with the status subresource enabled — `patch_custom_resource_status`
/// rejects the request outright otherwise.
async fn seed_crd_with_status_subresource(mem: &Arc<MemoryStorage>) {
    let crd = CustomResourceDefinition {
        api_version: "apiextensions.k8s.io/v1".to_string(),
        kind: "CustomResourceDefinition".to_string(),
        metadata: ObjectMeta::new("crontabs.stable.example.com"),
        spec: CustomResourceDefinitionSpec {
            group: GROUP.to_string(),
            names: CustomResourceDefinitionNames {
                plural: PLURAL.to_string(),
                singular: Some("crontab".to_string()),
                kind: "CronTab".to_string(),
                short_names: None,
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
                subresources: Some(CustomResourceSubresources {
                    status: Some(CustomResourceSubresourceStatus {}),
                    scale: None,
                }),
                additional_printer_columns: None,
            }],
            conversion: None,
            preserve_unknown_fields: None,
        },
        status: None,
    };
    let key = build_key("customresourcedefinitions", None, "crontabs.stable.example.com");
    mem.create(&key, &crd).await.expect("seed CRD");
}

async fn seed_crontab_with_status(mem: &Arc<MemoryStorage>, name: &str, status: Value) -> String {
    let cr = CustomResource {
        api_version: format!("{}/v1", GROUP),
        kind: "CronTab".to_string(),
        metadata: {
            let mut meta = ObjectMeta::new(name);
            meta.namespace = Some(TEST_NS.to_string());
            meta
        },
        spec: Some(json!({"cronSpec": "* * * * */5"})),
        status: Some(status),
        extra: Default::default(),
    };
    let key = build_key("stable_example_com_crontabs", Some(TEST_NS), name);
    mem.create(&key, &cr).await.expect("seed crontab");
    key
}

async fn read_stored(mem: &Arc<MemoryStorage>, key: &str) -> Value {
    mem.get::<Value>(key)
        .await
        .unwrap_or_else(|e| panic!("expected key {} to exist: {:?}", key, e))
}

/// The actual regression: a merge-patch body wrapped under `status` (the
/// shape `kubectl patch --subresource=status` sends) must merge its fields
/// directly into `.status`, not nest a nested `status.status`.
#[tokio::test]
async fn status_merge_patch_wrapped_under_status_key_merges_correctly() {
    let (mem, router) = spawn_router();
    seed_crd_with_status_subresource(&mem).await;
    let key = seed_crontab_with_status(
        &mem,
        "my-crontab",
        json!({"appliedResources": [{"kind": "ConfigMap", "name": "old"}], "retryCount": 0}),
    )
    .await;

    let (status_code, response_body) = send_with_ct(
        router,
        Method::PATCH,
        &format!(
            "/apis/{}/v1/namespaces/{}/{}/my-crontab/status",
            GROUP, TEST_NS, PLURAL
        ),
        "application/merge-patch+json",
        serde_json::to_vec(&json!({"status": {"appliedResources": []}})).unwrap(),
    )
    .await;

    assert_eq!(status_code, 200, "body={}", response_body);

    let stored = read_stored(&mem, &key).await;
    assert_eq!(
        stored["status"]["appliedResources"],
        json!([]),
        "appliedResources must be merged directly into .status, not nested; got {}",
        stored["status"]
    );
    assert!(
        stored["status"].get("status").is_none(),
        "must not produce a spurious nested status.status key; got {}",
        stored["status"]
    );
    assert_eq!(
        stored["status"]["retryCount"],
        json!(0),
        "unrelated existing status fields must survive the merge; got {}",
        stored["status"]
    );
}

/// A merge-patch body sent already unwrapped (no top-level `status` key)
/// must keep working exactly as before — not every client wraps it.
#[tokio::test]
async fn status_merge_patch_already_unwrapped_still_works() {
    let (mem, router) = spawn_router();
    seed_crd_with_status_subresource(&mem).await;
    let key = seed_crontab_with_status(
        &mem,
        "unwrapped-crontab",
        json!({"phase": "Pending"}),
    )
    .await;

    let (status_code, response_body) = send_with_ct(
        router,
        Method::PATCH,
        &format!(
            "/apis/{}/v1/namespaces/{}/{}/unwrapped-crontab/status",
            GROUP, TEST_NS, PLURAL
        ),
        "application/merge-patch+json",
        serde_json::to_vec(&json!({"phase": "Running"})).unwrap(),
    )
    .await;

    assert_eq!(status_code, 200, "body={}", response_body);

    let stored = read_stored(&mem, &key).await;
    assert_eq!(stored["status"]["phase"], json!("Running"));
}
