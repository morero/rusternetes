//! Server-side apply (`application/apply-patch+yaml`) against **custom
//! resources** (CRD instances) — `patch_custom_resource`'s SSA branch.
//!
//! Found live building `platform-db-real-cluster` (see
//! `openspec/changes/platform-db-real-cluster/tasks.md`): release-operator
//! applies a rendered chart's resources with server-side apply
//! (kube-rs's `Api::patch` + `PatchParams::apply(...)`), and any
//! second-and-later apply of an *already-existing* custom resource
//! (any `platform.ertia.io` CRD instance, or a third-party CRD like
//! CNPG's `Cluster`) failed with "Unsupported content type:
//! application/apply-patch+yaml" — `patch_custom_resource` only ever
//! recognized the three regular patch types (`PatchType::from_content_type`),
//! never server-side apply, even though the "resource doesn't exist yet"
//! branch already special-cased `apply-patch` content types. Typed
//! built-in resources (`generic_patch.rs`) already had a real SSA
//! implementation (`rusternetes_common::server_side_apply`); custom
//! resources never got it wired up.
//!
//! Mirrors `decoder_content_type_test.rs`'s SSA-on-Pod tests
//! (`test_content_type_apply_patch_yaml_routes_to_ssa` /
//! `..._without_field_manager_rejected`), applied to a CRD instance
//! instead of a built-in Pod, and specifically exercising the *existing
//! resource* branch that was actually broken (a create-only SSA test
//! would not have caught this regression).

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
        CustomResourceDefinitionSpec, CustomResourceDefinitionVersion, ResourceScope,
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

async fn read_stored(mem: &Arc<MemoryStorage>, key: &str) -> Value {
    mem.get::<Value>(key)
        .await
        .unwrap_or_else(|e| panic!("expected key {} to exist: {:?}", key, e))
}

/// Seed the `crontabs.stable.example.com` CRD — same fixture shape as
/// `custom_resource.rs`'s own `create_test_crd()` unit-test helper.
async fn seed_crd(mem: &Arc<MemoryStorage>) {
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
                subresources: None,
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

/// Seed one existing `CronTab` instance directly into storage — the SSA
/// branch's "resource already exists" path is what was actually broken;
/// a create-only test would not exercise it.
async fn seed_crontab(mem: &Arc<MemoryStorage>, name: &str) -> String {
    let cr = CustomResource {
        api_version: format!("{}/v1", GROUP),
        kind: "CronTab".to_string(),
        metadata: {
            let mut meta = ObjectMeta::new(name);
            meta.namespace = Some(TEST_NS.to_string());
            meta
        },
        spec: Some(json!({"cronSpec": "* * * * */5", "image": "my-cron-image:1.0"})),
        status: None,
        extra: Default::default(),
    };
    let key = build_key("stable_example_com_crontabs", Some(TEST_NS), name);
    mem.create(&key, &cr).await.expect("seed crontab");
    key
}

/// The actual regression: server-side apply against an *existing* custom
/// resource must succeed (not 4xx with "Unsupported content type"), and
/// must genuinely apply SSA semantics — `metadata.managedFields` gets an
/// entry for the field manager, the unambiguous signal the SSA path (not
/// some fallback) was taken.
#[tokio::test]
async fn test_ssa_patch_updates_an_existing_custom_resource() {
    let (mem, router) = spawn_router();
    seed_crd(&mem).await;
    let key = seed_crontab(&mem, "my-crontab").await;

    let apply_doc = json!({
        "apiVersion": format!("{}/v1", GROUP),
        "kind": "CronTab",
        "metadata": {"name": "my-crontab", "namespace": TEST_NS},
        "spec": {"cronSpec": "* * * * */5", "image": "my-cron-image:2.0"}
    });

    let (status, response_body) = send_with_ct(
        router,
        Method::PATCH,
        &format!(
            "/apis/{}/v1/namespaces/{}/{}/my-crontab?fieldManager=release-operator",
            GROUP, TEST_NS, PLURAL
        ),
        "application/apply-patch+yaml",
        serde_json::to_vec(&apply_doc).unwrap(),
    )
    .await;

    assert!(
        (200..300).contains(&status),
        "SSA patch of an existing custom resource must succeed; got {} body={}",
        status,
        response_body
    );

    let stored = read_stored(&mem, &key).await;
    assert_eq!(
        stored["spec"]["image"], "my-cron-image:2.0",
        "SSA-applied field must land in storage; got {}",
        stored
    );
    let mf = stored["metadata"]["managedFields"].as_array();
    assert!(
        mf.is_some() && !mf.unwrap().is_empty(),
        "SSA path must populate metadata.managedFields; got stored={}",
        stored
    );
    assert!(
        mf.unwrap()
            .iter()
            .any(|entry| entry["manager"] == "release-operator"),
        "managedFields must include our manager; got {:?}",
        mf
    );
}

/// A second, idempotent apply of the *same* content by the same manager
/// (the actual originally-observed symptom: release-operator re-applying
/// a rendered chart's already-created objects on every reconcile) must
/// keep succeeding, not regress into a conflict or a repeat 4xx.
#[tokio::test]
async fn test_ssa_patch_is_idempotent_across_repeated_applies() {
    let (mem, router) = spawn_router();
    seed_crd(&mem).await;
    let key = seed_crontab(&mem, "idempotent-crontab").await;

    let apply_doc = json!({
        "apiVersion": format!("{}/v1", GROUP),
        "kind": "CronTab",
        "metadata": {"name": "idempotent-crontab", "namespace": TEST_NS},
        "spec": {"cronSpec": "* * * * */5", "image": "my-cron-image:1.0"}
    });
    let uri = format!(
        "/apis/{}/v1/namespaces/{}/{}/idempotent-crontab?fieldManager=release-operator",
        GROUP, TEST_NS, PLURAL
    );

    for attempt in 1..=2 {
        let (status, response_body) = send_with_ct(
            router.clone(),
            Method::PATCH,
            &uri,
            "application/apply-patch+yaml",
            serde_json::to_vec(&apply_doc).unwrap(),
        )
        .await;
        assert!(
            (200..300).contains(&status),
            "attempt {}: repeated SSA apply must keep succeeding; got {} body={}",
            attempt,
            status,
            response_body
        );
    }

    let stored = read_stored(&mem, &key).await;
    assert_eq!(stored["spec"]["image"], "my-cron-image:1.0");
}

/// `application/apply-patch+yaml` WITHOUT `?fieldManager` must fall
/// through to the regular patch dispatcher and 4xx there — same
/// requirement `decoder_content_type_test.rs` already pins for Pods.
#[tokio::test]
async fn test_ssa_patch_without_field_manager_rejected() {
    let (mem, router) = spawn_router();
    seed_crd(&mem).await;
    seed_crontab(&mem, "nofm-crontab").await;

    let apply_doc = json!({
        "apiVersion": format!("{}/v1", GROUP),
        "kind": "CronTab",
        "metadata": {"name": "nofm-crontab", "namespace": TEST_NS},
        "spec": {"cronSpec": "* * * * */5", "image": "my-cron-image:2.0"}
    });

    let (status, response_body) = send_with_ct(
        router,
        Method::PATCH,
        &format!(
            "/apis/{}/v1/namespaces/{}/{}/nofm-crontab",
            GROUP, TEST_NS, PLURAL
        ),
        "application/apply-patch+yaml",
        serde_json::to_vec(&apply_doc).unwrap(),
    )
    .await;

    assert!(
        (400..500).contains(&status),
        "apply-patch+yaml WITHOUT fieldManager must be rejected; got {} body={}",
        status,
        response_body
    );
}
