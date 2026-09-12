//! `PUT .../<name>` on a custom resource must populate `oldObject` in the
//! AdmissionReview sent to validating webhooks.
//!
//! Found live getting CNPG's own Cluster validating webhook working:
//! `update_custom_resource` always passed `None` for `old_object` on every
//! UPDATE, even though a previous version of the resource existed in
//! storage. Real Kubernetes always populates `AdmissionRequest.oldObject`
//! for UPDATE (and DELETE) — some webhooks (CNPG's `vcluster.cnpg.io`
//! included) unconditionally decode it to compare against the new spec.
//! With `oldObject` missing, CNPG's own webhook server rejected every single
//! Cluster update with `{"message":"there is no content to decode","code":400}`
//! (`controller-runtime`'s literal message for an empty `oldObject.Raw`),
//! which surfaced back at the operator as a permanently failing reconcile —
//! not distinguishable from a real validation failure until traced through.

use axum::{
    body::Body,
    http::{Method, Request},
};
use rusternetes_api_server::{router::build_router, state::ApiServerState};
use rusternetes_common::{
    admission::AdmissionReview,
    auth::TokenManager,
    authz::AlwaysAllowAuthorizer,
    observability::MetricsRegistry,
    resources::{
        CustomResource, CustomResourceDefinition, CustomResourceDefinitionNames,
        CustomResourceDefinitionSpec, CustomResourceDefinitionVersion, OperationType, Rule,
        RuleWithOperations, SideEffectClass, ValidatingWebhook, ValidatingWebhookConfiguration,
        WebhookClientConfig,
    },
    types::ObjectMeta,
};
use rusternetes_storage::{build_key, memory::MemoryStorage, Storage, StorageBackend};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use tower::ServiceExt;
use warp::Filter;

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
            scope: rusternetes_common::resources::ResourceScope::Namespaced,
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
    let key = build_key(
        "customresourcedefinitions",
        None,
        "crontabs.stable.example.com",
    );
    mem.create(&key, &crd).await.expect("seed CRD");
}

async fn seed_crontab(mem: &Arc<MemoryStorage>, name: &str, cron_spec: &str) {
    let cr = CustomResource {
        api_version: format!("{}/v1", GROUP),
        kind: "CronTab".to_string(),
        metadata: {
            let mut meta = ObjectMeta::new(name);
            meta.namespace = Some(TEST_NS.to_string());
            meta
        },
        spec: Some(json!({"cronSpec": cron_spec})),
        status: None,
        extra: Default::default(),
    };
    let key = build_key("stable_example_com_crontabs", Some(TEST_NS), name);
    mem.create(&key, &cr).await.expect("seed crontab");
}

/// A validating webhook that captures the `oldObject` it was sent and
/// always allows the request.
async fn start_capturing_validating_server() -> (
    String,
    oneshot::Sender<()>,
    Arc<Mutex<Option<Option<Value>>>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let captured: Arc<Mutex<Option<Option<Value>>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();

    let route = warp::post()
        .and(warp::body::json())
        .map(move |review: AdmissionReview| {
            let uid = review
                .request
                .as_ref()
                .map(|r| r.uid.clone())
                .unwrap_or_else(|| "unknown".to_string());
            *captured_clone.lock().unwrap() =
                Some(review.request.as_ref().and_then(|r| r.old_object.clone()));
            let response = rusternetes_common::admission::AdmissionReviewResponse {
                uid,
                allowed: true,
                status: None,
                patch: None,
                patch_type: None,
                audit_annotations: None,
                warnings: None,
            };
            let response_review = AdmissionReview {
                api_version: "admission.k8s.io/v1".to_string(),
                kind: "AdmissionReview".to_string(),
                request: None,
                response: Some(response),
            };
            warp::reply::json(&response_review)
        });

    let (addr, server) =
        warp::serve(route).bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
            shutdown_rx.await.ok();
        });

    tokio::spawn(server);

    let url = format!("http://{}", addr);
    (url, shutdown_tx, captured)
}

async fn seed_validating_webhook(mem: &Arc<MemoryStorage>, url: String) {
    let config = ValidatingWebhookConfiguration {
        api_version: "admissionregistration.k8s.io/v1".to_string(),
        kind: "ValidatingWebhookConfiguration".to_string(),
        metadata: ObjectMeta::new("test-crontab-webhook"),
        webhooks: Some(vec![ValidatingWebhook {
            name: "vcrontab.test.io".to_string(),
            client_config: WebhookClientConfig {
                url: Some(url),
                service: None,
                ca_bundle: None,
            },
            rules: vec![RuleWithOperations {
                operations: vec![OperationType::Update],
                rule: Rule {
                    api_groups: vec![GROUP.to_string()],
                    api_versions: vec!["v1".to_string()],
                    resources: vec![PLURAL.to_string()],
                    scope: None,
                },
            }],
            failure_policy: None,
            match_policy: None,
            namespace_selector: None,
            object_selector: None,
            side_effects: SideEffectClass::None,
            timeout_seconds: None,
            admission_review_versions: vec!["v1".to_string()],
            match_conditions: None,
        }]),
    };
    let key = build_key(
        "validatingwebhookconfigurations",
        None,
        "test-crontab-webhook",
    );
    mem.create(&key, &config).await.expect("seed webhook config");
}

#[tokio::test]
async fn update_sends_old_object_to_validating_webhook() {
    let (mem, router) = spawn_router();
    seed_crd(&mem).await;
    seed_crontab(&mem, "my-crontab", "* * * * */5").await;

    let (url, _shutdown, captured) = start_capturing_validating_server().await;
    seed_validating_webhook(&mem, url).await;

    let updated_body = json!({
        "apiVersion": format!("{}/v1", GROUP),
        "kind": "CronTab",
        "metadata": {"name": "my-crontab", "namespace": TEST_NS},
        "spec": {"cronSpec": "*/10 * * * *"},
    });

    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!(
            "/apis/{}/v1/namespaces/{}/{}/my-crontab",
            GROUP, TEST_NS, PLURAL
        ))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&updated_body).unwrap()))
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "update should succeed: {}",
        String::from_utf8_lossy(&bytes)
    );

    let captured_old_object = captured
        .lock()
        .unwrap()
        .clone()
        .expect("webhook should have been called at all");
    let old_object =
        captured_old_object.expect("oldObject must be populated for an UPDATE, not null");
    assert_eq!(
        old_object["spec"]["cronSpec"], "* * * * */5",
        "oldObject must reflect the resource's state BEFORE this update, got: {:?}",
        old_object
    );
}
