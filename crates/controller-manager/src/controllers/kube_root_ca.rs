//! Puts a `kube-root-ca.crt` ConfigMap in every namespace.
//!
//! Real Kubernetes runs exactly this controller, and things quietly depend
//! on it. The kubelet projects `ca.crt` into each pod's ServiceAccount
//! mount from this ConfigMap, in that pod's own namespace, and marks the
//! projection `optional` — so a namespace without one does not fail to
//! mount, it just produces a pod with no `ca.crt` file. Every pod starts,
//! RBAC resolves, the API server answers, and any client doing ordinary
//! in-cluster TLS verification fails with `x509: certificate signed by
//! unknown authority`, wherever it happens to dial first.
//!
//! Before this controller existed, two other things tried. The API server's
//! namespace-create handler writes the ConfigMap, but reads the CA from
//! three fixed paths (`/etc/kubernetes/pki/ca.crt`,
//! `/etc/kubernetes/pki/api-server.crt`, `/root/.rusternetes/certs/ca.crt`)
//! that a harness running from a checkout does not have — its own log then
//! says `CA cert is empty, skipping kube-root-ca.crt` for every namespace it
//! makes. That left whichever tool started the cluster to write the
//! ConfigMap itself, for a fixed list of namespaces, which holds right up
//! until someone creates a namespace that is not on the list. One did, and
//! the operator deployed into it crash-looped on a cache-sync timeout naming
//! neither TLS nor a missing file.
//!
//! So it belongs here, beside the ServiceAccount controller that already
//! populates every new namespace: watch namespaces, write the ConfigMap, and
//! let the CA path be configured rather than guessed.

use anyhow::Result;
use futures::StreamExt;
use rusternetes_common::resources::{ConfigMap, Namespace};
use rusternetes_common::types::{ObjectMeta, TypeMeta};
use rusternetes_storage::{build_key, build_prefix, extract_key, Storage, WorkQueue};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// The ConfigMap's name and its single key — both fixed by the kubelet's
/// projection, which looks for exactly this name and this key.
const CONFIGMAP_NAME: &str = "kube-root-ca.crt";
const CA_KEY: &str = "ca.crt";

/// Where to read the cluster CA from, in preference order. The env var comes
/// first so a cluster running out of a checkout can say where its cert
/// actually is; the rest are the same fixed paths the API server's own
/// namespace handler tries, kept so a conventionally-installed cluster needs
/// no configuration.
const CA_PATH_ENV: &str = "RUSTERNETES_CLUSTER_CA_PATH";
const CA_FALLBACK_PATHS: [&str; 3] = [
    "/etc/kubernetes/pki/ca.crt",
    "/etc/kubernetes/pki/api-server.crt",
    "/root/.rusternetes/certs/ca.crt",
];

pub struct KubeRootCaController<S: Storage> {
    storage: Arc<S>,
    /// Read once at construction. `None` means no CA was found anywhere,
    /// which is reported once here rather than once per namespace forever.
    ca_cert: Option<String>,
}

impl<S: Storage + 'static> KubeRootCaController<S> {
    pub fn new(storage: Arc<S>) -> Self {
        let ca_cert = Self::load_ca_cert();
        if ca_cert.is_none() {
            warn!(
                "No cluster CA found (set {} or place it at one of {:?}); \
                 {} will not be written, and pods verifying the API server's \
                 certificate will fail with `certificate signed by unknown authority`",
                CA_PATH_ENV, CA_FALLBACK_PATHS, CONFIGMAP_NAME
            );
        }
        Self { storage, ca_cert }
    }

    fn load_ca_cert() -> Option<String> {
        if let Ok(path) = std::env::var(CA_PATH_ENV) {
            match std::fs::read_to_string(&path) {
                Ok(pem) if !pem.trim().is_empty() => {
                    info!("Loaded cluster CA from {} ({})", path, CA_PATH_ENV);
                    return Some(pem);
                }
                Ok(_) => warn!("{} points at {}, which is empty", CA_PATH_ENV, path),
                Err(e) => warn!(
                    "{} points at {}, which is unreadable: {}",
                    CA_PATH_ENV, path, e
                ),
            }
        }
        for path in CA_FALLBACK_PATHS {
            if let Ok(pem) = std::fs::read_to_string(path) {
                if !pem.trim().is_empty() {
                    info!("Loaded cluster CA from {}", path);
                    return Some(pem);
                }
            }
        }
        None
    }

    /// Watch-based run loop, resyncing every 30s — the same shape as the
    /// ServiceAccount controller, and watching the same thing it does.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        if self.ca_cert.is_none() {
            // Nothing to write, and no amount of watching will change that:
            // the cert is read once at startup. Returning keeps a pointless
            // watch off the storage layer.
            return Ok(());
        }

        let queue = WorkQueue::new();

        let worker_queue = queue.clone();
        let worker_self = Arc::clone(&self);
        tokio::spawn(async move {
            worker_self.worker(worker_queue).await;
        });

        loop {
            self.enqueue_all(&queue).await;

            let prefix = build_prefix("namespaces", None);
            let mut watch = match self.storage.watch(&prefix).await {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to establish namespace watch: {}, retrying", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut resync = tokio::time::interval(std::time::Duration::from_secs(30));
            resync.tick().await;

            let mut watch_broken = false;
            while !watch_broken {
                tokio::select! {
                    event = watch.next() => {
                        match event {
                            Some(Ok(ev)) => {
                                let key = extract_key(&ev);
                                queue.add(key).await;
                            }
                            Some(Err(e)) => {
                                warn!("Namespace watch error: {}, reconnecting", e);
                                watch_broken = true;
                            }
                            None => {
                                warn!("Namespace watch stream ended, reconnecting");
                                watch_broken = true;
                            }
                        }
                    }
                    _ = resync.tick() => {
                        self.enqueue_all(&queue).await;
                    }
                }
            }
        }
    }

    async fn worker(&self, queue: WorkQueue) {
        while let Some(key) = queue.get().await {
            // Namespaces are cluster-scoped, so the watch key is
            // `namespaces/<name>` — no namespace segment in the middle.
            let name = key.rsplit('/').next().unwrap_or_default().to_string();
            if name.is_empty() {
                queue.done(&key).await;
                continue;
            }
            match self.ensure_configmap(&name).await {
                Ok(()) => queue.forget(&key).await,
                Err(e) => {
                    error!("Failed to ensure {} in {}: {}", CONFIGMAP_NAME, name, e);
                    queue.requeue_rate_limited(key.clone()).await;
                }
            }
            queue.done(&key).await;
        }
    }

    async fn enqueue_all(&self, queue: &WorkQueue) {
        match self
            .storage
            .list::<Namespace>("/registry/namespaces/")
            .await
        {
            Ok(namespaces) => {
                for ns in &namespaces {
                    if ns.metadata.deletion_timestamp.is_none() {
                        queue.add(format!("namespaces/{}", ns.metadata.name)).await;
                    }
                }
            }
            Err(e) => error!(
                "Failed to list namespaces for {} enqueue: {}",
                CONFIGMAP_NAME, e
            ),
        }
    }

    /// Creates the ConfigMap if absent, and corrects `ca.crt` if it has
    /// drifted — a rotated CA has to reach pods, and a namespace whose copy
    /// is stale fails exactly like a namespace with no copy at all.
    async fn ensure_configmap(&self, namespace: &str) -> Result<()> {
        let Some(ca_cert) = self.ca_cert.as_ref() else {
            return Ok(());
        };

        // Don't write into a namespace on its way out: the namespace
        // controller is deleting its contents, and a ConfigMap created now
        // either races that or strands an object in a terminating namespace.
        let ns_key = build_key("namespaces", None, namespace);
        if let Ok(ns) = self.storage.get::<Namespace>(&ns_key).await {
            if ns.metadata.deletion_timestamp.is_some() {
                debug!(
                    "Skipping {} in terminating namespace {}",
                    CONFIGMAP_NAME, namespace
                );
                return Ok(());
            }
        }

        let key = build_key("configmaps", Some(namespace), CONFIGMAP_NAME);
        match self.storage.get::<ConfigMap>(&key).await {
            Ok(existing) => {
                let current = existing.data.as_ref().and_then(|d| d.get(CA_KEY));
                if current.is_some_and(|c| c == ca_cert) {
                    return Ok(());
                }
                // Keep everything else on the object — labels someone added,
                // other keys — and correct only `ca.crt`.
                let mut updated = existing;
                updated
                    .data
                    .get_or_insert_with(HashMap::new)
                    .insert(CA_KEY.to_string(), ca_cert.clone());
                self.storage.update(&key, &updated).await?;
                info!("Corrected {} in namespace {}", CONFIGMAP_NAME, namespace);
            }
            Err(_) => {
                let cm = ConfigMap {
                    type_meta: TypeMeta {
                        kind: "ConfigMap".to_string(),
                        api_version: "v1".to_string(),
                    },
                    metadata: ObjectMeta::new(CONFIGMAP_NAME).with_namespace(namespace.to_string()),
                    data: Some(HashMap::from([(CA_KEY.to_string(), ca_cert.clone())])),
                    binary_data: None,
                    immutable: None,
                };
                match self.storage.create(&key, &cm).await {
                    Ok(_) => info!("Created {} in namespace {}", CONFIGMAP_NAME, namespace),
                    // Another writer got there first — the API server's own
                    // namespace handler still tries, and a resync races
                    // itself. Both write the same bytes, so this is a no-op,
                    // not a conflict worth retrying.
                    Err(e) if is_already_exists(&e) => {
                        debug!("{} already present in {}", CONFIGMAP_NAME, namespace)
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }
}

fn is_already_exists(err: &impl std::fmt::Display) -> bool {
    let text = err.to_string().to_lowercase();
    text.contains("already exists") || text.contains("alreadyexists")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_storage::MemoryStorage;

    fn storage() -> Arc<MemoryStorage> {
        Arc::new(MemoryStorage::new())
    }

    async fn namespace(storage: &Arc<MemoryStorage>, name: &str) {
        let ns = Namespace {
            type_meta: TypeMeta {
                kind: "Namespace".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: ObjectMeta::new(name),
            spec: None,
            status: None,
        };
        storage
            .create(&build_key("namespaces", None, name), &ns)
            .await
            .expect("create namespace");
    }

    fn controller(storage: Arc<MemoryStorage>, ca: &str) -> KubeRootCaController<MemoryStorage> {
        KubeRootCaController {
            storage,
            ca_cert: Some(ca.to_string()),
        }
    }

    async fn ca_in(storage: &Arc<MemoryStorage>, ns: &str) -> Option<String> {
        storage
            .get::<ConfigMap>(&build_key("configmaps", Some(ns), CONFIGMAP_NAME))
            .await
            .ok()
            .and_then(|cm| cm.data.and_then(|d| d.get(CA_KEY).cloned()))
    }

    /// The whole point: a namespace nobody listed anywhere still gets the
    /// ConfigMap, because the controller watches namespaces rather than
    /// being handed a list of them.
    #[tokio::test]
    async fn a_new_namespace_gets_the_configmap() {
        let s = storage();
        namespace(&s, "guts-system").await;
        controller(s.clone(), "PEM")
            .ensure_configmap("guts-system")
            .await
            .expect("ensure");
        assert_eq!(ca_in(&s, "guts-system").await.as_deref(), Some("PEM"));
    }

    /// Resync runs every 30s against every namespace, so the common case by
    /// far is "already correct". It must not write.
    #[tokio::test]
    async fn an_up_to_date_configmap_is_left_alone() {
        let s = storage();
        namespace(&s, "default").await;
        let c = controller(s.clone(), "PEM");
        c.ensure_configmap("default").await.expect("first");
        let before = s
            .get::<ConfigMap>(&build_key("configmaps", Some("default"), CONFIGMAP_NAME))
            .await
            .expect("get");
        c.ensure_configmap("default").await.expect("second");
        let after = s
            .get::<ConfigMap>(&build_key("configmaps", Some("default"), CONFIGMAP_NAME))
            .await
            .expect("get");
        assert_eq!(
            before.metadata.resource_version, after.metadata.resource_version,
            "a second pass over an unchanged ConfigMap must not write"
        );
    }

    /// A rotated CA has to reach pods. A namespace holding the old bytes
    /// fails exactly like one holding none.
    #[tokio::test]
    async fn a_stale_ca_is_corrected() {
        let s = storage();
        namespace(&s, "default").await;
        controller(s.clone(), "OLD")
            .ensure_configmap("default")
            .await
            .expect("seed");
        controller(s.clone(), "NEW")
            .ensure_configmap("default")
            .await
            .expect("correct");
        assert_eq!(ca_in(&s, "default").await.as_deref(), Some("NEW"));
    }

    /// Writing into a namespace the namespace controller is emptying either
    /// races it or strands an object.
    #[tokio::test]
    async fn a_terminating_namespace_is_skipped() {
        let s = storage();
        let mut ns = Namespace {
            type_meta: TypeMeta {
                kind: "Namespace".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: ObjectMeta::new("doomed"),
            spec: None,
            status: None,
        };
        ns.metadata.deletion_timestamp = Some(chrono::Utc::now());
        s.create(&build_key("namespaces", None, "doomed"), &ns)
            .await
            .expect("create");

        controller(s.clone(), "PEM")
            .ensure_configmap("doomed")
            .await
            .expect("ensure");
        assert!(
            ca_in(&s, "doomed").await.is_none(),
            "no ConfigMap should be created in a terminating namespace"
        );
    }

    /// With no CA anywhere, the controller does nothing rather than writing
    /// an empty `ca.crt`, which would be worse than a missing file: a client
    /// would read it, parse no certificates, and fail with a different error.
    #[tokio::test]
    async fn without_a_ca_nothing_is_written() {
        let s = storage();
        namespace(&s, "default").await;
        let c = KubeRootCaController {
            storage: s.clone(),
            ca_cert: None,
        };
        c.ensure_configmap("default").await.expect("ensure");
        assert!(ca_in(&s, "default").await.is_none());
    }
}
