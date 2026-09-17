//! Deleting a Pod the way the kubelet can see.
//!
//! A controller that removes a Pod with `storage.delete` takes the object out
//! from under the kubelet: the containers are still running, and nothing has
//! told the node to stop them. The kubelet notices eventually — it reaps
//! containers whose Pod no longer exists — but "eventually" measured 45–75
//! seconds here, and for that whole window the cluster reports a workload that
//! is gone while the workload keeps running (ISSUES.md #76).
//!
//! **For a platform whose operators are writers, that window is not cosmetic.**
//! An operator scaled to zero keeps reconciling and keeps patching objects
//! while the API says it does not exist. It corrupted two test verdicts in one
//! session before the mechanism was found, each time by making a working fix
//! look broken.
//!
//! The kubelet already implements the correct sequence: it sees
//! `deletionTimestamp`, stops the containers, and *then* removes the object
//! from storage. So nothing new is needed on the node side — the controllers
//! simply have to stop bypassing it. That is what this function is for.
//!
//! **The rule, stated once so it does not have to be re-derived: delete
//! gracefully where the Pod may have running containers, and raw where it
//! demonstrably cannot.** Applying it mechanically to every `storage.delete`
//! call would be wrong in both directions, and each exception in this crate is
//! commented at its site:
//!
//! - `replicaset`'s scale-down and `daemonset`'s rolling update remove *live*
//!   pods — graceful.
//! - `daemonset`'s ineligible-node sweep removes pods for two different
//!   reasons and cannot tell them apart by itself, so it asks
//!   [`delete_pod_respecting_node`].
//! - `daemonset`'s terminal-pod cleanup and `ttl_controller`'s finished-Job
//!   cleanup remove pods whose containers have already exited — raw, because
//!   there is nothing to wait for and waiting would delay the replacement the
//!   DaemonSet creates in the same cycle.
//! - `node`'s eviction runs when the node has *failed*, so no kubelet will ever
//!   confirm — raw, or the pods sit `Terminating` forever. Real Kubernetes
//!   force-deletes here for the same reason.
//!
//! This is the same defect as ISSUES.md #72, where the garbage collector
//! deleted dependents through raw storage and skipped their finalizers. Same
//! cause — a controller reaching past the deletion semantics — and the second
//! time it has been found, which is why this is a shared helper rather than
//! another local fix.

use rusternetes_common::resources::Pod;
use rusternetes_storage::{build_key, Storage};
use tracing::debug;

/// Falls back to this when the Pod names no `terminationGracePeriodSeconds`,
/// matching Kubernetes' own default.
pub const DEFAULT_GRACE_PERIOD_SECONDS: i64 = 30;

/// Marks a Pod for deletion and leaves it for the kubelet to finish.
///
/// Sets `deletionTimestamp` and `deletionGracePeriodSeconds`, then returns. The
/// object deliberately stays in storage: the kubelet removes it once the
/// containers are actually stopped, which is what makes "the API no longer
/// lists this Pod" mean "this Pod is no longer running".
///
/// Idempotent. A Pod already marked keeps its original timestamp — re-stamping
/// it on every reconcile would push the deadline back forever, which is the
/// same shape as the `lastTransitionTime` bug that appears throughout this
/// repo.
///
/// A Pod that has already gone is not an error: something else deleting it
/// first is the outcome the caller wanted.
pub async fn delete_pod_gracefully<S: Storage>(
    storage: &S,
    namespace: &str,
    name: &str,
) -> rusternetes_common::Result<()> {
    let key = build_key("pods", Some(namespace), name);
    let mut pod: Pod = match storage.get(&key).await {
        Ok(pod) => pod,
        Err(rusternetes_common::Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };

    if pod.metadata.deletion_timestamp.is_some() {
        debug!("Pod {}/{} is already terminating", namespace, name);
        return Ok(());
    }

    pod.metadata.deletion_timestamp = Some(chrono::Utc::now());
    pod.metadata.deletion_grace_period_seconds = Some(
        pod.spec
            .as_ref()
            .and_then(|s| s.termination_grace_period_seconds)
            .unwrap_or(DEFAULT_GRACE_PERIOD_SECONDS),
    );
    storage.update(&key, &pod).await?;

    debug!(
        "Pod {}/{} marked for deletion; the kubelet removes it once its containers stop",
        namespace, name
    );
    Ok(())
}

/// Removes a Pod, choosing the right mechanism from whether its node still
/// exists.
///
/// The rule this whole module encodes is **graceful if and only if there is a
/// live kubelet to do the work.** Marking a Pod whose node has been removed
/// leaves it `Terminating` forever, because the confirmation it waits for can
/// never arrive; force-deleting one whose node is alive is the defect in
/// ISSUES.md #76. A caller that removes Pods for both reasons — a DaemonSet
/// dropping a node that either vanished or merely stopped matching — cannot
/// pick correctly without asking, so it asks here.
pub async fn delete_pod_respecting_node<S: Storage>(
    storage: &S,
    namespace: &str,
    name: &str,
    node_name: &str,
) -> rusternetes_common::Result<()> {
    let node_key = build_key("nodes", None, node_name);
    let node_exists = storage
        .get::<rusternetes_common::resources::Node>(&node_key)
        .await
        .is_ok();

    if node_exists {
        delete_pod_gracefully(storage, namespace, name).await
    } else {
        // No kubelet will ever confirm this one. Same reasoning as the node
        // controller's eviction path.
        debug!(
            "Node {} is gone; removing pod {}/{} outright",
            node_name, namespace, name
        );
        let key = build_key("pods", Some(namespace), name);
        match storage.delete(&key).await {
            Ok(()) | Err(rusternetes_common::Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_common::resources::PodSpec;
    use rusternetes_common::types::ObjectMeta;
    use rusternetes_storage::memory::MemoryStorage;

    fn pod(name: &str, grace: Option<i64>) -> Pod {
        Pod {
            type_meta: rusternetes_common::types::TypeMeta {
                kind: "Pod".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                ..ObjectMeta::new(name)
            },
            spec: Some(PodSpec {
                termination_grace_period_seconds: grace,
                ..Default::default()
            }),
            status: None,
        }
    }

    async fn stored(storage: &MemoryStorage, name: &str) -> Pod {
        storage
            .get(&build_key("pods", Some("default"), name))
            .await
            .expect("pod is still there")
    }

    /// The property the whole module exists for: the object outlives the call,
    /// so the kubelet gets a chance to stop the containers before anything
    /// reports the Pod gone.
    #[tokio::test]
    async fn the_pod_survives_the_call_and_is_marked_instead() {
        let storage = MemoryStorage::new();
        let key = build_key("pods", Some("default"), "web");
        storage.create(&key, &pod("web", None)).await.unwrap();

        delete_pod_gracefully(&storage, "default", "web")
            .await
            .unwrap();

        let after = stored(&storage, "web").await;
        assert!(
            after.metadata.deletion_timestamp.is_some(),
            "marked for deletion"
        );
        assert_eq!(
            after.metadata.deletion_grace_period_seconds,
            Some(DEFAULT_GRACE_PERIOD_SECONDS)
        );
    }

    #[tokio::test]
    async fn the_pods_own_grace_period_is_honoured() {
        let storage = MemoryStorage::new();
        let key = build_key("pods", Some("default"), "slow");
        storage.create(&key, &pod("slow", Some(120))).await.unwrap();

        delete_pod_gracefully(&storage, "default", "slow")
            .await
            .unwrap();

        assert_eq!(
            stored(&storage, "slow")
                .await
                .metadata
                .deletion_grace_period_seconds,
            Some(120)
        );
    }

    /// Re-stamping on every reconcile would push the deadline back forever and
    /// the Pod would never finish terminating — the same shape as the
    /// `lastTransitionTime` bug this repo has fixed repeatedly.
    #[tokio::test]
    async fn a_terminating_pod_keeps_its_original_timestamp() {
        let storage = MemoryStorage::new();
        let key = build_key("pods", Some("default"), "web");
        storage.create(&key, &pod("web", None)).await.unwrap();

        delete_pod_gracefully(&storage, "default", "web")
            .await
            .unwrap();
        let first = stored(&storage, "web").await.metadata.deletion_timestamp;

        delete_pod_gracefully(&storage, "default", "web")
            .await
            .unwrap();
        let second = stored(&storage, "web").await.metadata.deletion_timestamp;

        assert_eq!(first, second);
    }

    /// Something else having deleted it first is the outcome the caller wanted,
    /// not a failure to report.
    #[tokio::test]
    async fn an_already_gone_pod_is_not_an_error() {
        let storage = MemoryStorage::new();
        delete_pod_gracefully(&storage, "default", "never-existed")
            .await
            .expect("absent is fine");
    }
}
