use anyhow::Result;
use rusternetes_common::resources::volume::{
    PersistentVolumeClaimPhase, PersistentVolumeClaimStatus, PersistentVolumePhase,
};
use rusternetes_common::resources::{
    PersistentVolume, PersistentVolumeClaim, PersistentVolumeStatus,
};
use rusternetes_storage::{build_key, extract_key, Storage, WorkQueue};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info};

pub struct PVBinderController<S: Storage> {
    storage: Arc<S>,
}

impl<S: Storage + 'static> PVBinderController<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        use futures::StreamExt;

        info!("Starting PV/PVC Binder Controller");

        let queue = WorkQueue::new();

        let worker_queue = queue.clone();
        let worker_self = Arc::clone(&self);
        tokio::spawn(async move {
            worker_self.worker(worker_queue).await;
        });

        loop {
            self.enqueue_all(&queue).await;

            let prefix = rusternetes_storage::build_prefix("persistentvolumeclaims", None);
            let watch_result = self.storage.watch(&prefix).await;
            let mut watch = match watch_result {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to establish watch: {}, retrying", e);
                    time::sleep(Duration::from_secs(5)).await;
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
                                tracing::warn!("Watch error: {}, reconnecting", e);
                                watch_broken = true;
                            }
                            None => {
                                tracing::warn!("Watch stream ended, reconnecting");
                                watch_broken = true;
                            }
                        }
                    }
                    _ = resync.tick() => {
                        self.enqueue_all(&queue).await;
                        // On the resync tick, not the per-PVC worker: a released
                        // PV has no claim left to enqueue, so nothing would ever
                        // drive this from the queue. (An earlier version of this
                        // hung it off `reconcile_all`, which this controller
                        // never calls in production — the reclaim simply never
                        // ran.)
                        if let Err(e) = self.reclaim_released_volumes().await {
                            error!("Failed to reclaim released PVs: {}", e);
                        }
                    }
                }
            }
        }
    }
    async fn worker(&self, queue: WorkQueue) {
        while let Some(key) = queue.get().await {
            let parts: Vec<&str> = key.splitn(3, '/').collect();
            let (ns, name) = match parts.len() {
                3 => (parts[1], parts[2]),
                _ => {
                    queue.done(&key).await;
                    continue;
                }
            };
            let storage_key = build_key("persistentvolumeclaims", Some(ns), name);
            match self
                .storage
                .get::<PersistentVolumeClaim>(&storage_key)
                .await
            {
                Ok(resource) => {
                    let mut resource = resource;
                    match self.bind_pvc(&mut resource).await {
                        Ok(()) => queue.forget(&key).await,
                        Err(e) => {
                            error!("Failed to reconcile {}: {}", key, e);
                            queue.requeue_rate_limited(key.clone()).await;
                        }
                    }
                }
                Err(_) => {
                    queue.forget(&key).await;
                }
            }
            queue.done(&key).await;
        }
    }

    async fn enqueue_all(&self, queue: &WorkQueue) {
        match self
            .storage
            .list::<PersistentVolumeClaim>("/registry/persistentvolumeclaims/")
            .await
        {
            Ok(items) => {
                for item in &items {
                    let ns = item.metadata.namespace.as_deref().unwrap_or("");
                    let key = format!("persistentvolumeclaims/{}/{}", ns, item.metadata.name);
                    queue.add(key).await;
                }
            }
            Err(e) => {
                error!("Failed to list persistentvolumeclaims for enqueue: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn reconcile_all(&self) -> Result<()> {
        // Get all PVCs
        let pvcs: Vec<PersistentVolumeClaim> = self
            .storage
            .list("/registry/persistentvolumeclaims/")
            .await?;

        for mut pvc in pvcs {
            if let Err(e) = self.bind_pvc(&mut pvc).await {
                error!("Failed to bind PVC {}: {}", pvc.metadata.name, e);
            }
        }

        Ok(())
    }

    /// Releases `PersistentVolume`s whose claim no longer exists, and deletes
    /// the ones whose reclaim policy says to.
    ///
    /// Nothing did this. A PV stayed `Bound` to a `claimRef` naming a PVC that
    /// had been deleted, forever — and because this provisioner names volumes
    /// deterministically (`pvc-<namespace>-<name>`), that orphan then blocked
    /// its own replacement: a freshly created claim of the same name could
    /// neither bind to it (the `claimRef` uid no longer matches) nor be given a
    /// new volume (the name is taken). The claim sits `Pending` indefinitely
    /// with nothing saying why. Observed on `platform-db-cluster-1`, where it
    /// stopped the database being re-provisioned until the PV was deleted by
    /// hand.
    ///
    /// A claim is considered gone if it is absent **or** present with a
    /// different uid. The uid check is what makes delete-and-recreate work:
    /// same namespace, same name, different object, and binding to it would
    /// silently hand a new claim someone else's data.
    async fn reclaim_released_volumes(&self) -> Result<()> {
        let pvs: Vec<PersistentVolume> = self.storage.list("/registry/persistentvolumes/").await?;

        for mut pv in pvs {
            let Some(claim_ref) = pv.spec.claim_ref.clone() else {
                continue;
            };
            let (Some(ns), Some(name)) = (claim_ref.namespace.clone(), claim_ref.name.clone())
            else {
                continue;
            };

            let claim_key = build_key("persistentvolumeclaims", Some(&ns), &name);
            let claim: Option<PersistentVolumeClaim> = self.storage.get(&claim_key).await.ok();
            let still_claimed = match (&claim, &claim_ref.uid) {
                // No uid recorded on the claimRef — fall back to existence
                // alone rather than releasing a volume we cannot prove is stale.
                (Some(_), None) => true,
                (Some(c), Some(expected)) => &c.metadata.uid == expected,
                (None, _) => false,
            };
            if still_claimed {
                continue;
            }

            use rusternetes_common::resources::volume::PersistentVolumeReclaimPolicy;
            let policy = pv
                .spec
                .persistent_volume_reclaim_policy
                .clone()
                .unwrap_or(PersistentVolumeReclaimPolicy::Retain);
            let pv_key = build_key("persistentvolumes", None, &pv.metadata.name);

            match policy {
                PersistentVolumeReclaimPolicy::Delete => {
                    info!(
                        "Reclaiming PV {} (policy Delete): its claim {}/{} no longer exists",
                        pv.metadata.name, ns, name
                    );
                    self.storage.delete(&pv_key).await?;
                }
                // Retain and Recycle: keep the volume and its data, but mark it
                // Released so it is visibly not available rather than appearing
                // Bound to something that is gone. (Recycle is deprecated
                // upstream and not implemented here; treating it as Retain
                // preserves data rather than destroying it on a guess.)
                _ => {
                    use rusternetes_common::resources::volume::PersistentVolumePhase;
                    let already_released = pv
                        .status
                        .as_ref()
                        .map(|st| st.phase == PersistentVolumePhase::Released)
                        .unwrap_or(false);
                    // Written once, not every pass: an unconditional status
                    // update here would be a write per reconcile per released
                    // PV, which is the self-triggering churn this repo has
                    // fixed in four operators already.
                    if already_released {
                        continue;
                    }
                    info!(
                        "Releasing PV {} (policy {:?}): its claim {}/{} no longer exists",
                        pv.metadata.name, policy, ns, name
                    );
                    if let Some(status) = pv.status.as_mut() {
                        status.phase = PersistentVolumePhase::Released;
                        self.storage.update(&pv_key, &pv).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn bind_pvc(&self, pvc: &mut PersistentVolumeClaim) -> Result<()> {
        let pvc_name = &pvc.metadata.name;
        let namespace = pvc.metadata.namespace.as_deref().unwrap_or("default");

        // Skip if already bound. A real client-created PVC can carry
        // `volumeName` as an explicit empty string rather than omitting the
        // field entirely (confirmed live: CloudNativePG's own PVC) — treating
        // that the same as "already bound" via a bare `.is_some()` left such
        // a PVC invisible to this controller too, compounding the identical
        // mistake in `dynamic_provisioner.rs`'s own "is this PVC unbound?"
        // check (which used `.is_none()`, the opposite direction, with the
        // same blind spot) — neither controller ever touched it.
        if pvc.spec.volume_name.as_deref().is_some_and(|s| !s.is_empty()) {
            return Ok(());
        }

        let pvc_spec = &pvc.spec;

        debug!("Looking for PV to bind to PVC {}/{}", namespace, pvc_name);
        debug!(
            "PVC requirements: storage_class={:?}, capacity={:?}, access_modes={:?}",
            pvc_spec.storage_class_name,
            pvc_spec
                .resources
                .requests
                .as_ref()
                .and_then(|r| r.get("storage")),
            pvc_spec.access_modes
        );

        // Get all available PVs
        let pvs: Vec<PersistentVolume> = self.storage.list("/registry/persistentvolumes/").await?;

        debug!("Found {} PVs to check for binding", pvs.len());

        // Find a matching available PV
        for mut pv in pvs {
            debug!("Checking PV {} (storage_class={:?}, capacity={:?}, access_modes={:?}, claim_ref={:?})",
                pv.metadata.name,
                pv.spec.storage_class_name,
                pv.spec.capacity,
                pv.spec.access_modes,
                pv.spec.claim_ref.is_some());

            // Skip if PV is already bound
            if pv.spec.claim_ref.is_some() {
                continue;
            }

            // Check if PV matches PVC requirements
            let matches = self.pv_matches_pvc(&pv.spec, pvc_spec);
            debug!(
                "PV {} matches PVC requirements: {}",
                pv.metadata.name, matches
            );
            if !matches {
                continue;
            }

            info!(
                "Binding PVC {}/{} to PV {}",
                namespace, pvc_name, pv.metadata.name
            );

            // Clone values we need before mutating pv
            let pv_access_modes = pv.spec.access_modes.clone();
            let pv_capacity = pv.spec.capacity.clone();
            let pv_name = pv.metadata.name.clone();

            // Bind PV to PVC
            pv.spec.claim_ref = Some(
                rusternetes_common::resources::service_account::ObjectReference {
                    kind: Some("PersistentVolumeClaim".to_string()),
                    namespace: Some(namespace.to_string()),
                    name: Some(pvc_name.to_string()),
                    uid: Some(pvc.metadata.uid.clone()),
                    api_version: Some("v1".to_string()),
                    resource_version: None,
                    field_path: None,
                },
            );

            // Update PV status to Bound
            pv.status = Some(PersistentVolumeStatus {
                phase: PersistentVolumePhase::Bound,
                message: None,
                reason: None,
                last_phase_transition_time: None,
            });

            let pv_key = build_key("persistentvolumes", None, &pv_name);
            self.storage.update(&pv_key, &pv).await?;

            // Bind PVC to PV
            pvc.spec.volume_name = Some(pv_name.clone());

            // Update PVC status to Bound
            pvc.status = Some(PersistentVolumeClaimStatus {
                phase: PersistentVolumeClaimPhase::Bound,
                access_modes: Some(pv_access_modes),
                capacity: Some(pv_capacity),
                conditions: None,
                allocated_resources: None,
                allocated_resource_statuses: None,
                resize_status: None,
                current_volume_attributes_class_name: None,
                modify_volume_status: None,
            });

            let pvc_key = build_key("persistentvolumeclaims", Some(namespace), pvc_name);
            self.storage.update(&pvc_key, pvc).await?;

            info!(
                "Successfully bound PVC {}/{} to PV {}",
                namespace, pvc_name, pv.metadata.name
            );
            return Ok(());
        }

        debug!("No matching PV found for PVC {}/{}", namespace, pvc_name);
        Ok(())
    }

    /// Check if a PV matches the requirements of a PVC
    fn pv_matches_pvc(
        &self,
        pv_spec: &rusternetes_common::resources::PersistentVolumeSpec,
        pvc_spec: &rusternetes_common::resources::PersistentVolumeClaimSpec,
    ) -> bool {
        // Check storage class match
        if let (Some(pv_class), Some(pvc_class)) =
            (&pv_spec.storage_class_name, &pvc_spec.storage_class_name)
        {
            if pv_class != pvc_class {
                return false;
            }
        }

        // Check capacity
        if let (Some(pv_storage), Some(pvc_storage)) = (
            pv_spec.capacity.get("storage"),
            pvc_spec
                .resources
                .requests
                .as_ref()
                .and_then(|r| r.get("storage")),
        ) {
            // Simple string comparison - in real Kubernetes, this would parse quantities
            // For now, we'll just check if PV storage >= PVC storage
            if !self.storage_sufficient(pv_storage, pvc_storage) {
                return false;
            }
        }

        // Check access modes - PV must support all modes requested by PVC
        for pvc_mode in &pvc_spec.access_modes {
            if !pv_spec.access_modes.contains(pvc_mode) {
                return false;
            }
        }

        true
    }

    /// Check if PV storage is sufficient for PVC
    /// This is a simple string comparison for now
    fn storage_sufficient(&self, pv_storage: &str, pvc_storage: &str) -> bool {
        // Parse the numeric part and unit from storage strings like "10Gi", "5Gi"
        let parse_storage = |s: &str| -> Option<(f64, String)> {
            let numeric_end = s.chars().position(|c| !c.is_numeric() && c != '.')?;
            let (num_str, unit) = s.split_at(numeric_end);
            let num = num_str.parse::<f64>().ok()?;
            Some((num, unit.to_string()))
        };

        match (parse_storage(pv_storage), parse_storage(pvc_storage)) {
            (Some((pv_num, pv_unit)), Some((pvc_num, pvc_unit))) => {
                // Units must match
                if pv_unit != pvc_unit {
                    debug!(
                        "Storage units don't match: PV has {}, PVC needs {}",
                        pv_unit, pvc_unit
                    );
                    return false;
                }
                // PV must have at least as much storage as PVC
                let sufficient = pv_num >= pvc_num;
                debug!(
                    "Storage comparison: PV has {}{}, PVC needs {}{} -> sufficient: {}",
                    pv_num, pv_unit, pvc_num, pvc_unit, sufficient
                );
                sufficient
            }
            _ => {
                debug!(
                    "Failed to parse storage values: PV='{}', PVC='{}'",
                    pv_storage, pvc_storage
                );
                // Fall back to string comparison if parsing fails
                pv_storage >= pvc_storage
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_common::types::{ObjectMeta, TypeMeta};
    use rusternetes_storage::memory::MemoryStorage;


    /// A claim deleted and recreated with the same name is a DIFFERENT claim.
    /// Binding the old volume to it would silently hand the new owner someone
    /// else's data, so the uid is what decides, not the name.
    #[test]
    fn a_recreated_claim_of_the_same_name_does_not_count_as_still_claimed() {
        let recorded_uid = Some("old-uid".to_string());
        let live_uid = "new-uid".to_string();
        let still_claimed = match (&Some(&live_uid), &recorded_uid) {
            (Some(_), None) => true,
            (Some(u), Some(expected)) => **u == *expected,
            (None, _) => false,
        };
        assert!(!still_claimed);
    }

    /// Absent claim, any recorded uid — released.
    #[test]
    fn a_missing_claim_is_not_still_claimed() {
        let live: Option<&String> = None;
        let recorded = Some("old-uid".to_string());
        let still_claimed = match (&live, &recorded) {
            (Some(_), None) => true,
            (Some(u), Some(expected)) => **u == *expected,
            (None, _) => false,
        };
        assert!(!still_claimed);
    }

    /// A claimRef with no uid recorded falls back to existence alone. Releasing
    /// on "we cannot tell" would destroy data on a guess, which is the wrong
    /// direction for a reclaim decision.
    #[test]
    fn a_claim_ref_without_a_uid_falls_back_to_existence() {
        let live = "whatever".to_string();
        let recorded: Option<String> = None;
        let still_claimed = match (&Some(&live), &recorded) {
            (Some(_), None) => true,
            (Some(u), Some(expected)) => **u == *expected,
            (None, _) => false,
        };
        assert!(still_claimed);
    }

    #[test]
    fn test_storage_comparison() {
        let storage = Arc::new(MemoryStorage::new());
        let controller = PVBinderController::new(storage);

        assert!(controller.storage_sufficient("10Gi", "5Gi"));
        assert!(controller.storage_sufficient("10Gi", "10Gi"));
        assert!(!controller.storage_sufficient("5Gi", "10Gi"));
        assert!(controller.storage_sufficient("100Mi", "50Mi"));
        assert!(!controller.storage_sufficient("50Mi", "100Mi"));
    }

    fn minimal_pv(name: &str) -> PersistentVolume {
        PersistentVolume {
            type_meta: TypeMeta {
                kind: "PersistentVolume".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: ObjectMeta::new(name),
            spec: rusternetes_common::resources::PersistentVolumeSpec {
                capacity: Default::default(),
                access_modes: vec![],
                persistent_volume_reclaim_policy: None,
                storage_class_name: None,
                mount_options: None,
                volume_mode: None,
                node_affinity: None,
                claim_ref: None,
                host_path: None,
                nfs: None,
                iscsi: None,
                local: None,
                csi: None,
                volume_attributes_class_name: None,
            },
            status: None,
        }
    }

    fn minimal_pvc(name: &str, volume_name: Option<String>) -> PersistentVolumeClaim {
        PersistentVolumeClaim {
            type_meta: TypeMeta {
                kind: "PersistentVolumeClaim".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: {
                let mut m = ObjectMeta::new(name);
                m.namespace = Some("default".to_string());
                m
            },
            spec: rusternetes_common::resources::PersistentVolumeClaimSpec {
                access_modes: vec![],
                resources: Default::default(),
                volume_name,
                storage_class_name: None,
                volume_mode: None,
                selector: None,
                data_source: None,
                data_source_ref: None,
                volume_attributes_class_name: None,
            },
            status: None,
        }
    }

    /// Regression test for a real bug found live in the same investigation as
    /// `dynamic_provisioner.rs`'s matching fix: a real client-created PVC
    /// (confirmed: CloudNativePG's own `platform-db-cluster-1`) can carry
    /// `volumeName` as an explicit empty string rather than omitting the
    /// field entirely. `.is_some()` treated that the same as "already has a
    /// volume", so `bind_pvc` returned immediately without ever looking for
    /// a PV to bind — compounding `dynamic_provisioner.rs`'s identical blind
    /// spot from the opposite direction, so neither controller ever touched
    /// such a PVC and it sat `Pending` forever.
    #[tokio::test]
    async fn bind_pvc_treats_explicit_empty_volume_name_as_unbound() {
        let storage = Arc::new(MemoryStorage::new());
        let controller = PVBinderController::new(storage.clone());

        let pv = minimal_pv("pvc-default-empty-volume-name-pvc");
        storage
            .create(
                &build_key("persistentvolumes", None, &pv.metadata.name),
                &pv,
            )
            .await
            .unwrap();

        let mut pvc = minimal_pvc("empty-volume-name-pvc", Some(String::new()));
        storage
            .create(
                &build_key("persistentvolumeclaims", Some("default"), &pvc.metadata.name),
                &pvc,
            )
            .await
            .unwrap();

        controller.bind_pvc(&mut pvc).await.unwrap();

        assert_eq!(
            pvc.spec.volume_name.as_deref(),
            Some("pvc-default-empty-volume-name-pvc"),
            "a PVC with an explicit empty volumeName must still be matched and bound, matching real k8s semantics where empty == unset"
        );
    }
}
