use anyhow::{Context, Result};
use rusternetes_common::resources::volume::{
    HostPathType, HostPathVolumeSource, PersistentVolumePhase, PersistentVolumeReclaimPolicy,
};
use rusternetes_common::resources::{EventType, ObjectReference};
use rusternetes_common::resources::{
    PersistentVolume, PersistentVolumeClaim, PersistentVolumeStatus, StorageClass, VolumeSnapshot,
    VolumeSnapshotContent,
};
use rusternetes_common::types::{ObjectMeta, TypeMeta};
use rusternetes_storage::{build_key, extract_key, Storage, WorkQueue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info, warn};

pub struct DynamicProvisionerController<S: Storage> {
    storage: Arc<S>,
}

impl<S: Storage + 'static> DynamicProvisionerController<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        use futures::StreamExt;

        info!("Starting Dynamic Provisioner Controller");

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
                                warn!("Watch error: {}, reconnecting", e);
                                watch_broken = true;
                            }
                            None => {
                                warn!("Watch stream ended, reconnecting");
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
                Ok(pvc) => {
                    // Only process unbound PVCs — `provision_volume`
                    // resolves which StorageClass to use, explicit or the
                    // cluster's default. This is the actual, live
                    // reconcile path (unlike `reconcile_all` below, which
                    // is `#[allow(dead_code)]` — genuinely unused, not a
                    // reference implementation): the same
                    // `storage_class_name.is_some()` bug this fixes was
                    // live here too, and fixing only the dead-code copy
                    // first (an easy mistake to make — they read
                    // identically) would have changed nothing real.
                    // A real client-created PVC (confirmed live: CloudNativePG's
                    // own `platform-db-cluster-1` PVC) can carry `volumeName` as
                    // an explicit empty string rather than omitting the field —
                    // the same wire-level convention already confirmed for
                    // `schedulerName` in the scheduler. `.is_none()` alone left
                    // such a PVC looking "already bound" forever, so
                    // `provision_volume` was never even called — and the
                    // inverse check in `pv_binder.rs` independently treated the
                    // same empty string as "already has a volume", so neither
                    // controller ever touched it from either direction.
                    let already_bound = pvc
                        .spec
                        .volume_name
                        .as_deref()
                        .is_some_and(|s| !s.is_empty());
                    if !already_bound {
                        match self.provision_volume(&pvc).await {
                            Ok(()) => queue.forget(&key).await,
                            Err(e) => {
                                error!("Failed to provision volume for {}: {}", key, e);
                                queue.requeue_rate_limited(key.clone()).await;
                            }
                        }
                    } else {
                        queue.forget(&key).await;
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

        for pvc in pvcs {
            // Only process unbound PVCs — `provision_volume` itself
            // resolves which StorageClass to use, explicit or the
            // cluster's default (see its own doc comment for the real
            // bug this used to be: a PVC that omits `storageClassName`
            // entirely, real, standard Kubernetes behavior for "use
            // whatever the cluster's default StorageClass is", used to
            // be silently skipped right here, before ever reaching that
            // resolution logic). An explicit empty-string `volumeName`
            // (confirmed live) must also count as unbound — see the
            // matching fix and comment in `worker()`, the actual live path.
            let already_bound = pvc
                .spec
                .volume_name
                .as_deref()
                .is_some_and(|s| !s.is_empty());
            if !already_bound {
                if let Err(e) = self.provision_volume(&pvc).await {
                    error!(
                        "Failed to provision volume for PVC {}/{}: {}",
                        pvc.metadata.namespace.as_deref().unwrap_or("default"),
                        pvc.metadata.name,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    /// Real, live-confirmed bug this fixes: a `PersistentVolumeClaim` that
    /// omits `storageClassName` entirely — standard, common Kubernetes
    /// usage, meaning "use the cluster's default `StorageClass`" (the one
    /// annotated `storageclass.kubernetes.io/is-default-class: "true"`) —
    /// used to be silently skipped by the caller (`reconcile_all` required
    /// `storage_class_name.is_some()` before even calling this function),
    /// with no log line and no error anywhere. A real chart (Bitnami's
    /// Valkey) hit this exactly: its `volumeClaimTemplate` doesn't set an
    /// explicit `storageClassName`, so no `PersistentVolume` was ever
    /// provisioned, and the pod failed at startup with `dir /data: No
    /// such file or directory` — a symptom that gave no hint the real
    /// cause was upstream in provisioning, not the pod's own config.
    async fn provision_volume(&self, pvc: &PersistentVolumeClaim) -> Result<()> {
        let pvc_name = &pvc.metadata.name;
        let namespace = pvc.metadata.namespace.as_deref().unwrap_or("default");

        let storage_class_name = match &pvc.spec.storage_class_name {
            Some(name) => name.clone(),
            None => match self.default_storage_class_name().await? {
                Some(name) => name,
                None => {
                    debug!(
                        "PVC {}/{} has no storageClassName and no default StorageClass exists — \
                         cannot dynamically provision",
                        namespace, pvc_name
                    );
                    self.report_blocked(
                        pvc,
                        "ProvisioningFailed",
                        "no storageClassName is set on this claim and no StorageClass is \
                         annotated storageclass.kubernetes.io/is-default-class=true, so no \
                         volume can be provisioned for it",
                    )
                    .await;
                    return Ok(());
                }
            },
        };
        let storage_class_name = &storage_class_name;

        debug!(
            "Attempting to dynamically provision volume for PVC {}/{} using StorageClass {}",
            namespace, pvc_name, storage_class_name
        );

        // Get the StorageClass
        let sc_key = build_key("storageclasses", None, storage_class_name);
        let storage_class: StorageClass = self
            .storage
            .get(&sc_key)
            .await
            .with_context(|| format!("StorageClass {} not found", storage_class_name))?;

        debug!(
            "Found StorageClass {} with provisioner {}",
            storage_class_name, storage_class.provisioner
        );

        // Check if provisioner is supported
        if !self.is_provisioner_supported(&storage_class.provisioner) {
            warn!(
                "Provisioner {} is not supported. Skipping PVC {}/{}",
                storage_class.provisioner, namespace, pvc_name
            );
            self.report_blocked(
                pvc,
                "ProvisioningFailed",
                &format!(
                    "StorageClass {} uses provisioner {}, which this cluster does not implement",
                    storage_class_name, storage_class.provisioner
                ),
            )
            .await;
            return Ok(());
        }

        // Check if a PV already exists for this PVC (in case we're retrying)
        let pv_name = format!("pvc-{}-{}", namespace, pvc_name);
        let pv_key = build_key("persistentvolumes", None, &pv_name);

        if let Ok(existing_pv) = self.storage.get::<PersistentVolume>(&pv_key).await {
            // Existing and *ours* is the ordinary retry case. Existing and
            // claimed by someone else is the one from ISSUES.md #70: PV names
            // are derived from the claim, so a leftover volume under this name
            // makes the claim unprovisionable — and until now said nothing at
            // all, leaving a `Pending` PVC with no explanation anywhere.
            let held_by_another = existing_pv.spec.claim_ref.as_ref().filter(|claim_ref| {
                claim_ref
                    .uid
                    .as_deref()
                    .is_none_or(|uid| uid != pvc.metadata.uid)
            });
            if let Some(claim_ref) = held_by_another {
                self.report_blocked(
                    pvc,
                    "ProvisioningFailed",
                    &format!(
                        "PersistentVolume {} already exists and is claimed by {}/{} (uid {}). \
                         Volume names are derived from the claim, so this claim cannot be \
                         provisioned while that volume exists.",
                        pv_name,
                        claim_ref.namespace.as_deref().unwrap_or("<none>"),
                        claim_ref.name.as_deref().unwrap_or("<none>"),
                        claim_ref.uid.as_deref().unwrap_or("<unset>"),
                    ),
                )
                .await;
            } else {
                debug!(
                    "PV {} already exists for PVC {}/{}",
                    pv_name, namespace, pvc_name
                );
            }
            return Ok(());
        }

        // Create the PV (with snapshot restore if dataSource is specified)
        let pv = self
            .create_pv_for_pvc(&storage_class, pvc, &pv_name)
            .await?;

        // Store the PV
        self.storage
            .create(&pv_key, &pv)
            .await
            .with_context(|| format!("Failed to create PV {}", pv_name))?;

        info!(
            "Successfully provisioned PV {} for PVC {}/{}",
            pv_name, namespace, pvc_name
        );

        Ok(())
    }

    /// Say, on the claim itself, why it is not getting a volume.
    ///
    /// Every early return in `provision_volume` used to be a `debug!` or a
    /// `warn!` in the controller's log — which is the wrong audience. The
    /// person waiting is looking at `kubectl describe pvc`, and a `Pending`
    /// claim with an empty Events section tells them nothing about whether
    /// anything is even trying (ISSUES.md #70).
    async fn report_blocked(&self, pvc: &PersistentVolumeClaim, reason: &str, message: &str) {
        let namespace = pvc.metadata.namespace.as_deref().unwrap_or("default");
        super::events::record_event_once(
            self.storage.as_ref(),
            namespace,
            ObjectReference {
                kind: Some("PersistentVolumeClaim".to_string()),
                namespace: Some(namespace.to_string()),
                name: Some(pvc.metadata.name.clone()),
                uid: Some(pvc.metadata.uid.clone()),
                api_version: Some("v1".to_string()),
                resource_version: None,
                field_path: None,
            },
            reason,
            message,
            EventType::Warning,
            "persistentvolume-controller",
        )
        .await;
    }

    /// The name of the `StorageClass` annotated
    /// `storageclass.kubernetes.io/is-default-class: "true"`, if any —
    /// matches real Kubernetes' own convention for what "no
    /// storageClassName on the PVC" resolves to. If more than one
    /// `StorageClass` carries the annotation (a cluster misconfiguration
    /// in real Kubernetes too — admission control there rejects a second
    /// `true` value, which this reimplementation doesn't enforce), the
    /// first one found wins; deterministic-enough for this to still be
    /// useful, not a silent correctness trap for the common case.
    async fn default_storage_class_name(&self) -> Result<Option<String>> {
        let classes: Vec<StorageClass> = self.storage.list("/registry/storageclasses/").await?;
        Ok(classes
            .into_iter()
            .find(|sc| {
                sc.metadata
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("storageclass.kubernetes.io/is-default-class"))
                    .map(|v| v == "true")
                    .unwrap_or(false)
            })
            .map(|sc| sc.metadata.name))
    }

    fn is_provisioner_supported(&self, provisioner: &str) -> bool {
        matches!(
            provisioner,
            "rusternetes.io/hostpath" | "kubernetes.io/hostpath" | "hostpath"
        )
    }

    async fn create_pv_for_pvc(
        &self,
        storage_class: &StorageClass,
        pvc: &PersistentVolumeClaim,
        pv_name: &str,
    ) -> Result<PersistentVolume> {
        let namespace = pvc.metadata.namespace.as_deref().unwrap_or("default");

        // Get requested storage capacity
        let requested_storage = pvc
            .spec
            .resources
            .requests
            .as_ref()
            .and_then(|r| r.get("storage"))
            .context("PVC has no storage request")?;

        let mut capacity = HashMap::new();
        capacity.insert("storage".to_string(), requested_storage.clone());

        // Determine the path for the volume
        let base_path = storage_class
            .parameters
            .as_ref()
            .and_then(|p| p.get("path"))
            .map(|s| s.as_str())
            .unwrap_or("/tmp/rusternetes/dynamic-pvs");

        let volume_path = format!("{}/{}", base_path, pv_name);

        // Check if this PVC is being restored from a snapshot
        let snapshot_source_path = if let Some(data_source) = &pvc.spec.data_source {
            self.handle_snapshot_restore(data_source, namespace, &volume_path)
                .await?
        } else {
            None
        };

        let message = if snapshot_source_path.is_some() {
            Some("Dynamically provisioned from snapshot".to_string())
        } else {
            Some("Dynamically provisioned".to_string())
        };

        info!(
            "Creating PV {} with path {} and capacity {}{}",
            pv_name,
            volume_path,
            requested_storage,
            if snapshot_source_path.is_some() {
                " (restored from snapshot)"
            } else {
                ""
            }
        );

        // Validate provisioner type
        if !matches!(
            storage_class.provisioner.as_str(),
            "rusternetes.io/hostpath" | "kubernetes.io/hostpath" | "hostpath"
        ) {
            return Err(anyhow::anyhow!(
                "Unsupported provisioner: {}",
                storage_class.provisioner
            ));
        }
        let host_path_source = Some(HostPathVolumeSource {
            path: volume_path,
            r#type: Some(HostPathType::DirectoryOrCreate),
        });

        // Determine reclaim policy (default to Delete for dynamically provisioned volumes)
        let reclaim_policy = storage_class
            .reclaim_policy
            .clone()
            .unwrap_or(PersistentVolumeReclaimPolicy::Delete);

        // Create labels to track the PVC this was created for
        let mut labels = HashMap::new();
        labels.insert("pvc-name".to_string(), pvc.metadata.name.clone());
        labels.insert("pvc-namespace".to_string(), namespace.to_string());
        labels.insert("provisioner".to_string(), storage_class.provisioner.clone());
        labels.insert(
            "storage-class".to_string(),
            storage_class.metadata.name.clone(),
        );

        let pv = PersistentVolume {
            type_meta: TypeMeta {
                kind: "PersistentVolume".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: {
                let mut meta = ObjectMeta::new(pv_name);
                meta.uid = uuid::Uuid::new_v4().to_string();
                meta.resource_version = Some("1".to_string());
                meta.labels = Some(labels);
                meta.annotations = Some({
                    let mut annotations = HashMap::new();
                    annotations.insert(
                        "pv.kubernetes.io/provisioned-by".to_string(),
                        storage_class.provisioner.clone(),
                    );
                    annotations
                });
                meta
            },
            spec: rusternetes_common::resources::PersistentVolumeSpec {
                capacity,
                host_path: host_path_source,
                nfs: None,
                iscsi: None,
                local: None,
                csi: None,
                access_modes: pvc.spec.access_modes.clone(),
                persistent_volume_reclaim_policy: Some(reclaim_policy),
                storage_class_name: Some(storage_class.metadata.name.clone()),
                mount_options: None,
                volume_mode: pvc.spec.volume_mode.clone(),
                node_affinity: None,
                claim_ref: None, // Will be bound by the PV binder controller
                volume_attributes_class_name: None,
            },
            status: Some(PersistentVolumeStatus {
                phase: PersistentVolumePhase::Available,
                message,
                reason: None,
                last_phase_transition_time: None,
            }),
        };

        Ok(pv)
    }

    /// Handle snapshot restore by validating the snapshot and returning the source path
    async fn handle_snapshot_restore(
        &self,
        data_source: &rusternetes_common::resources::volume::TypedLocalObjectReference,
        namespace: &str,
        target_path: &str,
    ) -> Result<Option<String>> {
        // Check if data source is a VolumeSnapshot
        if data_source.kind != "VolumeSnapshot" {
            warn!(
                "Unsupported dataSource kind: {}. Only VolumeSnapshot is supported for restore.",
                data_source.kind
            );
            return Ok(None);
        }

        let snapshot_name = &data_source.name;
        info!(
            "PVC is requesting restore from VolumeSnapshot {}/{}",
            namespace, snapshot_name
        );

        // Get the VolumeSnapshot
        let snapshot_key = build_key("volumesnapshots", Some(namespace), snapshot_name);
        let snapshot: VolumeSnapshot =
            self.storage.get(&snapshot_key).await.with_context(|| {
                format!("VolumeSnapshot {}/{} not found", namespace, snapshot_name)
            })?;

        // Ensure snapshot is ready to use
        let ready = snapshot
            .status
            .as_ref()
            .and_then(|s| s.ready_to_use)
            .unwrap_or(false);

        if !ready {
            return Err(anyhow::anyhow!(
                "VolumeSnapshot {}/{} is not ready to use",
                namespace,
                snapshot_name
            ));
        }

        // Get the bound VolumeSnapshotContent
        let content_name = snapshot
            .status
            .as_ref()
            .and_then(|s| s.bound_volume_snapshot_content_name.as_ref())
            .context("VolumeSnapshot has no bound VolumeSnapshotContent")?;

        let content_key = build_key("volumesnapshotcontents", None, content_name);
        let content: VolumeSnapshotContent = self
            .storage
            .get(&content_key)
            .await
            .with_context(|| format!("VolumeSnapshotContent {} not found", content_name))?;

        // Get the snapshot handle (this would be the path to the snapshot data)
        let snapshot_handle = content
            .status
            .as_ref()
            .and_then(|s| s.snapshot_handle.as_ref())
            .context("VolumeSnapshotContent has no snapshot handle")?;

        info!(
            "Restoring from snapshot {} (handle: {}) to {}",
            content_name, snapshot_handle, target_path
        );

        // In a real implementation, this would:
        // 1. Copy data from the snapshot location to the new volume location
        // 2. For hostpath volumes, this could be a directory copy
        // 3. For CSI volumes, this would invoke the CSI driver's CreateVolumeFromSnapshot

        // For now, we'll just log the operation and mark it as successful
        // The actual data copy would be handled by the CSI driver or volume plugin
        info!(
            "Snapshot restore simulated: {} -> {}. In production, this would copy snapshot data.",
            snapshot_handle, target_path
        );

        Ok(Some(snapshot_handle.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_common::resources::volume::{
        PersistentVolumeAccessMode, PersistentVolumeClaimPhase, PersistentVolumeClaimStatus,
        PersistentVolumeMode, ResourceRequirements,
    };
    use rusternetes_storage::memory::MemoryStorage;

    #[test]
    fn test_is_provisioner_supported() {
        let storage = Arc::new(MemoryStorage::new());
        let controller = DynamicProvisionerController::new(storage);

        assert!(controller.is_provisioner_supported("rusternetes.io/hostpath"));
        assert!(controller.is_provisioner_supported("kubernetes.io/hostpath"));
        assert!(controller.is_provisioner_supported("hostpath"));
        assert!(!controller.is_provisioner_supported("kubernetes.io/aws-ebs"));
    }

    fn storage_class(name: &str, is_default: bool) -> StorageClass {
        let mut metadata = ObjectMeta::new(name);
        if is_default {
            let mut annotations = HashMap::new();
            annotations.insert(
                "storageclass.kubernetes.io/is-default-class".to_string(),
                "true".to_string(),
            );
            metadata.annotations = Some(annotations);
        }
        StorageClass {
            type_meta: TypeMeta {
                kind: "StorageClass".to_string(),
                api_version: "storage.k8s.io/v1".to_string(),
            },
            metadata,
            provisioner: "rusternetes.io/hostpath".to_string(),
            parameters: None,
            reclaim_policy: Some(PersistentVolumeReclaimPolicy::Delete),
            volume_binding_mode: None,
            allowed_topologies: None,
            allow_volume_expansion: None,
            mount_options: None,
        }
    }

    fn pvc_without_storage_class(name: &str) -> PersistentVolumeClaim {
        let mut requests = HashMap::new();
        requests.insert("storage".to_string(), "5Gi".to_string());
        PersistentVolumeClaim {
            type_meta: TypeMeta {
                kind: "PersistentVolumeClaim".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: {
                let mut meta = ObjectMeta::new(name);
                meta.namespace = Some("default".to_string());
                meta
            },
            spec: rusternetes_common::resources::PersistentVolumeClaimSpec {
                access_modes: vec![PersistentVolumeAccessMode::ReadWriteOnce],
                resources: ResourceRequirements {
                    limits: None,
                    requests: Some(requests),
                },
                volume_name: None,
                storage_class_name: None,
                volume_mode: Some(PersistentVolumeMode::Filesystem),
                selector: None,
                data_source: None,
                data_source_ref: None,
                volume_attributes_class_name: None,
            },
            status: Some(PersistentVolumeClaimStatus {
                phase: PersistentVolumeClaimPhase::Pending,
                access_modes: None,
                capacity: None,
                conditions: None,
                allocated_resources: None,
                allocated_resource_statuses: None,
                resize_status: None,
                current_volume_attributes_class_name: None,
                modify_volume_status: None,
            }),
        }
    }

    /// Real, live-confirmed bug: a PVC with no `storageClassName` (common,
    /// standard Kubernetes usage — meaning "use the cluster's default
    /// StorageClass") used to be silently skipped by `reconcile_all`
    /// before this fix, provisioning nothing, no error, no log — found
    /// live when Bitnami's real Valkey chart (whose `volumeClaimTemplate`
    /// doesn't set an explicit class) hit exactly this, and its pod
    /// failed with a confusing, unrelated-looking `dir /data: No such
    /// file or directory`.
    #[tokio::test]
    async fn provision_volume_falls_back_to_the_default_storage_class() {
        let storage = Arc::new(MemoryStorage::new());
        let sc_key = build_key("storageclasses", None, "standard");
        storage
            .create(&sc_key, &storage_class("standard", true))
            .await
            .unwrap();

        let controller = DynamicProvisionerController::new(storage.clone());
        let pvc = pvc_without_storage_class("no-class-pvc");

        controller.provision_volume(&pvc).await.unwrap();

        let pv_key = build_key("persistentvolumes", None, "pvc-default-no-class-pvc");
        let pv: PersistentVolume = storage
            .get(&pv_key)
            .await
            .expect("PV should be provisioned");
        assert_eq!(pv.spec.storage_class_name, Some("standard".to_string()));
    }

    /// Every event this controller records, for one claim.
    async fn events_for(
        storage: &rusternetes_storage::memory::MemoryStorage,
        pvc: &str,
    ) -> Vec<rusternetes_common::resources::Event> {
        let all: Vec<rusternetes_common::resources::Event> =
            storage.list("/registry/events/").await.unwrap();
        all.into_iter()
            .filter(|e| e.involved_object.name.as_deref() == Some(pvc))
            .collect()
    }

    /// ISSUES.md #70, second half. PV names are derived from the claim, so a
    /// leftover volume under that name makes the claim unprovisionable — and
    /// said nothing at all, which is how it cost an hour. The event has to name
    /// the volume and who holds it, or the operator is no better off.
    #[tokio::test]
    async fn a_volume_name_held_by_another_claim_is_reported_on_the_claim() {
        let storage = Arc::new(MemoryStorage::new());
        storage
            .create(
                &build_key("storageclasses", None, "standard"),
                &storage_class("standard", true),
            )
            .await
            .unwrap();

        let pvc = pvc_without_storage_class("held-name-pvc");
        let pv_name = "pvc-default-held-name-pvc";

        // A volume already under the deterministic name, claimed by a
        // *different* incarnation of this claim — exactly the state left behind
        // by a delete-and-recreate.
        let controller = DynamicProvisionerController::new(storage.clone());
        let mut orphan = controller
            .create_pv_for_pvc(&storage_class("standard", true), &pvc, pv_name)
            .await
            .unwrap();
        orphan.spec.claim_ref = Some(ObjectReference {
            kind: Some("PersistentVolumeClaim".to_string()),
            namespace: Some("default".to_string()),
            name: Some("held-name-pvc".to_string()),
            uid: Some("a-previous-incarnation".to_string()),
            api_version: Some("v1".to_string()),
            resource_version: None,
            field_path: None,
        });
        storage
            .create(&build_key("persistentvolumes", None, pv_name), &orphan)
            .await
            .unwrap();

        controller.provision_volume(&pvc).await.unwrap();

        let events = events_for(&storage, "held-name-pvc").await;
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].reason, "ProvisioningFailed");
        assert_eq!(events[0].event_type, EventType::Warning);
        assert!(events[0].message.contains(pv_name), "{}", events[0].message);
        assert!(
            events[0].message.contains("a-previous-incarnation"),
            "the event must name who holds the volume, not just that it is held: {}",
            events[0].message
        );
    }

    /// The ordinary retry: the volume under this name is *this* claim's. Saying
    /// something here would train the reader to ignore the message that matters.
    #[tokio::test]
    async fn our_own_existing_volume_is_not_reported_as_a_conflict() {
        let storage = Arc::new(MemoryStorage::new());
        storage
            .create(
                &build_key("storageclasses", None, "standard"),
                &storage_class("standard", true),
            )
            .await
            .unwrap();

        let pvc = pvc_without_storage_class("our-own-pvc");
        let controller = DynamicProvisionerController::new(storage.clone());

        // First pass provisions; second pass finds it already there.
        controller.provision_volume(&pvc).await.unwrap();
        controller.provision_volume(&pvc).await.unwrap();

        assert!(
            events_for(&storage, "our-own-pvc").await.is_empty(),
            "an unclaimed volume we provisioned ourselves is not a conflict"
        );
    }

    /// A claim nothing will ever provision must say so. `Pending` with an empty
    /// Events section is the state that gave the operator nothing to go on.
    #[tokio::test]
    async fn a_claim_with_no_storage_class_at_all_says_why() {
        let storage = Arc::new(MemoryStorage::new());
        let controller = DynamicProvisionerController::new(storage.clone());
        let pvc = pvc_without_storage_class("no-class-at-all-pvc");

        controller.provision_volume(&pvc).await.unwrap();

        let events = events_for(&storage, "no-class-at-all-pvc").await;
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].reason, "ProvisioningFailed");
        assert!(
            events[0].message.contains("is-default-class"),
            "the message has to say what would fix it: {}",
            events[0].message
        );
    }

    /// The other half of the same fix: when no `StorageClass` is marked
    /// default at all, a PVC with no `storageClassName` genuinely can't
    /// be provisioned — that's a real "nothing to do here" case, not an
    /// error, and shouldn't panic or fail loudly.
    #[tokio::test]
    async fn provision_volume_is_a_no_op_when_no_default_storage_class_exists() {
        let storage = Arc::new(MemoryStorage::new());
        let controller = DynamicProvisionerController::new(storage.clone());
        let pvc = pvc_without_storage_class("no-class-pvc-2");

        controller.provision_volume(&pvc).await.unwrap();

        let pv_key = build_key("persistentvolumes", None, "pvc-default-no-class-pvc-2");
        assert!(storage.get::<PersistentVolume>(&pv_key).await.is_err());
    }

    /// Regression test for a real bug found live: a real client-created PVC
    /// (confirmed: CloudNativePG's own `platform-db-cluster-1`) can carry
    /// `volumeName` as an explicit empty string rather than omitting the
    /// field entirely. `reconcile_all`'s (and the live `worker()`'s)
    /// `volume_name.is_none()` check treated that as "already bound",
    /// silently never provisioning it — no error, no log, the PVC just sat
    /// `Pending` forever. `pv_binder.rs` independently had the exact same
    /// blind spot from the opposite direction (`.is_some()`), so neither
    /// controller ever touched such a PVC.
    #[tokio::test]
    async fn reconcile_all_treats_explicit_empty_volume_name_as_unbound() {
        let storage = Arc::new(MemoryStorage::new());
        let sc_key = build_key("storageclasses", None, "standard");
        storage
            .create(&sc_key, &storage_class("standard", true))
            .await
            .unwrap();

        let controller = DynamicProvisionerController::new(storage.clone());
        let mut pvc = pvc_without_storage_class("empty-volume-name-pvc");
        pvc.spec.storage_class_name = Some("standard".to_string());
        pvc.spec.volume_name = Some(String::new());
        let pvc_key = build_key(
            "persistentvolumeclaims",
            Some("default"),
            "empty-volume-name-pvc",
        );
        storage.create(&pvc_key, &pvc).await.unwrap();

        controller.reconcile_all().await.unwrap();

        let pv_key = build_key(
            "persistentvolumes",
            None,
            "pvc-default-empty-volume-name-pvc",
        );
        assert!(
            storage.get::<PersistentVolume>(&pv_key).await.is_ok(),
            "a PVC with an explicit empty volumeName must still be provisioned, matching real k8s semantics where empty == unset"
        );
    }

    #[tokio::test]
    async fn test_create_pv_for_pvc() {
        // Use MemoryStorage for testing
        let storage = Arc::new(MemoryStorage::new());
        let controller = DynamicProvisionerController::new(storage);

        let mut requests = HashMap::new();
        requests.insert("storage".to_string(), "5Gi".to_string());

        let pvc = PersistentVolumeClaim {
            type_meta: TypeMeta {
                kind: "PersistentVolumeClaim".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: {
                let mut meta = ObjectMeta::new("test-pvc");
                meta.namespace = Some("default".to_string());
                meta
            },
            spec: rusternetes_common::resources::PersistentVolumeClaimSpec {
                access_modes: vec![PersistentVolumeAccessMode::ReadWriteOnce],
                resources: ResourceRequirements {
                    limits: None,
                    requests: Some(requests),
                },
                volume_name: None,
                storage_class_name: Some("fast".to_string()),
                volume_mode: Some(PersistentVolumeMode::Filesystem),
                selector: None,
                data_source: None,
                data_source_ref: None,
                volume_attributes_class_name: None,
            },
            status: Some(PersistentVolumeClaimStatus {
                phase: PersistentVolumeClaimPhase::Pending,
                access_modes: None,
                capacity: None,
                conditions: None,
                allocated_resources: None,
                allocated_resource_statuses: None,
                resize_status: None,
                current_volume_attributes_class_name: None,
                modify_volume_status: None,
            }),
        };

        let storage_class = StorageClass {
            type_meta: TypeMeta {
                kind: "StorageClass".to_string(),
                api_version: "storage.k8s.io/v1".to_string(),
            },
            metadata: ObjectMeta::new("fast"),
            provisioner: "rusternetes.io/hostpath".to_string(),
            parameters: None,
            reclaim_policy: Some(PersistentVolumeReclaimPolicy::Delete),
            volume_binding_mode: None,
            allowed_topologies: None,
            allow_volume_expansion: None,
            mount_options: None,
        };

        let pv = controller
            .create_pv_for_pvc(&storage_class, &pvc, "pvc-default-test-pvc")
            .await
            .unwrap();

        // Verify PV metadata
        assert_eq!(pv.metadata.name, "pvc-default-test-pvc");
        assert_eq!(pv.spec.storage_class_name, Some("fast".to_string()));
        assert_eq!(pv.spec.capacity.get("storage"), Some(&"5Gi".to_string()));
        assert_eq!(
            pv.spec.persistent_volume_reclaim_policy,
            Some(PersistentVolumeReclaimPolicy::Delete)
        );
        assert_eq!(
            pv.spec.access_modes,
            vec![PersistentVolumeAccessMode::ReadWriteOnce]
        );
        assert_eq!(
            pv.status.as_ref().unwrap().phase,
            PersistentVolumePhase::Available
        );

        // Verify hostpath volume source
        let hp = pv
            .spec
            .host_path
            .as_ref()
            .expect("Expected HostPath volume source");
        assert_eq!(hp.path, "/tmp/rusternetes/dynamic-pvs/pvc-default-test-pvc");
        assert_eq!(hp.r#type, Some(HostPathType::DirectoryOrCreate));

        // Verify labels
        let labels = pv.metadata.labels.as_ref().unwrap();
        assert_eq!(labels.get("pvc-name"), Some(&"test-pvc".to_string()));
        assert_eq!(labels.get("pvc-namespace"), Some(&"default".to_string()));
        assert_eq!(
            labels.get("provisioner"),
            Some(&"rusternetes.io/hostpath".to_string())
        );
        assert_eq!(labels.get("storage-class"), Some(&"fast".to_string()));

        // Verify annotations
        let annotations = pv.metadata.annotations.as_ref().unwrap();
        assert_eq!(
            annotations.get("pv.kubernetes.io/provisioned-by"),
            Some(&"rusternetes.io/hostpath".to_string())
        );
    }
}
