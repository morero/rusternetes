//! Generic Kubernetes protobuf-to-JSON decoder.
//!
//! Kubernetes wraps all protobuf-encoded resources in an `Unknown` envelope:
//!   k8s\0 + proto(Unknown { typeMeta, raw, contentEncoding, contentType })
//!
//! The `raw` field contains the native protobuf encoding of the resource
//! (e.g., apps/v1.Deployment). This module decodes native protobuf into
//! JSON using field number → name mappings extracted from the K8s .proto
//! schema files.
//!
//! The Go API server uses generated .pb.go Unmarshal methods. We achieve
//! the same result by maintaining a registry of proto schemas and using
//! a generic recursive decoder.

use serde_json::{json, Map, Value};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Wire types in protobuf encoding
const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LENGTH_DELIMITED: u8 = 2;
const WIRE_32BIT: u8 = 5;

/// Describes how a protobuf field should be decoded to JSON
#[derive(Debug, Clone)]
pub enum FieldType {
    /// Scalar string field
    String,
    /// Scalar integer field (int32, int64, uint32, uint64)
    Int,
    /// Scalar boolean field
    Bool,
    /// Nested message — value is the message type name for schema lookup
    Message(String),
    /// map<string, string> — encoded as repeated MapEntry messages
    StringMap,
    /// Repeated field — value is the element type
    Repeated(Box<FieldType>),
    /// Bytes field — base64 encode
    Bytes,
    /// IntOrString — K8s special type, try string first then int
    IntOrString,
    /// map<string, Message> — encoded as repeated MapEntry with key=string, value=message
    MessageMap(String),
    /// K8s JSON type — a message with a single `raw` bytes field containing JSON
    JsonRaw,
    /// map<string, resource.Quantity> (e.g. ResourceRequirements limits/requests,
    /// PodSpec.overhead). Each map entry's value is itself a `resource.Quantity`
    /// message (`{ optional string string = 1; }`), which must be unwrapped to
    /// its plain string form ("8Gi", "500m") — matching how real k8s marshals
    /// Quantity to JSON. Not just a `StringMap`: treating the value's raw
    /// message bytes as a plain UTF-8 string (the pre-fix behavior) leaks the
    /// wrapping message's own tag/length bytes into the string, e.g. a PVC's
    /// `storage: 8Gi` request decoding as `"\n\x038Gi"`.
    QuantityMap,
    /// A single `resource.Quantity` field (e.g. `EmptyDirVolumeSource.sizeLimit`),
    /// unwrapped to its plain string form rather than decoded as a generic
    /// nested message (which would produce `{"string":"1Gi"}` instead of the
    /// real k8s JSON shape, a bare `"1Gi"`).
    Quantity,
    /// A nested message whose fields should be merged directly into the
    /// *parent* JSON object, rather than nested under this field's own key —
    /// matching a real k8s Go struct embedded with `json:",inline"`. Real
    /// k8s's `Volume` message, for instance, wraps all its source-type
    /// variants (hostPath, emptyDir, secret, ...) in a nested `VolumeSource`
    /// sub-message at field 2, but the JSON representation flattens those
    /// keys directly onto the `Volume` object (`{"name":"x","emptyDir":{}}`,
    /// never `{"name":"x","volumeSource":{"emptyDir":{}}}`). Before this
    /// variant existed, `Volume`'s schema wrongly treated its OWN field
    /// numbers as if they directly were the source-type fields, which
    /// decoded a real emptyDir volume as a broken, empty `hostPath` object
    /// (missing its required `path`) — found live via a real CNPG-created
    /// Job whose pod template's first volume tripped this exact bug.
    FlattenedMessage(String),
}

/// Schema for a single protobuf message type
#[derive(Debug, Clone)]
pub struct MessageSchema {
    /// Map of field number → (json_field_name, field_type)
    pub fields: HashMap<u32, (String, FieldType)>,
}

/// Registry of all known K8s protobuf message schemas
pub struct ProtoRegistry {
    /// Map of message type name → schema
    schemas: HashMap<String, MessageSchema>,
}

impl Default for ProtoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoRegistry {
    /// Build the registry with all known K8s proto schemas.
    /// Field numbers are from the generated.proto files in k8s.io/api.
    pub fn new() -> Self {
        let mut schemas = HashMap::new();

        // ========== apimachinery types ==========

        schemas.insert("ObjectMeta".into(), Self::object_meta_schema());
        schemas.insert("LabelSelector".into(), Self::label_selector_schema());
        schemas.insert(
            "LabelSelectorRequirement".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("key".into(), FieldType::String)),
                    (2, ("operator".into(), FieldType::String)),
                    (
                        3,
                        (
                            "values".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert("OwnerReference".into(), Self::owner_reference_schema());
        schemas.insert(
            "Time".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("seconds".into(), FieldType::Int)),
                    (2, ("nanos".into(), FieldType::Int)),
                ]),
            },
        );
        // Lease (coordination.k8s.io/v1) — real, live-confirmed bug: with no
        // schema entry here, decode_k8s_resource() returns None for every
        // Lease and every write falls through to the generic CRD-shaped
        // fallback decoder, which blindly applies
        // CustomResourceDefinitionSpec's own field layout (group/names/scope/
        // versions) to Lease's completely different bytes — a coincidental
        // field-number collision, not a real decode. Found live chasing a
        // `guts-shell-bundle` blocker: a client-go leader-election Lease
        // renewal decoded as
        // `{"spec":{"group":"<holder-identity-string>","names":{...},"scope":
        // "<raw protobuf bytes leaking into a string field>","versions":[...]}}`
        // — garbage in every field, confirmed via temporary raw-JSON logging
        // in middleware.rs (since removed). Field numbers verified against
        // the real upstream k8s.io/api/coordination/v1 generated.proto.
        schemas.insert(
            "Lease".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("spec".into(), FieldType::Message("LeaseSpec".into()))),
                ]),
            },
        );
        schemas.insert(
            "LeaseSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("holderIdentity".into(), FieldType::String)),
                    (2, ("leaseDurationSeconds".into(), FieldType::Int)),
                    (
                        3,
                        ("acquireTime".into(), FieldType::Message("Time".into())),
                    ),
                    (4, ("renewTime".into(), FieldType::Message("Time".into()))),
                    (5, ("leaseTransitions".into(), FieldType::Int)),
                    (6, ("strategy".into(), FieldType::String)),
                    (7, ("preferredHolder".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "ManagedFieldsEntry".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("manager".into(), FieldType::String)),
                    (2, ("operation".into(), FieldType::String)),
                    (3, ("apiVersion".into(), FieldType::String)),
                    (4, ("time".into(), FieldType::Message("Time".into()))),
                    (6, ("fieldsType".into(), FieldType::String)),
                    (7, ("fieldsV1".into(), FieldType::Bytes)),
                    (8, ("subresource".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "DeleteOptions".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("gracePeriodSeconds".into(), FieldType::Int)),
                    (
                        2,
                        (
                            "preconditions".into(),
                            FieldType::Message("Preconditions".into()),
                        ),
                    ),
                    (3, ("orphanDependents".into(), FieldType::Bool)),
                    (4, ("propagationPolicy".into(), FieldType::String)),
                    (
                        5,
                        (
                            "dryRun".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        6,
                        (
                            "ignoreStoreReadErrorWithClusterBreakingPotential".into(),
                            FieldType::Bool,
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "Preconditions".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("uid".into(), FieldType::String)),
                    (2, ("resourceVersion".into(), FieldType::String)),
                ]),
            },
        );

        // ========== apps/v1 types ==========

        schemas.insert("Deployment".into(), Self::deployment_schema());
        schemas.insert("DeploymentSpec".into(), Self::deployment_spec_schema());
        schemas.insert("DeploymentStatus".into(), Self::deployment_status_schema());
        schemas.insert(
            "DeploymentCondition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("status".into(), FieldType::String)),
                    (4, ("reason".into(), FieldType::String)),
                    (5, ("message".into(), FieldType::String)),
                    (
                        6,
                        ("lastUpdateTime".into(), FieldType::Message("Time".into())),
                    ),
                    (
                        7,
                        (
                            "lastTransitionTime".into(),
                            FieldType::Message("Time".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "DeploymentStrategy".into(),
            Self::deployment_strategy_schema(),
        );
        schemas.insert(
            "RollingUpdateDeployment".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("maxUnavailable".into(), FieldType::IntOrString)),
                    (2, ("maxSurge".into(), FieldType::IntOrString)),
                ]),
            },
        );
        schemas.insert(
            "ReplicaSet".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        ("spec".into(), FieldType::Message("ReplicaSetSpec".into())),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("ReplicaSetStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "ReplicaSetSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("replicas".into(), FieldType::Int)),
                    (
                        2,
                        (
                            "selector".into(),
                            FieldType::Message("LabelSelector".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "template".into(),
                            FieldType::Message("PodTemplateSpec".into()),
                        ),
                    ),
                    (4, ("minReadySeconds".into(), FieldType::Int)),
                ]),
            },
        );
        schemas.insert(
            "ReplicaSetStatus".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("replicas".into(), FieldType::Int)),
                    (2, ("fullyLabeledReplicas".into(), FieldType::Int)),
                    (3, ("observedGeneration".into(), FieldType::Int)),
                    (4, ("readyReplicas".into(), FieldType::Int)),
                    (5, ("availableReplicas".into(), FieldType::Int)),
                    (
                        6,
                        (
                            "conditions".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "ReplicaSetCondition".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "ReplicaSetCondition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("status".into(), FieldType::String)),
                    (
                        3,
                        (
                            "lastTransitionTime".into(),
                            FieldType::Message("Time".into()),
                        ),
                    ),
                    (4, ("reason".into(), FieldType::String)),
                    (5, ("message".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "StatefulSet".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        ("spec".into(), FieldType::Message("StatefulSetSpec".into())),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("StatefulSetStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "StatefulSetSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("replicas".into(), FieldType::Int)),
                    (
                        2,
                        (
                            "selector".into(),
                            FieldType::Message("LabelSelector".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "template".into(),
                            FieldType::Message("PodTemplateSpec".into()),
                        ),
                    ),
                    (
                        4,
                        (
                            "volumeClaimTemplates".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "PersistentVolumeClaim".into(),
                            ))),
                        ),
                    ),
                    (5, ("serviceName".into(), FieldType::String)),
                    (6, ("podManagementPolicy".into(), FieldType::String)),
                    (
                        7,
                        (
                            "updateStrategy".into(),
                            FieldType::Message("StatefulSetUpdateStrategy".into()),
                        ),
                    ),
                    (8, ("revisionHistoryLimit".into(), FieldType::Int)),
                    (9, ("minReadySeconds".into(), FieldType::Int)),
                    (
                        10,
                        (
                            "persistentVolumeClaimRetentionPolicy".into(),
                            FieldType::Message(
                                "StatefulSetPersistentVolumeClaimRetentionPolicy".into(),
                            ),
                        ),
                    ),
                    (
                        11,
                        (
                            "ordinals".into(),
                            FieldType::Message("StatefulSetOrdinals".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "StatefulSetUpdateStrategy".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (
                        2,
                        (
                            "rollingUpdate".into(),
                            FieldType::Message("RollingUpdateStatefulSetStrategy".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "RollingUpdateStatefulSetStrategy".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("partition".into(), FieldType::Int)),
                    (2, ("maxUnavailable".into(), FieldType::IntOrString)),
                ]),
            },
        );
        schemas.insert(
            "StatefulSetPersistentVolumeClaimRetentionPolicy".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("whenDeleted".into(), FieldType::String)),
                    (2, ("whenScaled".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "StatefulSetOrdinals".into(),
            MessageSchema {
                fields: HashMap::from([(1, ("start".into(), FieldType::Int))]),
            },
        );
        schemas.insert(
            "StatefulSetStatus".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("observedGeneration".into(), FieldType::Int)),
                    (2, ("replicas".into(), FieldType::Int)),
                    (3, ("readyReplicas".into(), FieldType::Int)),
                    (4, ("currentReplicas".into(), FieldType::Int)),
                    (5, ("updatedReplicas".into(), FieldType::Int)),
                    (6, ("currentRevision".into(), FieldType::String)),
                    (7, ("updateRevision".into(), FieldType::String)),
                    (8, ("collisionCount".into(), FieldType::Int)),
                    (
                        9,
                        (
                            "conditions".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "StatefulSetCondition".into(),
                            ))),
                        ),
                    ),
                    (10, ("availableReplicas".into(), FieldType::Int)),
                ]),
            },
        );
        schemas.insert(
            "StatefulSetCondition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("status".into(), FieldType::String)),
                    (
                        3,
                        (
                            "lastTransitionTime".into(),
                            FieldType::Message("Time".into()),
                        ),
                    ),
                    (4, ("reason".into(), FieldType::String)),
                    (5, ("message".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "DaemonSet".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        ("spec".into(), FieldType::Message("DaemonSetSpec".into())),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("DaemonSetStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "DaemonSetSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "selector".into(),
                            FieldType::Message("LabelSelector".into()),
                        ),
                    ),
                    (
                        2,
                        (
                            "template".into(),
                            FieldType::Message("PodTemplateSpec".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "updateStrategy".into(),
                            FieldType::Message("DaemonSetUpdateStrategy".into()),
                        ),
                    ),
                    (4, ("minReadySeconds".into(), FieldType::Int)),
                    (5, ("revisionHistoryLimit".into(), FieldType::Int)),
                ]),
            },
        );
        schemas.insert(
            "DaemonSetUpdateStrategy".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (
                        2,
                        (
                            "rollingUpdate".into(),
                            FieldType::Message("RollingUpdateDaemonSet".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "RollingUpdateDaemonSet".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("maxUnavailable".into(), FieldType::IntOrString)),
                    (2, ("maxSurge".into(), FieldType::IntOrString)),
                ]),
            },
        );
        schemas.insert(
            "DaemonSetStatus".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("currentNumberScheduled".into(), FieldType::Int)),
                    (2, ("numberMisscheduled".into(), FieldType::Int)),
                    (3, ("desiredNumberScheduled".into(), FieldType::Int)),
                    (4, ("numberReady".into(), FieldType::Int)),
                    (5, ("observedGeneration".into(), FieldType::Int)),
                    (6, ("updatedNumberScheduled".into(), FieldType::Int)),
                    (7, ("numberAvailable".into(), FieldType::Int)),
                    (8, ("numberUnavailable".into(), FieldType::Int)),
                    (9, ("collisionCount".into(), FieldType::Int)),
                    (
                        10,
                        (
                            "conditions".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "DaemonSetCondition".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "DaemonSetCondition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("status".into(), FieldType::String)),
                    (
                        3,
                        (
                            "lastTransitionTime".into(),
                            FieldType::Message("Time".into()),
                        ),
                    ),
                    (4, ("reason".into(), FieldType::String)),
                    (5, ("message".into(), FieldType::String)),
                ]),
            },
        );

        // ========== core/v1 types ==========

        schemas.insert("PodTemplateSpec".into(), Self::pod_template_spec_schema());
        schemas.insert("PodSpec".into(), Self::pod_spec_schema());
        schemas.insert("Container".into(), Self::container_schema());
        schemas.insert("ContainerPort".into(), Self::container_port_schema());
        schemas.insert("SecurityContext".into(), Self::security_context_schema());
        schemas.insert(
            "ResourceRequirements".into(),
            Self::resource_requirements_schema(),
        );
        schemas.insert("Volume".into(), Self::volume_schema());
        schemas.insert("VolumeSource".into(), Self::volume_source_schema());
        schemas.insert(
            "HostPathVolumeSource".into(),
            Self::host_path_volume_source_schema(),
        );
        schemas.insert(
            "EmptyDirVolumeSource".into(),
            Self::empty_dir_volume_source_schema(),
        );
        schemas.insert(
            "SecretVolumeSource".into(),
            Self::secret_volume_source_schema(),
        );
        schemas.insert(
            "PersistentVolumeClaimVolumeSource".into(),
            Self::persistent_volume_claim_volume_source_schema(),
        );
        schemas.insert(
            "ConfigMapVolumeSource".into(),
            Self::config_map_volume_source_schema(),
        );
        schemas.insert("KeyToPath".into(), Self::key_to_path_schema());
        schemas.insert(
            "DownwardAPIVolumeSource".into(),
            Self::downward_api_volume_source_schema(),
        );
        schemas.insert(
            "DownwardAPIVolumeFile".into(),
            Self::downward_api_volume_file_schema(),
        );
        schemas.insert(
            "ProjectedVolumeSource".into(),
            Self::projected_volume_source_schema(),
        );
        schemas.insert("VolumeProjection".into(), Self::volume_projection_schema());
        schemas.insert("SecretProjection".into(), Self::secret_projection_schema());
        schemas.insert(
            "ConfigMapProjection".into(),
            Self::config_map_projection_schema(),
        );
        schemas.insert(
            "DownwardAPIProjection".into(),
            Self::downward_api_projection_schema(),
        );
        schemas.insert(
            "ServiceAccountTokenProjection".into(),
            Self::service_account_token_projection_schema(),
        );
        schemas.insert("VolumeMount".into(), Self::volume_mount_schema());
        schemas.insert("EnvVar".into(), Self::env_var_schema());
        schemas.insert("EnvVarSource".into(), Self::env_var_source_schema());
        schemas.insert(
            "ObjectFieldSelector".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("apiVersion".into(), FieldType::String)),
                    (2, ("fieldPath".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "ResourceFieldSelector".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("containerName".into(), FieldType::String)),
                    (2, ("resource".into(), FieldType::String)),
                    (3, ("divisor".into(), FieldType::String)),
                ]),
            },
        );
        // ConfigMapKeySelector/SecretKeySelector/*EnvSource all embed
        // `LocalObjectReference` FLATTENED at field 1 (real k8s Go struct:
        // `LocalObjectReference \`json:",inline\``, so the JSON representation
        // is a bare `{"name":"x","key":"y"}`, never a nested `localObjectReference`
        // key). Field 1 was wrongly declared as a plain string here, which
        // decoded the wrapping message's own tag+length bytes straight into
        // the name — found live via a real CNPG-created Job whose container's
        // `env[].valueFrom.secretKeyRef.name` came back as
        // `"\n\x17platform-db-cluster-app"` instead of
        // `"platform-db-cluster-app"` — same bug class as the Quantity and
        // Volume/VolumeSource fixes above, just recurring in a different
        // family of embedded types.
        schemas.insert(
            "ConfigMapKeySelector".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "__localObjectReference".into(),
                            FieldType::FlattenedMessage("LocalObjectReference".into()),
                        ),
                    ),
                    (2, ("key".into(), FieldType::String)),
                    (3, ("optional".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "SecretKeySelector".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "__localObjectReference".into(),
                            FieldType::FlattenedMessage("LocalObjectReference".into()),
                        ),
                    ),
                    (2, ("key".into(), FieldType::String)),
                    (3, ("optional".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "SecretEnvSource".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "__localObjectReference".into(),
                            FieldType::FlattenedMessage("LocalObjectReference".into()),
                        ),
                    ),
                    (2, ("optional".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "ConfigMapEnvSource".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "__localObjectReference".into(),
                            FieldType::FlattenedMessage("LocalObjectReference".into()),
                        ),
                    ),
                    (2, ("optional".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "EnvFromSource".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("prefix".into(), FieldType::String)),
                    (
                        2,
                        (
                            "configMapRef".into(),
                            FieldType::Message("ConfigMapEnvSource".into()),
                        ),
                    ),
                    (
                        3,
                        ("secretRef".into(), FieldType::Message("SecretEnvSource".into())),
                    ),
                ]),
            },
        );
        schemas.insert("Probe".into(), Self::probe_schema());
        schemas.insert("ProbeHandler".into(), Self::probe_handler_schema());
        schemas.insert(
            "ExecAction".into(),
            MessageSchema {
                fields: HashMap::from([(
                    1,
                    (
                        "command".into(),
                        FieldType::Repeated(Box::new(FieldType::String)),
                    ),
                )]),
            },
        );
        schemas.insert(
            "HTTPGetAction".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("path".into(), FieldType::String)),
                    (2, ("port".into(), FieldType::IntOrString)),
                    (3, ("host".into(), FieldType::String)),
                    (4, ("scheme".into(), FieldType::String)),
                    (
                        5,
                        (
                            "httpHeaders".into(),
                            FieldType::Repeated(Box::new(FieldType::Message("HTTPHeader".into()))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "HTTPHeader".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("name".into(), FieldType::String)),
                    (2, ("value".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "TCPSocketAction".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("port".into(), FieldType::IntOrString)),
                    (2, ("host".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "GRPCAction".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("port".into(), FieldType::Int)),
                    (2, ("service".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "Lifecycle".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "postStart".into(),
                            FieldType::Message("LifecycleHandler".into()),
                        ),
                    ),
                    (
                        2,
                        (
                            "preStop".into(),
                            FieldType::Message("LifecycleHandler".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "LifecycleHandler".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("exec".into(), FieldType::Message("ExecAction".into()))),
                    (
                        2,
                        ("httpGet".into(), FieldType::Message("HTTPGetAction".into())),
                    ),
                    (
                        3,
                        (
                            "tcpSocket".into(),
                            FieldType::Message("TCPSocketAction".into()),
                        ),
                    ),
                    (
                        4,
                        ("sleep".into(), FieldType::Message("SleepAction".into())),
                    ),
                ]),
            },
        );
        schemas.insert(
            "SleepAction".into(),
            MessageSchema {
                fields: HashMap::from([(1, ("seconds".into(), FieldType::Int))]),
            },
        );
        schemas.insert(
            "Capabilities".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "add".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        2,
                        (
                            "drop".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "SELinuxOptions".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("user".into(), FieldType::String)),
                    (2, ("role".into(), FieldType::String)),
                    (3, ("type".into(), FieldType::String)),
                    (4, ("level".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "SeccompProfile".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("localhostProfile".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "AppArmorProfile".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("localhostProfile".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "PodSecurityContext".into(),
            Self::pod_security_context_schema(),
        );
        schemas.insert(
            "Toleration".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("key".into(), FieldType::String)),
                    (2, ("operator".into(), FieldType::String)),
                    (3, ("value".into(), FieldType::String)),
                    (4, ("effect".into(), FieldType::String)),
                    (5, ("tolerationSeconds".into(), FieldType::Int)),
                ]),
            },
        );
        schemas.insert(
            "PodDNSConfig".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "nameservers".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        2,
                        (
                            "searches".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        3,
                        (
                            "options".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "PodDNSConfigOption".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "PodDNSConfigOption".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("name".into(), FieldType::String)),
                    (2, ("value".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "LocalObjectReference".into(),
            MessageSchema {
                fields: HashMap::from([(1, ("name".into(), FieldType::String))]),
            },
        );
        schemas.insert(
            "Affinity".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "nodeAffinity".into(),
                            FieldType::Message("NodeAffinity".into()),
                        ),
                    ),
                    (
                        2,
                        (
                            "podAffinity".into(),
                            FieldType::Message("PodAffinity".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "podAntiAffinity".into(),
                            FieldType::Message("PodAntiAffinity".into()),
                        ),
                    ),
                ]),
            },
        );
        // Affinity sub-types are complex — decode as opaque messages
        schemas.insert(
            "NodeAffinity".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "PodAffinity".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "PodAntiAffinity".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "TopologySpreadConstraint".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("maxSkew".into(), FieldType::Int)),
                    (2, ("topologyKey".into(), FieldType::String)),
                    (3, ("whenUnsatisfiable".into(), FieldType::String)),
                    (
                        4,
                        (
                            "labelSelector".into(),
                            FieldType::Message("LabelSelector".into()),
                        ),
                    ),
                    (5, ("minDomains".into(), FieldType::Int)),
                    (6, ("nodeAffinityPolicy".into(), FieldType::String)),
                    (7, ("nodeTaintsPolicy".into(), FieldType::String)),
                    (
                        8,
                        (
                            "matchLabelKeys".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                ]),
            },
        );
        // Service, ConfigMap, Secret, etc. — common pattern
        schemas.insert(
            "Service".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("spec".into(), FieldType::Message("ServiceSpec".into()))),
                    (
                        3,
                        ("status".into(), FieldType::Message("ServiceStatus".into())),
                    ),
                ]),
            },
        );
        schemas.insert(
            "ServiceSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "ports".into(),
                            FieldType::Repeated(Box::new(FieldType::Message("ServicePort".into()))),
                        ),
                    ),
                    (2, ("selector".into(), FieldType::StringMap)),
                    (3, ("clusterIP".into(), FieldType::String)),
                    (4, ("type".into(), FieldType::String)),
                    (
                        5,
                        (
                            "externalIPs".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (7, ("sessionAffinity".into(), FieldType::String)),
                    (8, ("loadBalancerIP".into(), FieldType::String)),
                    (
                        9,
                        (
                            "loadBalancerSourceRanges".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (10, ("externalName".into(), FieldType::String)),
                    (11, ("externalTrafficPolicy".into(), FieldType::String)),
                    (12, ("healthCheckNodePort".into(), FieldType::Int)),
                    (13, ("publishNotReadyAddresses".into(), FieldType::Bool)),
                    (
                        14,
                        (
                            "sessionAffinityConfig".into(),
                            FieldType::Message("SessionAffinityConfig".into()),
                        ),
                    ),
                    (
                        17,
                        (
                            "ipFamilies".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (18, ("ipFamilyPolicy".into(), FieldType::String)),
                    (
                        19,
                        (
                            "clusterIPs".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (20, ("internalTrafficPolicy".into(), FieldType::String)),
                    (
                        21,
                        ("allocateLoadBalancerNodePorts".into(), FieldType::Bool),
                    ),
                    (22, ("loadBalancerClass".into(), FieldType::String)),
                    (23, ("trafficDistribution".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "ServicePort".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("name".into(), FieldType::String)),
                    (2, ("protocol".into(), FieldType::String)),
                    (3, ("port".into(), FieldType::Int)),
                    (4, ("targetPort".into(), FieldType::IntOrString)),
                    (5, ("nodePort".into(), FieldType::Int)),
                ]),
            },
        );
        schemas.insert(
            "ServiceStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "SessionAffinityConfig".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // PodDisruptionBudget (policy/v1) — found live via CNPG's Cluster
        // reconcile: no schema was registered for this kind at all, so
        // decode_k8s_resource() returned None for every protobuf-encoded
        // PodDisruptionBudget write, falling through to the generic CRD
        // fallback decoder (which blindly applies CustomResourceDefinitionSpec's
        // own field layout to any unregistered kind), producing garbage that
        // then failed strict deserialization — same bug class as the earlier
        // missing "Lease" schema.
        schemas.insert(
            "PodDisruptionBudget".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "spec".into(),
                            FieldType::Message("PodDisruptionBudgetSpec".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("PodDisruptionBudgetStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "PodDisruptionBudgetSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("minAvailable".into(), FieldType::IntOrString)),
                    (2, ("selector".into(), FieldType::Message("LabelSelector".into()))),
                    (3, ("maxUnavailable".into(), FieldType::IntOrString)),
                    (4, ("unhealthyPodEvictionPolicy".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "PodDisruptionBudgetStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // RBAC types (rbac.authorization.k8s.io/v1) — found live in the same
        // investigation as PodDisruptionBudget above: CNPG's Cluster reconcile
        // creates a Role/RoleBinding per cluster and hit the identical
        // no-schema-registered symptom immediately after PDB was fixed. Field
        // numbers verified against the real upstream k8s.io/api/rbac/v1
        // generated.proto.
        schemas.insert(
            "PolicyRule".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "verbs".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        2,
                        (
                            "apiGroups".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        3,
                        (
                            "resources".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        4,
                        (
                            "resourceNames".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        5,
                        (
                            "nonResourceURLs".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "Role".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "rules".into(),
                            FieldType::Repeated(Box::new(FieldType::Message("PolicyRule".into()))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "AggregationRule".into(),
            MessageSchema {
                fields: HashMap::from([(
                    1,
                    (
                        "clusterRoleSelectors".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("LabelSelector".into()))),
                    ),
                )]),
            },
        );
        schemas.insert(
            "ClusterRole".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "rules".into(),
                            FieldType::Repeated(Box::new(FieldType::Message("PolicyRule".into()))),
                        ),
                    ),
                    (
                        3,
                        (
                            "aggregationRule".into(),
                            FieldType::Message("AggregationRule".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "Subject".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("kind".into(), FieldType::String)),
                    (2, ("apiGroup".into(), FieldType::String)),
                    (3, ("name".into(), FieldType::String)),
                    (4, ("namespace".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "RoleRef".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("apiGroup".into(), FieldType::String)),
                    (2, ("kind".into(), FieldType::String)),
                    (3, ("name".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "RoleBinding".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "subjects".into(),
                            FieldType::Repeated(Box::new(FieldType::Message("Subject".into()))),
                        ),
                    ),
                    (3, ("roleRef".into(), FieldType::Message("RoleRef".into()))),
                ]),
            },
        );
        schemas.insert(
            "ClusterRoleBinding".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "subjects".into(),
                            FieldType::Repeated(Box::new(FieldType::Message("Subject".into()))),
                        ),
                    ),
                    (3, ("roleRef".into(), FieldType::Message("RoleRef".into()))),
                ]),
            },
        );

        // Batch types
        schemas.insert(
            "Job".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("spec".into(), FieldType::Message("JobSpec".into()))),
                    (3, ("status".into(), FieldType::Message("JobStatus".into()))),
                ]),
            },
        );
        schemas.insert(
            "JobSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("parallelism".into(), FieldType::Int)),
                    (2, ("completions".into(), FieldType::Int)),
                    (3, ("activeDeadlineSeconds".into(), FieldType::Int)),
                    (
                        4,
                        (
                            "selector".into(),
                            FieldType::Message("LabelSelector".into()),
                        ),
                    ),
                    (5, ("manualSelector".into(), FieldType::Bool)),
                    (
                        6,
                        (
                            "template".into(),
                            FieldType::Message("PodTemplateSpec".into()),
                        ),
                    ),
                    (7, ("backoffLimit".into(), FieldType::Int)),
                    (8, ("ttlSecondsAfterFinished".into(), FieldType::Int)),
                    (9, ("completionMode".into(), FieldType::String)),
                    (10, ("suspend".into(), FieldType::Bool)),
                    (11, ("podReplacementPolicy".into(), FieldType::String)),
                    (12, ("managedBy".into(), FieldType::String)),
                    (13, ("backoffLimitPerIndex".into(), FieldType::Int)),
                    (14, ("maxFailedIndexes".into(), FieldType::Int)),
                    (
                        15,
                        (
                            "podFailurePolicy".into(),
                            FieldType::Message("PodFailurePolicy".into()),
                        ),
                    ),
                    (
                        16,
                        (
                            "successPolicy".into(),
                            FieldType::Message("SuccessPolicy".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "JobStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "PodFailurePolicy".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "SuccessPolicy".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // Pod (standalone)
        schemas.insert(
            "Pod".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("spec".into(), FieldType::Message("PodSpec".into()))),
                    (3, ("status".into(), FieldType::Message("PodStatus".into()))),
                ]),
            },
        );
        schemas.insert(
            "PodStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // ConfigMap & Secret
        schemas.insert(
            "ConfigMap".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("data".into(), FieldType::StringMap)),
                    (3, ("binaryData".into(), FieldType::StringMap)),
                    (4, ("immutable".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "Secret".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("data".into(), FieldType::StringMap)),
                    (3, ("type".into(), FieldType::String)),
                    (4, ("stringData".into(), FieldType::StringMap)),
                    (5, ("immutable".into(), FieldType::Bool)),
                ]),
            },
        );

        // Namespace
        schemas.insert(
            "Namespace".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        ("spec".into(), FieldType::Message("NamespaceSpec".into())),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("NamespaceStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "NamespaceSpec".into(),
            MessageSchema {
                fields: HashMap::from([(
                    1,
                    (
                        "finalizers".into(),
                        FieldType::Repeated(Box::new(FieldType::String)),
                    ),
                )]),
            },
        );
        schemas.insert(
            "NamespaceStatus".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("phase".into(), FieldType::String)),
                    (
                        2,
                        (
                            "conditions".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "NamespaceCondition".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "NamespaceCondition".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // ServiceAccount
        schemas.insert(
            "ServiceAccount".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "secrets".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "ObjectReference".into(),
                            ))),
                        ),
                    ),
                    (
                        3,
                        (
                            "imagePullSecrets".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "LocalObjectReference".into(),
                            ))),
                        ),
                    ),
                    (4, ("automountServiceAccountToken".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "ObjectReference".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("kind".into(), FieldType::String)),
                    (2, ("namespace".into(), FieldType::String)),
                    (3, ("name".into(), FieldType::String)),
                    (4, ("uid".into(), FieldType::String)),
                    (5, ("apiVersion".into(), FieldType::String)),
                    (6, ("resourceVersion".into(), FieldType::String)),
                    (7, ("fieldPath".into(), FieldType::String)),
                ]),
            },
        );

        // PersistentVolumeClaim (used by StatefulSet volumeClaimTemplates)
        schemas.insert(
            "PersistentVolumeClaim".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "spec".into(),
                            FieldType::Message("PersistentVolumeClaimSpec".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("PersistentVolumeClaimStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "PersistentVolumeClaimSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "accessModes".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        2,
                        (
                            "resources".into(),
                            FieldType::Message("VolumeResourceRequirements".into()),
                        ),
                    ),
                    (3, ("volumeName".into(), FieldType::String)),
                    (
                        4,
                        (
                            "selector".into(),
                            FieldType::Message("LabelSelector".into()),
                        ),
                    ),
                    (5, ("storageClassName".into(), FieldType::String)),
                    (6, ("volumeMode".into(), FieldType::String)),
                    (
                        7,
                        (
                            "dataSource".into(),
                            FieldType::Message("TypedLocalObjectReference".into()),
                        ),
                    ),
                    (
                        8,
                        (
                            "dataSourceRef".into(),
                            FieldType::Message("TypedObjectReference".into()),
                        ),
                    ),
                    (9, ("volumeAttributesClassName".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "PersistentVolumeClaimStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "VolumeResourceRequirements".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("limits".into(), FieldType::QuantityMap)),
                    (2, ("requests".into(), FieldType::QuantityMap)),
                ]),
            },
        );
        schemas.insert(
            "TypedLocalObjectReference".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("apiGroup".into(), FieldType::String)),
                    (2, ("kind".into(), FieldType::String)),
                    (3, ("name".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "TypedObjectReference".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("apiGroup".into(), FieldType::String)),
                    (2, ("kind".into(), FieldType::String)),
                    (3, ("name".into(), FieldType::String)),
                    (4, ("namespace".into(), FieldType::String)),
                ]),
            },
        );

        // ReplicationController (core/v1)
        schemas.insert(
            "ReplicationController".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "spec".into(),
                            FieldType::Message("ReplicationControllerSpec".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("ReplicationControllerStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "ReplicationControllerSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("replicas".into(), FieldType::Int)),
                    (2, ("selector".into(), FieldType::StringMap)),
                    (
                        3,
                        (
                            "template".into(),
                            FieldType::Message("PodTemplateSpec".into()),
                        ),
                    ),
                    (4, ("minReadySeconds".into(), FieldType::Int)),
                ]),
            },
        );
        schemas.insert(
            "ReplicationControllerStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // Endpoints
        schemas.insert(
            "Endpoints".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "subsets".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "EndpointSubset".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "EndpointSubset".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // Node
        schemas.insert(
            "Node".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (2, ("spec".into(), FieldType::Message("NodeSpec".into()))),
                    (
                        3,
                        ("status".into(), FieldType::Message("NodeStatus".into())),
                    ),
                ]),
            },
        );
        schemas.insert(
            "NodeSpec".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "NodeStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );

        // ========== apiextensions types (CRDs) ==========

        schemas.insert(
            "CustomResourceDefinition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                    ),
                    (
                        2,
                        (
                            "spec".into(),
                            FieldType::Message("CustomResourceDefinitionSpec".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "status".into(),
                            FieldType::Message("CustomResourceDefinitionStatus".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceDefinitionSpec".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("group".into(), FieldType::String)),
                    (
                        3,
                        (
                            "names".into(),
                            FieldType::Message("CustomResourceDefinitionNames".into()),
                        ),
                    ),
                    (4, ("scope".into(), FieldType::String)),
                    (
                        7,
                        (
                            "versions".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "CustomResourceDefinitionVersion".into(),
                            ))),
                        ),
                    ),
                    (
                        9,
                        (
                            "conversion".into(),
                            FieldType::Message("CustomResourceConversion".into()),
                        ),
                    ),
                    (10, ("preserveUnknownFields".into(), FieldType::Bool)),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceDefinitionNames".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("plural".into(), FieldType::String)),
                    (2, ("singular".into(), FieldType::String)),
                    (
                        3,
                        (
                            "shortNames".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (4, ("kind".into(), FieldType::String)),
                    (5, ("listKind".into(), FieldType::String)),
                    (
                        6,
                        (
                            "categories".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceDefinitionVersion".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("name".into(), FieldType::String)),
                    (2, ("served".into(), FieldType::Bool)),
                    (3, ("storage".into(), FieldType::Bool)),
                    (
                        4,
                        (
                            "schema".into(),
                            FieldType::Message("CustomResourceValidation".into()),
                        ),
                    ),
                    (
                        5,
                        (
                            "subresources".into(),
                            FieldType::Message("CustomResourceSubresources".into()),
                        ),
                    ),
                    (
                        6,
                        (
                            "additionalPrinterColumns".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "CustomResourceColumnDefinition".into(),
                            ))),
                        ),
                    ),
                    (7, ("deprecated".into(), FieldType::Bool)),
                    (8, ("deprecationWarning".into(), FieldType::String)),
                    (
                        9,
                        (
                            "selectableFields".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "SelectableField".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceValidation".into(),
            MessageSchema {
                fields: HashMap::from([(
                    1,
                    (
                        "openAPIV3Schema".into(),
                        FieldType::Message("JSONSchemaProps".into()),
                    ),
                )]),
            },
        );
        schemas.insert(
            "JSONSchemaProps".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("id".into(), FieldType::String)),
                    (2, ("$schema".into(), FieldType::String)),
                    (3, ("$ref".into(), FieldType::String)),
                    (4, ("description".into(), FieldType::String)),
                    (5, ("type".into(), FieldType::String)),
                    (6, ("format".into(), FieldType::String)),
                    (7, ("title".into(), FieldType::String)),
                    (8, ("default".into(), FieldType::JsonRaw)),
                    (9, ("maximum".into(), FieldType::Int)),
                    (10, ("exclusiveMaximum".into(), FieldType::Bool)),
                    (11, ("minimum".into(), FieldType::Int)),
                    (12, ("exclusiveMinimum".into(), FieldType::Bool)),
                    (13, ("maxLength".into(), FieldType::Int)),
                    (14, ("minLength".into(), FieldType::Int)),
                    (15, ("pattern".into(), FieldType::String)),
                    (16, ("maxItems".into(), FieldType::Int)),
                    (17, ("minItems".into(), FieldType::Int)),
                    (18, ("uniqueItems".into(), FieldType::Bool)),
                    (19, ("multipleOf".into(), FieldType::Int)), // double, but Int works for decode
                    (
                        20,
                        (
                            "enum".into(),
                            FieldType::Repeated(Box::new(FieldType::JsonRaw)),
                        ),
                    ),
                    (21, ("maxProperties".into(), FieldType::Int)),
                    (22, ("minProperties".into(), FieldType::Int)),
                    (
                        23,
                        (
                            "required".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (
                        24,
                        (
                            "items".into(),
                            FieldType::Message("JSONSchemaPropsOrArray".into()),
                        ),
                    ),
                    (
                        25,
                        (
                            "allOf".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "JSONSchemaProps".into(),
                            ))),
                        ),
                    ),
                    (
                        26,
                        (
                            "oneOf".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "JSONSchemaProps".into(),
                            ))),
                        ),
                    ),
                    (
                        27,
                        (
                            "anyOf".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "JSONSchemaProps".into(),
                            ))),
                        ),
                    ),
                    (
                        28,
                        ("not".into(), FieldType::Message("JSONSchemaProps".into())),
                    ),
                    // field 29: properties — map<string, JSONSchemaProps>
                    // Protobuf maps are encoded as repeated MapEntry messages.
                    // We handle this as a special StringMap-like type but with Message values.
                    // For now, decode properties entries manually.
                    (
                        29,
                        (
                            "properties".into(),
                            FieldType::MessageMap("JSONSchemaProps".into()),
                        ),
                    ),
                    (
                        30,
                        (
                            "additionalProperties".into(),
                            FieldType::Message("JSONSchemaPropsOrBool".into()),
                        ),
                    ),
                    (37, ("nullable".into(), FieldType::Bool)),
                    (
                        38,
                        (
                            "x-kubernetes-preserve-unknown-fields".into(),
                            FieldType::Bool,
                        ),
                    ),
                    (
                        39,
                        ("x-kubernetes-embedded-resource".into(), FieldType::Bool),
                    ),
                    (40, ("x-kubernetes-int-or-string".into(), FieldType::Bool)),
                    (
                        41,
                        (
                            "x-kubernetes-list-map-keys".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                    (42, ("x-kubernetes-list-type".into(), FieldType::String)),
                    (43, ("x-kubernetes-map-type".into(), FieldType::String)),
                    (
                        44,
                        (
                            "x-kubernetes-validations".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "ValidationRule".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        // JSONSchemaPropsOrArray: field 1 = schema (JSONSchemaProps), field 2 = jsonSchemas (repeated JSONSchemaProps)
        schemas.insert(
            "JSONSchemaPropsOrArray".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "schema".into(),
                            FieldType::Message("JSONSchemaProps".into()),
                        ),
                    ),
                    (
                        2,
                        (
                            "jsonSchemas".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "JSONSchemaProps".into(),
                            ))),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "JSONSchemaPropsOrBool".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("allows".into(), FieldType::Bool)),
                    (
                        2,
                        (
                            "schema".into(),
                            FieldType::Message("JSONSchemaProps".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceSubresources".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "status".into(),
                            FieldType::Message("CustomResourceSubresourceStatus".into()),
                        ),
                    ),
                    (
                        2,
                        (
                            "scale".into(),
                            FieldType::Message("CustomResourceSubresourceScale".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceSubresourceStatus".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "CustomResourceSubresourceScale".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("specReplicasPath".into(), FieldType::String)),
                    (2, ("statusReplicasPath".into(), FieldType::String)),
                    (3, ("labelSelectorPath".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceConversion".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("strategy".into(), FieldType::String)),
                    (
                        2,
                        (
                            "webhook".into(),
                            FieldType::Message("WebhookConversion".into()),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "WebhookConversion".into(),
            MessageSchema {
                fields: HashMap::new(),
            },
        );
        schemas.insert(
            "CustomResourceDefinitionStatus".into(),
            MessageSchema {
                fields: HashMap::from([
                    (
                        1,
                        (
                            "conditions".into(),
                            FieldType::Repeated(Box::new(FieldType::Message(
                                "CustomResourceDefinitionCondition".into(),
                            ))),
                        ),
                    ),
                    (
                        2,
                        (
                            "acceptedNames".into(),
                            FieldType::Message("CustomResourceDefinitionNames".into()),
                        ),
                    ),
                    (
                        3,
                        (
                            "storedVersions".into(),
                            FieldType::Repeated(Box::new(FieldType::String)),
                        ),
                    ),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceDefinitionCondition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("type".into(), FieldType::String)),
                    (2, ("status".into(), FieldType::String)),
                    (
                        3,
                        (
                            "lastTransitionTime".into(),
                            FieldType::Message("Time".into()),
                        ),
                    ),
                    (4, ("reason".into(), FieldType::String)),
                    (5, ("message".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "CustomResourceColumnDefinition".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("name".into(), FieldType::String)),
                    (2, ("type".into(), FieldType::String)),
                    (3, ("format".into(), FieldType::String)),
                    (4, ("description".into(), FieldType::String)),
                    (5, ("priority".into(), FieldType::Int)),
                    (6, ("jsonPath".into(), FieldType::String)),
                ]),
            },
        );
        schemas.insert(
            "SelectableField".into(),
            MessageSchema {
                fields: HashMap::from([(1, ("jsonPath".into(), FieldType::String))]),
            },
        );
        schemas.insert(
            "ValidationRule".into(),
            MessageSchema {
                fields: HashMap::from([
                    (1, ("rule".into(), FieldType::String)),
                    (2, ("message".into(), FieldType::String)),
                    (4, ("messageExpression".into(), FieldType::String)),
                    (5, ("reason".into(), FieldType::String)),
                    (6, ("fieldPath".into(), FieldType::String)),
                    (7, ("optionalOldSelf".into(), FieldType::Bool)),
                ]),
            },
        );

        ProtoRegistry { schemas }
    }

    fn object_meta_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("name".into(), FieldType::String)),
                (2, ("generateName".into(), FieldType::String)),
                (3, ("namespace".into(), FieldType::String)),
                (5, ("uid".into(), FieldType::String)),
                (6, ("resourceVersion".into(), FieldType::String)),
                (7, ("generation".into(), FieldType::Int)),
                (
                    8,
                    (
                        "creationTimestamp".into(),
                        FieldType::Message("Time".into()),
                    ),
                ),
                (
                    9,
                    (
                        "deletionTimestamp".into(),
                        FieldType::Message("Time".into()),
                    ),
                ),
                (10, ("deletionGracePeriodSeconds".into(), FieldType::Int)),
                (11, ("labels".into(), FieldType::StringMap)),
                (12, ("annotations".into(), FieldType::StringMap)),
                (
                    13,
                    (
                        "ownerReferences".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("OwnerReference".into()))),
                    ),
                ),
                (
                    14,
                    (
                        "finalizers".into(),
                        FieldType::Repeated(Box::new(FieldType::String)),
                    ),
                ),
                (
                    17,
                    (
                        "managedFields".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "ManagedFieldsEntry".into(),
                        ))),
                    ),
                ),
            ]),
        }
    }

    /// Field numbers per the real `k8s.io/apimachinery/pkg/apis/meta/v1`
    /// `OwnerReference` proto (verified against upstream
    /// `generated.proto`, not assumed): `kind=1`, `name=3`, `uid=4`,
    /// `apiVersion=5`, `controller=6`, `blockOwnerDeletion=7` — field 2
    /// does not exist. This schema previously had `apiVersion=1,
    /// kind=2` (backwards) with no mapping for the real `apiVersion=5`
    /// at all — silently dropping every real client's `kind` value into
    /// the `apiVersion` JSON key and losing `apiVersion` and `kind`
    /// entirely. Since `kind` is a required field on a real
    /// `OwnerReference`, this broke deserializing *any* protobuf-encoded
    /// object carrying an `ownerReferences` entry (confirmed live: a
    /// real operator, CloudNativePG, creating its own webhook-cert
    /// `Secret` with an owner reference to its `Deployment` — a
    /// generic bug, not specific to that one object).
    fn owner_reference_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("kind".into(), FieldType::String)),
                (3, ("name".into(), FieldType::String)),
                (4, ("uid".into(), FieldType::String)),
                (5, ("apiVersion".into(), FieldType::String)),
                (6, ("controller".into(), FieldType::Bool)),
                (7, ("blockOwnerDeletion".into(), FieldType::Bool)),
            ]),
        }
    }

    fn label_selector_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("matchLabels".into(), FieldType::StringMap)),
                (
                    2,
                    (
                        "matchExpressions".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "LabelSelectorRequirement".into(),
                        ))),
                    ),
                ),
            ]),
        }
    }

    fn deployment_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                ),
                (
                    2,
                    ("spec".into(), FieldType::Message("DeploymentSpec".into())),
                ),
                (
                    3,
                    (
                        "status".into(),
                        FieldType::Message("DeploymentStatus".into()),
                    ),
                ),
            ]),
        }
    }

    fn deployment_spec_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("replicas".into(), FieldType::Int)),
                (
                    2,
                    (
                        "selector".into(),
                        FieldType::Message("LabelSelector".into()),
                    ),
                ),
                (
                    3,
                    (
                        "template".into(),
                        FieldType::Message("PodTemplateSpec".into()),
                    ),
                ),
                (
                    4,
                    (
                        "strategy".into(),
                        FieldType::Message("DeploymentStrategy".into()),
                    ),
                ),
                (5, ("minReadySeconds".into(), FieldType::Int)),
                (6, ("revisionHistoryLimit".into(), FieldType::Int)),
                (7, ("paused".into(), FieldType::Bool)),
                (9, ("progressDeadlineSeconds".into(), FieldType::Int)),
            ]),
        }
    }

    fn deployment_status_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("observedGeneration".into(), FieldType::Int)),
                (2, ("replicas".into(), FieldType::Int)),
                (3, ("updatedReplicas".into(), FieldType::Int)),
                (4, ("unavailableReplicas".into(), FieldType::Int)),
                (5, ("availableReplicas".into(), FieldType::Int)),
                (
                    6,
                    (
                        "conditions".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "DeploymentCondition".into(),
                        ))),
                    ),
                ),
                (7, ("readyReplicas".into(), FieldType::Int)),
                (8, ("collisionCount".into(), FieldType::Int)),
            ]),
        }
    }

    fn deployment_strategy_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("type".into(), FieldType::String)),
                (
                    2,
                    (
                        "rollingUpdate".into(),
                        FieldType::Message("RollingUpdateDeployment".into()),
                    ),
                ),
            ]),
        }
    }

    fn pod_template_spec_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    ("metadata".into(), FieldType::Message("ObjectMeta".into())),
                ),
                (2, ("spec".into(), FieldType::Message("PodSpec".into()))),
            ]),
        }
    }

    fn pod_spec_schema() -> MessageSchema {
        // From core/v1/generated.proto — PodSpec has MANY fields
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "volumes".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("Volume".into()))),
                    ),
                ),
                (
                    2,
                    (
                        "containers".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("Container".into()))),
                    ),
                ),
                (3, ("restartPolicy".into(), FieldType::String)),
                (4, ("terminationGracePeriodSeconds".into(), FieldType::Int)),
                (5, ("activeDeadlineSeconds".into(), FieldType::Int)),
                (6, ("dnsPolicy".into(), FieldType::String)),
                (7, ("nodeSelector".into(), FieldType::StringMap)),
                (8, ("serviceAccountName".into(), FieldType::String)),
                (9, ("serviceAccount".into(), FieldType::String)),
                (10, ("nodeName".into(), FieldType::String)),
                (11, ("hostNetwork".into(), FieldType::Bool)),
                (12, ("hostPID".into(), FieldType::Bool)),
                (13, ("hostIPC".into(), FieldType::Bool)),
                (
                    14,
                    (
                        "securityContext".into(),
                        FieldType::Message("PodSecurityContext".into()),
                    ),
                ),
                (
                    15,
                    (
                        "imagePullSecrets".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "LocalObjectReference".into(),
                        ))),
                    ),
                ),
                (16, ("hostname".into(), FieldType::String)),
                (17, ("subdomain".into(), FieldType::String)),
                (
                    18,
                    ("affinity".into(), FieldType::Message("Affinity".into())),
                ),
                (19, ("schedulerName".into(), FieldType::String)),
                (
                    20,
                    (
                        "initContainers".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("Container".into()))),
                    ),
                ),
                (21, ("automountServiceAccountToken".into(), FieldType::Bool)),
                (
                    22,
                    (
                        "tolerations".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("Toleration".into()))),
                    ),
                ),
                (
                    23,
                    (
                        "hostAliases".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("HostAlias".into()))),
                    ),
                ),
                (24, ("priorityClassName".into(), FieldType::String)),
                (25, ("priority".into(), FieldType::Int)),
                (
                    26,
                    (
                        "dnsConfig".into(),
                        FieldType::Message("PodDNSConfig".into()),
                    ),
                ),
                (27, ("shareProcessNamespace".into(), FieldType::Bool)),
                (
                    28,
                    (
                        "readinessGates".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "PodReadinessGate".into(),
                        ))),
                    ),
                ),
                (29, ("runtimeClassName".into(), FieldType::String)),
                (32, ("overhead".into(), FieldType::QuantityMap)),
                (30, ("enableServiceLinks".into(), FieldType::Bool)),
                (
                    34,
                    (
                        "ephemeralContainers".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("Container".into()))),
                    ),
                ),
                (
                    33,
                    (
                        "topologySpreadConstraints".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "TopologySpreadConstraint".into(),
                        ))),
                    ),
                ),
                (35, ("setHostnameAsFQDN".into(), FieldType::Bool)),
                (36, ("os".into(), FieldType::Message("PodOS".into()))),
                (
                    39,
                    (
                        "resourceClaims".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "PodResourceClaim".into(),
                        ))),
                    ),
                ),
                (
                    38,
                    (
                        "schedulingGates".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "PodSchedulingGate".into(),
                        ))),
                    ),
                ),
            ]),
        }
    }

    fn container_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("name".into(), FieldType::String)),
                (2, ("image".into(), FieldType::String)),
                (
                    3,
                    (
                        "command".into(),
                        FieldType::Repeated(Box::new(FieldType::String)),
                    ),
                ),
                (
                    4,
                    (
                        "args".into(),
                        FieldType::Repeated(Box::new(FieldType::String)),
                    ),
                ),
                (5, ("workingDir".into(), FieldType::String)),
                (
                    6,
                    (
                        "ports".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("ContainerPort".into()))),
                    ),
                ),
                (
                    7,
                    (
                        "env".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("EnvVar".into()))),
                    ),
                ),
                (
                    8,
                    (
                        "resources".into(),
                        FieldType::Message("ResourceRequirements".into()),
                    ),
                ),
                (
                    9,
                    (
                        "volumeMounts".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("VolumeMount".into()))),
                    ),
                ),
                (
                    10,
                    ("livenessProbe".into(), FieldType::Message("Probe".into())),
                ),
                (
                    11,
                    ("readinessProbe".into(), FieldType::Message("Probe".into())),
                ),
                (
                    12,
                    ("lifecycle".into(), FieldType::Message("Lifecycle".into())),
                ),
                (13, ("terminationMessagePath".into(), FieldType::String)),
                (14, ("imagePullPolicy".into(), FieldType::String)),
                (
                    15,
                    (
                        "securityContext".into(),
                        FieldType::Message("SecurityContext".into()),
                    ),
                ),
                (16, ("stdin".into(), FieldType::Bool)),
                (17, ("stdinOnce".into(), FieldType::Bool)),
                (18, ("tty".into(), FieldType::Bool)),
                (
                    19,
                    (
                        "envFrom".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("EnvFromSource".into()))),
                    ),
                ),
                (20, ("terminationMessagePolicy".into(), FieldType::String)),
                (
                    22,
                    ("startupProbe".into(), FieldType::Message("Probe".into())),
                ),
                (
                    23,
                    (
                        "volumeDevices".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("VolumeDevice".into()))),
                    ),
                ),
                (
                    24,
                    (
                        "resizePolicy".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "ContainerResizePolicy".into(),
                        ))),
                    ),
                ),
                (25, ("restartPolicy".into(), FieldType::String)),
            ]),
        }
    }

    fn container_port_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("name".into(), FieldType::String)),
                (2, ("hostPort".into(), FieldType::Int)),
                (3, ("containerPort".into(), FieldType::Int)),
                (4, ("protocol".into(), FieldType::String)),
                (5, ("hostIP".into(), FieldType::String)),
            ]),
        }
    }

    fn security_context_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "capabilities".into(),
                        FieldType::Message("Capabilities".into()),
                    ),
                ),
                (2, ("privileged".into(), FieldType::Bool)),
                (
                    3,
                    (
                        "seLinuxOptions".into(),
                        FieldType::Message("SELinuxOptions".into()),
                    ),
                ),
                (4, ("runAsUser".into(), FieldType::Int)),
                (5, ("runAsNonRoot".into(), FieldType::Bool)),
                (6, ("readOnlyRootFilesystem".into(), FieldType::Bool)),
                (7, ("allowPrivilegeEscalation".into(), FieldType::Bool)),
                (8, ("runAsGroup".into(), FieldType::Int)),
                (9, ("procMount".into(), FieldType::String)),
                (
                    11,
                    (
                        "seccompProfile".into(),
                        FieldType::Message("SeccompProfile".into()),
                    ),
                ),
                (
                    12,
                    (
                        "appArmorProfile".into(),
                        FieldType::Message("AppArmorProfile".into()),
                    ),
                ),
            ]),
        }
    }

    fn resource_requirements_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("limits".into(), FieldType::QuantityMap)),
                (2, ("requests".into(), FieldType::QuantityMap)),
                (
                    3,
                    (
                        "claims".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("ResourceClaim".into()))),
                    ),
                ),
            ]),
        }
    }

    fn volume_schema() -> MessageSchema {
        // Real k8s.io/api/core/v1 `Volume` message: `{ name = 1; volumeSource
        // VolumeSource = 2; }` — VolumeSource is a genuine NESTED sub-message,
        // not fields flattened directly onto Volume's own field numbers (the
        // pre-fix bug: Volume's field 2 was treated as directly being
        // `hostPath`, which decoded a real `emptyDir` volume as a broken,
        // empty `hostPath` object missing its required `path`). The JSON
        // representation flattens VolumeSource's fields onto Volume though
        // (matching Go's `VolumeSource \`json:",inline\`` embedding), hence
        // `FlattenedMessage` here rather than a plain nested `Message`.
        MessageSchema {
            fields: HashMap::from([
                (1, ("name".into(), FieldType::String)),
                (2, ("__volumeSource".into(), FieldType::FlattenedMessage("VolumeSource".into()))),
            ]),
        }
    }

    /// `VolumeSource` — we handle the source types actually likely to appear
    /// in real workloads; legacy/deprecated cloud-specific types (GCE/AWS/
    /// Azure/vSphere/Cinder/RBD/etc.) are intentionally omitted. Field
    /// numbers verified against the real upstream
    /// k8s.io/api/core/v1 generated.proto.
    fn volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("hostPath".into(), FieldType::Message("HostPathVolumeSource".into()))),
                (2, ("emptyDir".into(), FieldType::Message("EmptyDirVolumeSource".into()))),
                (6, ("secret".into(), FieldType::Message("SecretVolumeSource".into()))),
                (
                    10,
                    (
                        "persistentVolumeClaim".into(),
                        FieldType::Message("PersistentVolumeClaimVolumeSource".into()),
                    ),
                ),
                (16, ("downwardAPI".into(), FieldType::Message("DownwardAPIVolumeSource".into()))),
                (19, ("configMap".into(), FieldType::Message("ConfigMapVolumeSource".into()))),
                (26, ("projected".into(), FieldType::Message("ProjectedVolumeSource".into()))),
            ]),
        }
    }

    fn host_path_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("path".into(), FieldType::String)),
                (2, ("type".into(), FieldType::String)),
            ]),
        }
    }

    fn empty_dir_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("medium".into(), FieldType::String)),
                (2, ("sizeLimit".into(), FieldType::Quantity)),
            ]),
        }
    }

    fn secret_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("secretName".into(), FieldType::String)),
                (
                    2,
                    (
                        "items".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("KeyToPath".into()))),
                    ),
                ),
                (3, ("defaultMode".into(), FieldType::Int)),
                (4, ("optional".into(), FieldType::Bool)),
            ]),
        }
    }

    fn persistent_volume_claim_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("claimName".into(), FieldType::String)),
                (2, ("readOnly".into(), FieldType::Bool)),
            ]),
        }
    }

    fn config_map_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "__localObjectReference".into(),
                        FieldType::FlattenedMessage("LocalObjectReference".into()),
                    ),
                ),
                (
                    2,
                    (
                        "items".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("KeyToPath".into()))),
                    ),
                ),
                (3, ("defaultMode".into(), FieldType::Int)),
                (4, ("optional".into(), FieldType::Bool)),
            ]),
        }
    }

    fn key_to_path_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("key".into(), FieldType::String)),
                (2, ("path".into(), FieldType::String)),
                (3, ("mode".into(), FieldType::Int)),
            ]),
        }
    }

    fn downward_api_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "items".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "DownwardAPIVolumeFile".into(),
                        ))),
                    ),
                ),
                (2, ("defaultMode".into(), FieldType::Int)),
            ]),
        }
    }

    fn downward_api_volume_file_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("path".into(), FieldType::String)),
                (
                    2,
                    (
                        "fieldRef".into(),
                        FieldType::Message("ObjectFieldSelector".into()),
                    ),
                ),
                (
                    3,
                    (
                        "resourceFieldRef".into(),
                        FieldType::Message("ResourceFieldSelector".into()),
                    ),
                ),
                (4, ("mode".into(), FieldType::Int)),
            ]),
        }
    }

    fn projected_volume_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "sources".into(),
                        FieldType::Repeated(Box::new(FieldType::Message(
                            "VolumeProjection".into(),
                        ))),
                    ),
                ),
                (2, ("defaultMode".into(), FieldType::Int)),
            ]),
        }
    }

    fn volume_projection_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("secret".into(), FieldType::Message("SecretProjection".into()))),
                (
                    2,
                    (
                        "downwardAPI".into(),
                        FieldType::Message("DownwardAPIProjection".into()),
                    ),
                ),
                (
                    3,
                    (
                        "configMap".into(),
                        FieldType::Message("ConfigMapProjection".into()),
                    ),
                ),
                (
                    4,
                    (
                        "serviceAccountToken".into(),
                        FieldType::Message("ServiceAccountTokenProjection".into()),
                    ),
                ),
            ]),
        }
    }

    fn secret_projection_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "__localObjectReference".into(),
                        FieldType::FlattenedMessage("LocalObjectReference".into()),
                    ),
                ),
                (
                    2,
                    (
                        "items".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("KeyToPath".into()))),
                    ),
                ),
                (4, ("optional".into(), FieldType::Bool)),
            ]),
        }
    }

    fn config_map_projection_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "__localObjectReference".into(),
                        FieldType::FlattenedMessage("LocalObjectReference".into()),
                    ),
                ),
                (
                    2,
                    (
                        "items".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("KeyToPath".into()))),
                    ),
                ),
                (4, ("optional".into(), FieldType::Bool)),
            ]),
        }
    }

    fn downward_api_projection_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([(
                1,
                (
                    "items".into(),
                    FieldType::Repeated(Box::new(FieldType::Message(
                        "DownwardAPIVolumeFile".into(),
                    ))),
                ),
            )]),
        }
    }

    fn service_account_token_projection_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("audience".into(), FieldType::String)),
                (2, ("expirationSeconds".into(), FieldType::Int)),
                (3, ("path".into(), FieldType::String)),
            ]),
        }
    }

    fn volume_mount_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("name".into(), FieldType::String)),
                (2, ("readOnly".into(), FieldType::Bool)),
                (3, ("mountPath".into(), FieldType::String)),
                (4, ("subPath".into(), FieldType::String)),
                (5, ("mountPropagation".into(), FieldType::String)),
                (6, ("subPathExpr".into(), FieldType::String)),
                (7, ("recursiveReadOnly".into(), FieldType::String)),
            ]),
        }
    }

    fn env_var_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("name".into(), FieldType::String)),
                (2, ("value".into(), FieldType::String)),
                (
                    3,
                    (
                        "valueFrom".into(),
                        FieldType::Message("EnvVarSource".into()),
                    ),
                ),
            ]),
        }
    }

    fn env_var_source_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "fieldRef".into(),
                        FieldType::Message("ObjectFieldSelector".into()),
                    ),
                ),
                (
                    2,
                    (
                        "resourceFieldRef".into(),
                        FieldType::Message("ResourceFieldSelector".into()),
                    ),
                ),
                (
                    3,
                    (
                        "configMapKeyRef".into(),
                        FieldType::Message("ConfigMapKeySelector".into()),
                    ),
                ),
                (
                    4,
                    (
                        "secretKeyRef".into(),
                        FieldType::Message("SecretKeySelector".into()),
                    ),
                ),
            ]),
        }
    }

    fn probe_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                // FlattenedMessage, not Message: Go's `corev1.Probe` embeds
                // `ProbeHandler` via `json:",inline"` — exec/httpGet/tcpSocket
                // appear directly on the probe object in JSON, matching this
                // crate's own Probe struct. Decoding this as a literal nested
                // `handler` message (this field's previous behavior) produced
                // JSON that didn't match the Rust struct's shape at all,
                // silently failing strict-field-validation with "unknown
                // field ...handler" on every real client's Pod create —
                // live-hit via CNPG's own instance pod creation. Same bug
                // class as `Volume`/`VolumeSource` elsewhere in this file.
                (
                    1,
                    (
                        "__probeHandler".into(),
                        FieldType::FlattenedMessage("ProbeHandler".into()),
                    ),
                ),
                (2, ("initialDelaySeconds".into(), FieldType::Int)),
                (3, ("timeoutSeconds".into(), FieldType::Int)),
                (4, ("periodSeconds".into(), FieldType::Int)),
                (5, ("successThreshold".into(), FieldType::Int)),
                (6, ("failureThreshold".into(), FieldType::Int)),
                (7, ("terminationGracePeriodSeconds".into(), FieldType::Int)),
            ]),
        }
    }

    fn probe_handler_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (1, ("exec".into(), FieldType::Message("ExecAction".into()))),
                (
                    2,
                    ("httpGet".into(), FieldType::Message("HTTPGetAction".into())),
                ),
                (
                    3,
                    (
                        "tcpSocket".into(),
                        FieldType::Message("TCPSocketAction".into()),
                    ),
                ),
                (4, ("grpc".into(), FieldType::Message("GRPCAction".into()))),
            ]),
        }
    }

    fn pod_security_context_schema() -> MessageSchema {
        MessageSchema {
            fields: HashMap::from([
                (
                    1,
                    (
                        "seLinuxOptions".into(),
                        FieldType::Message("SELinuxOptions".into()),
                    ),
                ),
                (2, ("runAsUser".into(), FieldType::Int)),
                (3, ("runAsNonRoot".into(), FieldType::Bool)),
                (
                    4,
                    (
                        "supplementalGroups".into(),
                        FieldType::Repeated(Box::new(FieldType::Int)),
                    ),
                ),
                (5, ("fsGroup".into(), FieldType::Int)),
                (6, ("runAsGroup".into(), FieldType::Int)),
                (
                    7,
                    (
                        "sysctls".into(),
                        FieldType::Repeated(Box::new(FieldType::Message("Sysctl".into()))),
                    ),
                ),
                (9, ("fsGroupChangePolicy".into(), FieldType::String)),
                (
                    10,
                    (
                        "seccompProfile".into(),
                        FieldType::Message("SeccompProfile".into()),
                    ),
                ),
                (
                    12,
                    (
                        "appArmorProfile".into(),
                        FieldType::Message("AppArmorProfile".into()),
                    ),
                ),
                (13, ("supplementalGroupsPolicy".into(), FieldType::String)),
            ]),
        }
    }

    /// Decode a protobuf message to JSON using the schema for the given message type.
    /// Returns None if the message type is not in the registry.
    pub fn decode_message(&self, msg_type: &str, data: &[u8]) -> Option<Value> {
        let schema = self.schemas.get(msg_type)?;
        Some(self.decode_with_schema(schema, data))
    }

    /// Decode protobuf bytes using a specific schema
    fn decode_with_schema(&self, schema: &MessageSchema, data: &[u8]) -> Value {
        let mut obj = Map::new();
        let mut repeated_fields: HashMap<String, Vec<Value>> = HashMap::new();
        let mut pos = 0;

        while pos < data.len() {
            // Read tag as varint
            let (tag, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            let field_num = (tag >> 3) as u32;
            let wire_type = (tag & 0x07) as u8;

            match wire_type {
                WIRE_VARINT => {
                    let (value, new_pos) = match read_varint(data, pos) {
                        Some(v) => v,
                        None => break,
                    };
                    pos = new_pos;

                    if let Some((name, field_type)) = schema.fields.get(&field_num) {
                        let json_val = match field_type {
                            FieldType::Bool => Value::Bool(value != 0),
                            FieldType::Int => json!(value as i64),
                            _ => json!(value as i64),
                        };
                        match field_type {
                            FieldType::Repeated(_) => {
                                repeated_fields
                                    .entry(name.clone())
                                    .or_default()
                                    .push(json_val);
                            }
                            _ => {
                                obj.insert(name.clone(), json_val);
                            }
                        }
                    }
                }
                WIRE_64BIT => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    let value = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    if let Some((name, _)) = schema.fields.get(&field_num) {
                        obj.insert(name.clone(), json!(value));
                    }
                }
                WIRE_LENGTH_DELIMITED => {
                    let (len, new_pos) = match read_varint(data, pos) {
                        Some(v) => v,
                        None => break,
                    };
                    pos = new_pos;
                    let len = len as usize;
                    if pos + len > data.len() {
                        break;
                    }
                    let field_data = &data[pos..pos + len];
                    pos += len;

                    if let Some((name, field_type)) = schema.fields.get(&field_num) {
                        let json_val = self.decode_field_value(field_type, field_data);

                        match field_type {
                            FieldType::Repeated(_) => {
                                repeated_fields
                                    .entry(name.clone())
                                    .or_default()
                                    .push(json_val);
                            }
                            FieldType::StringMap => {
                                // Maps are encoded as repeated MapEntry messages.
                                // Each MapEntry has field 1 (key) and field 2 (value).
                                let (key, val) = decode_map_entry(field_data);
                                let map = obj
                                    .entry(name.clone())
                                    .or_insert_with(|| Value::Object(Map::new()));
                                if let Value::Object(ref mut m) = map {
                                    m.insert(key, Value::String(val));
                                }
                            }
                            FieldType::QuantityMap => {
                                // map<string, resource.Quantity> — the value is
                                // itself a nested Quantity message, not a plain
                                // string; unwrap it (see decode_quantity_map_entry).
                                let (key, val) = decode_quantity_map_entry(field_data);
                                let map = obj
                                    .entry(name.clone())
                                    .or_insert_with(|| Value::Object(Map::new()));
                                if let Value::Object(ref mut m) = map {
                                    m.insert(key, Value::String(val));
                                }
                            }
                            FieldType::MessageMap(ref msg_type) => {
                                // map<string, Message> — decode MapEntry with message value
                                let (key, val) =
                                    self.decode_message_map_entry(msg_type, field_data);
                                let map = obj
                                    .entry(name.clone())
                                    .or_insert_with(|| Value::Object(Map::new()));
                                if let Value::Object(ref mut m) = map {
                                    m.insert(key, val);
                                }
                            }
                            FieldType::FlattenedMessage(ref msg_type) => {
                                // Decode the nested message, then merge its keys
                                // directly into the parent object — matching a
                                // real k8s Go struct embedded with `json:",inline"`.
                                if let Some(Value::Object(inner)) =
                                    self.decode_message(msg_type, field_data)
                                {
                                    for (k, v) in inner {
                                        obj.insert(k, v);
                                    }
                                }
                            }
                            _ => {
                                obj.insert(name.clone(), json_val);
                            }
                        }
                    }
                }
                WIRE_32BIT => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    let value = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    if let Some((name, _)) = schema.fields.get(&field_num) {
                        obj.insert(name.clone(), json!(value));
                    }
                }
                _ => break,
            }
        }

        // Insert accumulated repeated fields
        for (name, values) in repeated_fields {
            obj.insert(name, Value::Array(values));
        }

        Value::Object(obj)
    }

    /// Decode a single field value based on its type
    fn decode_field_value(&self, field_type: &FieldType, data: &[u8]) -> Value {
        match field_type {
            FieldType::String => Value::String(String::from_utf8_lossy(data).to_string()),
            FieldType::Bytes => {
                use base64::Engine;
                Value::String(base64::engine::general_purpose::STANDARD.encode(data))
            }
            FieldType::Message(msg_type) => {
                if msg_type == "Time" {
                    // K8s Time is a Timestamp proto — decode to RFC3339 string
                    return decode_timestamp(data);
                }
                match self.decode_message(msg_type, data) {
                    Some(v) => v,
                    None => {
                        // Unknown message type — try to decode generically
                        debug!("Unknown proto message type: {}", msg_type);
                        Value::Object(Map::new())
                    }
                }
            }
            FieldType::Int => {
                // Length-delimited int is unusual — treat as a submessage or packed repeated
                if let Some((val, _)) = read_varint(data, 0) {
                    json!(val as i64)
                } else {
                    Value::Null
                }
            }
            FieldType::Bool => {
                if data.first() == Some(&1) {
                    Value::Bool(true)
                } else {
                    Value::Bool(false)
                }
            }
            FieldType::Repeated(inner) => {
                // Single element of a repeated field (not packed)
                self.decode_field_value(inner, data)
            }
            FieldType::StringMap => {
                // Should be handled at the caller level as MapEntry
                Value::Object(Map::new())
            }
            FieldType::QuantityMap => {
                // Should be handled at the caller level as a Quantity MapEntry
                Value::Object(Map::new())
            }
            FieldType::MessageMap(_) => {
                // Should be handled at the caller level as MessageMapEntry
                Value::Object(Map::new())
            }
            FieldType::FlattenedMessage(_) => {
                // Should be handled at the caller level, merged into the parent
                Value::Object(Map::new())
            }
            FieldType::IntOrString => {
                // K8s IntOrString: in protobuf, encoded as a message with
                // field 1 (type: int32), field 2 (intVal: int32), field 3 (strVal: string)
                decode_int_or_string(data)
            }
            FieldType::Quantity => Value::String(decode_quantity_message(data)),
            FieldType::JsonRaw => {
                // K8s JSON type: a message with field 1 = bytes containing raw JSON.
                // Decode the message to extract the raw bytes, then parse as JSON.
                let mut pos = 0;
                while pos < data.len() {
                    let (tag, new_pos) = match read_varint(data, pos) {
                        Some(v) => v,
                        None => break,
                    };
                    pos = new_pos;
                    let field_num = (tag >> 3) as u32;
                    let wire_type = (tag & 0x07) as u8;
                    if wire_type == WIRE_LENGTH_DELIMITED && field_num == 1 {
                        // field 1: raw bytes containing JSON
                        let (len, new_pos) = match read_varint(data, pos) {
                            Some(v) => v,
                            None => break,
                        };
                        pos = new_pos;
                        let len = len as usize;
                        if pos + len <= data.len() {
                            let raw = &data[pos..pos + len];
                            if let Ok(v) = serde_json::from_slice(raw) {
                                return v;
                            }
                            // If not valid JSON, return as string
                            return Value::String(String::from_utf8_lossy(raw).to_string());
                        }
                    } else {
                        // Skip unknown fields
                        match wire_type {
                            WIRE_VARINT => {
                                let _ = read_varint(data, pos).map(|(_, p)| pos = p);
                            }
                            WIRE_64BIT => {
                                pos += 8;
                            }
                            WIRE_LENGTH_DELIMITED => {
                                if let Some((len, new_pos)) = read_varint(data, pos) {
                                    pos = new_pos + len as usize;
                                } else {
                                    break;
                                }
                            }
                            WIRE_32BIT => {
                                pos += 4;
                            }
                            _ => break,
                        }
                    }
                }
                Value::Null
            }
        }
    }

    /// Decode a protobuf map entry where value is a message type
    fn decode_message_map_entry(&self, msg_type: &str, data: &[u8]) -> (String, Value) {
        let mut key = String::new();
        let mut val = Value::Null;
        let mut pos = 0;
        while pos < data.len() {
            let (tag, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            let field_num = (tag >> 3) as u32;
            let wire_type = (tag & 0x07) as u8;
            if wire_type == WIRE_LENGTH_DELIMITED {
                let (len, new_pos) = match read_varint(data, pos) {
                    Some(v) => v,
                    None => break,
                };
                pos = new_pos;
                let len = len as usize;
                if pos + len > data.len() {
                    break;
                }
                match field_num {
                    1 => {
                        key = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
                    }
                    2 => {
                        val = self
                            .decode_message(msg_type, &data[pos..pos + len])
                            .unwrap_or(Value::Null);
                    }
                    _ => {}
                }
                pos += len;
            } else if wire_type == WIRE_VARINT {
                let (_, new_pos) = match read_varint(data, pos) {
                    Some(v) => v,
                    None => break,
                };
                pos = new_pos;
            } else {
                break;
            }
        }
        (key, val)
    }

    /// Decode a full K8s protobuf-encoded resource (with k8s\0 prefix) to JSON.
    /// Returns (apiVersion, kind, json_bytes) on success.
    pub fn decode_k8s_resource(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 5 || &data[0..4] != b"k8s\0" {
            return None;
        }
        let envelope = &data[4..];

        // Parse the Unknown envelope to get TypeMeta and raw bytes
        let mut api_version = String::new();
        let mut kind = String::new();
        let mut raw_bytes: Option<&[u8]> = None;

        let mut pos = 0;
        while pos < envelope.len() {
            let (tag, new_pos) = read_varint(envelope, pos)?;
            pos = new_pos;
            let field_num = (tag >> 3) as u32;
            let wire_type = (tag & 0x07) as u8;

            if wire_type == WIRE_LENGTH_DELIMITED {
                let (len, new_pos) = read_varint(envelope, pos)?;
                pos = new_pos;
                let len = len as usize;
                if pos + len > envelope.len() {
                    break;
                }
                let field_data = &envelope[pos..pos + len];
                pos += len;

                match field_num {
                    1 => {
                        // TypeMeta
                        let mut tp = 0;
                        while tp < field_data.len() {
                            let (t, ntp) = read_varint(field_data, tp)?;
                            tp = ntp;
                            let fnum = (t >> 3) as u32;
                            let wt = (t & 0x07) as u8;
                            if wt == WIRE_LENGTH_DELIMITED {
                                let (slen, ntp) = read_varint(field_data, tp)?;
                                tp = ntp;
                                let slen = slen as usize;
                                if tp + slen <= field_data.len() {
                                    if let Ok(s) = std::str::from_utf8(&field_data[tp..tp + slen]) {
                                        match fnum {
                                            1 => api_version = s.to_string(),
                                            2 => kind = s.to_string(),
                                            _ => {}
                                        }
                                    }
                                }
                                tp += slen;
                            } else if wt == WIRE_VARINT {
                                let (_, ntp) = read_varint(field_data, tp)?;
                                tp = ntp;
                            } else {
                                break;
                            }
                        }
                    }
                    2 => {
                        // raw bytes — the serialized resource
                        raw_bytes = Some(field_data);
                    }
                    // field 3 = contentEncoding (string, skip)
                    // field 4 = contentType (string, skip)
                    _ => {}
                }
            } else if wire_type == WIRE_VARINT {
                let (_, new_pos) = read_varint(envelope, pos)?;
                pos = new_pos;
            } else if wire_type == WIRE_64BIT {
                pos += 8;
            } else if wire_type == WIRE_32BIT {
                pos += 4;
            } else {
                break;
            }
        }

        if api_version.is_empty() || kind.is_empty() {
            return None;
        }

        let raw = raw_bytes?;

        // Check if raw is already JSON
        if !raw.is_empty() && (raw[0] == b'{' || raw[0] == b'[') {
            return Some(raw.to_vec());
        }

        // Look up the schema for this kind
        if let Some(json_obj) = self.decode_message(&kind, raw) {
            // Add apiVersion and kind to the JSON
            let result = match json_obj {
                Value::Object(m) => {
                    // Insert apiVersion/kind at the top (they're part of TypeMeta, not the raw message)
                    let mut ordered = Map::new();
                    ordered.insert("apiVersion".into(), Value::String(api_version));
                    ordered.insert("kind".into(), Value::String(kind));
                    // Merge the decoded fields
                    for (k, v) in m {
                        ordered.insert(k, v);
                    }
                    Value::Object(ordered)
                }
                other => other,
            };

            serde_json::to_vec(&result).ok()
        } else {
            warn!(
                "No schema found for kind '{}', cannot decode protobuf",
                kind
            );
            None
        }
    }
}

// ========== Helper functions ==========

/// Read a varint from data starting at pos. Returns (value, new_pos).
fn read_varint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let b = data[pos] as u64;
        pos += 1;
        value |= (b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Decode a protobuf map entry (field 1 = key, field 2 = value, both strings)
fn decode_map_entry(data: &[u8]) -> (String, String) {
    let mut key = String::new();
    let mut val = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, new_pos) = match read_varint(data, pos) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if wire_type == WIRE_LENGTH_DELIMITED {
            let (len, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            let len = len as usize;
            if pos + len > data.len() {
                break;
            }
            if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
                match field_num {
                    1 => key = s.to_string(),
                    2 => val = s.to_string(),
                    _ => {}
                }
            }
            pos += len;
        } else if wire_type == WIRE_VARINT {
            let (_, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
        } else {
            break;
        }
    }
    (key, val)
}

/// Decode a `resource.Quantity` protobuf message (`{ optional string string = 1; }`)
/// into its plain string form (e.g. "8Gi", "500m").
fn decode_quantity_message(data: &[u8]) -> String {
    let mut pos = 0;
    while pos < data.len() {
        let (tag, new_pos) = match read_varint(data, pos) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if wire_type == WIRE_LENGTH_DELIMITED {
            let (len, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            let len = len as usize;
            if pos + len > data.len() {
                break;
            }
            if field_num == 1 {
                return String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            }
            pos += len;
        } else if wire_type == WIRE_VARINT {
            let (_, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
        } else {
            break;
        }
    }
    String::new()
}

/// Decode a MapEntry whose value is a `resource.Quantity` message (used for
/// ResourceList-typed fields: limits/requests/overhead) — key stays a plain
/// string, value is unwrapped via `decode_quantity_message` into its plain
/// string form rather than being treated as raw UTF-8 bytes.
fn decode_quantity_map_entry(data: &[u8]) -> (String, String) {
    let mut key = String::new();
    let mut val = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, new_pos) = match read_varint(data, pos) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if wire_type == WIRE_LENGTH_DELIMITED {
            let (len, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            let len = len as usize;
            if pos + len > data.len() {
                break;
            }
            match field_num {
                1 => key = String::from_utf8_lossy(&data[pos..pos + len]).to_string(),
                2 => val = decode_quantity_message(&data[pos..pos + len]),
                _ => {}
            }
            pos += len;
        } else if wire_type == WIRE_VARINT {
            let (_, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
        } else {
            break;
        }
    }
    (key, val)
}

/// Decode a K8s Timestamp protobuf to RFC3339 string
fn decode_timestamp(data: &[u8]) -> Value {
    let mut seconds: i64 = 0;
    let mut nanos: i32 = 0;
    let mut pos = 0;
    while pos < data.len() {
        let (tag, new_pos) = match read_varint(data, pos) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if wire_type == WIRE_VARINT {
            let (val, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            match field_num {
                1 => seconds = val as i64,
                2 => nanos = val as i32,
                _ => {}
            }
        } else {
            break;
        }
    }
    if seconds == 0 && nanos == 0 {
        return Value::Null;
    }
    // Convert to RFC3339
    let dt = chrono::DateTime::from_timestamp(seconds, nanos as u32);
    match dt {
        Some(dt) => Value::String(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        None => Value::String(format!("{}s", seconds)),
    }
}

/// Decode K8s IntOrString protobuf message
/// Proto: message IntOrString { int64 type = 1; int32 intVal = 2; string strVal = 3; }
fn decode_int_or_string(data: &[u8]) -> Value {
    let mut kind: i64 = 0; // 0 = int, 1 = string
    let mut int_val: i64 = 0;
    let mut str_val = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let (tag, new_pos) = match read_varint(data, pos) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if wire_type == WIRE_VARINT {
            let (val, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            match field_num {
                1 => kind = val as i64,
                2 => int_val = val as i64,
                _ => {}
            }
        } else if wire_type == WIRE_LENGTH_DELIMITED {
            let (len, new_pos) = match read_varint(data, pos) {
                Some(v) => v,
                None => break,
            };
            pos = new_pos;
            let len = len as usize;
            if pos + len > data.len() {
                break;
            }
            if field_num == 3 {
                str_val = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            }
            pos += len;
        } else {
            break;
        }
    }
    if kind == 1 {
        Value::String(str_val)
    } else {
        json!(int_val)
    }
}

// Placeholder schemas for types we handle but don't need full detail
// These are empty — the decoder treats unknown fields as ignored
impl ProtoRegistry {
    // Additional placeholder types that we reference but don't need full schemas for
}

#[cfg(test)]
mod tests {
    /// PodSpec protobuf field numbers, pinned against upstream
    /// `kubernetes/api/core/v1/generated.proto`.
    ///
    /// These are wire-format identity: a protobuf client sends field *numbers*,
    /// not names, so a number that disagrees with upstream silently decodes one
    /// field as another or drops it entirely. Nothing else in this codebase can
    /// catch that — the result is a structurally valid object with the wrong
    /// contents, which is exactly the failure mode that made the `restartPolicy`
    /// outage (ISSUES.md #69) take seventeen hours to notice.
    ///
    /// The schema was wrong from field 23 onward: `hostAliases` was numbered 24,
    /// and everything after it shifted. `hostAliases` is not an arbitrary
    /// example — this harness has no CoreDNS, so it pins database and identity
    /// addresses through exactly that field.
    #[test]
    fn pod_spec_field_numbers_match_upstream() {
        let schema = super::ProtoRegistry::pod_spec_schema();
        // Only the fields whose numbering was verified against upstream. A
        // partial pin that is correct beats a complete one that is guessed.
        for (number, name) in [
            (1u32, "volumes"),
            (2, "containers"),
            (3, "restartPolicy"),
            (6, "dnsPolicy"),
            (20, "initContainers"),
            (22, "tolerations"),
            (23, "hostAliases"),
            (24, "priorityClassName"),
            (25, "priority"),
            (26, "dnsConfig"),
            (27, "shareProcessNamespace"),
            (28, "readinessGates"),
            (29, "runtimeClassName"),
            (30, "enableServiceLinks"),
            (32, "overhead"),
            (33, "topologySpreadConstraints"),
            (34, "ephemeralContainers"),
            (35, "setHostnameAsFQDN"),
            (36, "os"),
            (38, "schedulingGates"),
            (39, "resourceClaims"),
        ] {
            let actual = schema.fields
                .get(&number)
                .unwrap_or_else(|| panic!("PodSpec field {number} ({name}) is missing"));
            assert_eq!(
                actual.0, name,
                "PodSpec field {number} should be {name}, found {}",
                actual.0
            );
        }
    }


    use super::*;

    #[test]
    fn test_read_varint() {
        assert_eq!(read_varint(&[0x08], 0), Some((8, 1)));
        assert_eq!(read_varint(&[0x96, 0x01], 0), Some((150, 2)));
        assert_eq!(read_varint(&[0xac, 0x02], 0), Some((300, 2)));
    }

    #[test]
    fn test_decode_simple_message() {
        let registry = ProtoRegistry::new();
        // A simple LabelSelector with matchLabels = {"app": "nginx"}
        // Encoded as: field 1 (matchLabels) = MapEntry { key="app", value="nginx" }
        // MapEntry: field 1 (key) = "app", field 2 (value) = "nginx"
        // field 1 tag = 0x0a (field 1, wire type 2)
        let map_entry = {
            let mut buf = Vec::new();
            // key field: tag=0x0a, len=3, "app"
            buf.extend_from_slice(&[0x0a, 0x03]);
            buf.extend_from_slice(b"app");
            // value field: tag=0x12, len=5, "nginx"
            buf.extend_from_slice(&[0x12, 0x05]);
            buf.extend_from_slice(b"nginx");
            buf
        };

        let mut label_selector = Vec::new();
        // matchLabels field: tag=0x0a (field 1, wire 2), length, then map_entry
        label_selector.push(0x0a);
        label_selector.push(map_entry.len() as u8);
        label_selector.extend_from_slice(&map_entry);

        let result = registry.decode_message("LabelSelector", &label_selector);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(
            val.pointer("/matchLabels/app"),
            Some(&Value::String("nginx".into()))
        );
    }

    #[test]
    fn test_decode_owner_reference_real_field_numbers() {
        // Regression test for a real bug (found live-testing a real
        // operator, CloudNativePG, creating a Secret with an
        // ownerReference): the schema previously had apiVersion=1,
        // kind=2, with no mapping for apiVersion's real field (5) —
        // backwards from upstream `k8s.io/apimachinery`'s actual
        // OwnerReference proto (verified against generated.proto:
        // kind=1, name=3, uid=4, apiVersion=5, controller=6,
        // blockOwnerDeletion=7; field 2 does not exist).
        let registry = ProtoRegistry::new();
        let mut owner_ref = Vec::new();
        // kind (field 1, string) = "Deployment"
        owner_ref.push(0x0a);
        owner_ref.push(10);
        owner_ref.extend_from_slice(b"Deployment");
        // name (field 3, string) = "my-deploy"
        owner_ref.push(0x1a);
        owner_ref.push(9);
        owner_ref.extend_from_slice(b"my-deploy");
        // uid (field 4, string) = "abc-123"
        owner_ref.push(0x22);
        owner_ref.push(7);
        owner_ref.extend_from_slice(b"abc-123");
        // apiVersion (field 5, string) = "apps/v1"
        owner_ref.push(0x2a);
        owner_ref.push(7);
        owner_ref.extend_from_slice(b"apps/v1");
        // controller (field 6, varint bool) = true
        owner_ref.push(0x30);
        owner_ref.push(0x01);

        let result = registry.decode_message("OwnerReference", &owner_ref);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val.get("kind"), Some(&Value::String("Deployment".into())));
        assert_eq!(
            val.get("apiVersion"),
            Some(&Value::String("apps/v1".into()))
        );
        assert_eq!(val.get("name"), Some(&Value::String("my-deploy".into())));
        assert_eq!(val.get("uid"), Some(&Value::String("abc-123".into())));
        assert_eq!(val.get("controller"), Some(&Value::Bool(true)));
    }

    #[test]
    fn test_decode_lease_uses_its_own_schema_not_crd_fallback() {
        // Regression test for a real bug (found live chasing a
        // `guts-shell-bundle` blocker: a client-go leader-election Lease
        // renewal from a real operator, CloudNativePG): with no "Lease"
        // entry in the schema registry at all, decode_k8s_resource()
        // returned None for every Lease, and the caller (middleware.rs)
        // fell through to the generic CRD-shaped fallback decoder — which
        // applies CustomResourceDefinitionSpec's own field layout
        // (group/names/scope/versions) to whatever bytes it's given,
        // regardless of the real kind. Confirmed live via temporary raw-JSON
        // logging: a real Lease decoded as
        // `{"spec":{"group":"<holderIdentity string>","names":{...},
        // "scope":"<raw protobuf bytes leaking into a string field>",
        // "versions":[...]}}` — garbage in every field. Field numbers here
        // verified against the real upstream
        // k8s.io/api/coordination/v1 generated.proto.
        let registry = ProtoRegistry::new();
        let mut lease_spec = Vec::new();
        // holderIdentity (field 1, string)
        lease_spec.push(0x0a);
        lease_spec.push(20);
        lease_spec.extend_from_slice(b"cnpg-operator-abc123");
        // leaseDurationSeconds (field 2, varint) = 15
        lease_spec.push(0x10);
        lease_spec.push(15);
        // leaseTransitions (field 5, varint) = 3
        lease_spec.push(0x28);
        lease_spec.push(3);

        let result = registry.decode_message("LeaseSpec", &lease_spec);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(
            val.get("holderIdentity"),
            Some(&Value::String("cnpg-operator-abc123".into())),
            "must decode the real holderIdentity, not a CRD-shaped 'group' field; got {:?}",
            val
        );
        assert_eq!(val.get("leaseDurationSeconds"), Some(&Value::Number(15.into())));
        assert_eq!(val.get("leaseTransitions"), Some(&Value::Number(3.into())));
        // The CRD-fallback bug's telltale signature: these fields must never
        // appear on a decoded LeaseSpec.
        assert!(val.get("group").is_none());
        assert!(val.get("names").is_none());
        assert!(val.get("versions").is_none());
    }

    #[test]
    fn test_decode_pod_disruption_budget_uses_its_own_schema_not_crd_fallback() {
        // Regression test for a real bug found live continuing the same
        // guts-shell-bundle/CNPG investigation as the Lease bug above: once the
        // Service-creation bug was fixed, CNPG's Cluster reconcile moved on to
        // creating a PodDisruptionBudget and hit the identical symptom — no
        // "PodDisruptionBudget" entry existed in the schema registry at all, so
        // decode_k8s_resource() fell through to the generic CRD-fallback
        // decoder for every protobuf-encoded PodDisruptionBudget write.
        let registry = ProtoRegistry::new();

        // Build a real-shaped PodDisruptionBudgetSpec:
        // field 2 (selector, LabelSelector message) with one matchLabels entry,
        // field 4 (unhealthyPodEvictionPolicy, string).
        let mut match_labels_entry = Vec::new();
        match_labels_entry.push(0x0a); // key field 1, wire type 2
        match_labels_entry.push(3);
        match_labels_entry.extend_from_slice(b"app");
        match_labels_entry.push(0x12); // value field 2, wire type 2
        match_labels_entry.push(8);
        match_labels_entry.extend_from_slice(b"postgres");

        let mut label_selector = Vec::new();
        label_selector.push(0x0a); // matchLabels field 1, wire type 2
        label_selector.push(match_labels_entry.len() as u8);
        label_selector.extend_from_slice(&match_labels_entry);

        let mut pdb_spec = Vec::new();
        pdb_spec.push(0x12); // selector field 2, wire type 2
        pdb_spec.push(label_selector.len() as u8);
        pdb_spec.extend_from_slice(&label_selector);
        pdb_spec.push(0x22); // unhealthyPodEvictionPolicy field 4, wire type 2
        pdb_spec.push(15);
        pdb_spec.extend_from_slice(b"IfHealthyBudget");

        let result = registry.decode_message("PodDisruptionBudgetSpec", &pdb_spec);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(
            val.get("selector").and_then(|s| s.get("matchLabels")),
            Some(&serde_json::json!({"app": "postgres"})),
            "must decode the real selector.matchLabels, not a CRD-shaped fallback; got {:?}",
            val
        );
        assert_eq!(
            val.get("unhealthyPodEvictionPolicy"),
            Some(&Value::String("IfHealthyBudget".into()))
        );
        // The CRD-fallback bug's telltale signature: these fields must never
        // appear on a decoded PodDisruptionBudgetSpec.
        assert!(val.get("group").is_none());
        assert!(val.get("names").is_none());
        assert!(val.get("versions").is_none());
    }

    #[test]
    fn test_decode_role_uses_its_own_schema_not_crd_fallback() {
        // Regression test for a real bug found live in the same investigation
        // as Lease and PodDisruptionBudget above: immediately after those two
        // were fixed, CNPG's Cluster reconcile moved on to creating a
        // per-cluster Role and hit the identical symptom — no "Role"/
        // "PolicyRule" entries existed in the schema registry at all. Field
        // numbers verified against the real upstream
        // k8s.io/api/rbac/v1 generated.proto.
        let registry = ProtoRegistry::new();

        let mut rule = Vec::new();
        // verbs (field 1, repeated string) — one entry "get"
        rule.push(0x0a);
        rule.push(3);
        rule.extend_from_slice(b"get");
        // resources (field 3, repeated string) — one entry "secrets"
        rule.push(0x1a);
        rule.push(7);
        rule.extend_from_slice(b"secrets");

        let mut role = Vec::new();
        // rules (field 2, repeated message)
        role.push(0x12);
        role.push(rule.len() as u8);
        role.extend_from_slice(&rule);

        let result = registry.decode_message("Role", &role);
        assert!(result.is_some());
        let val = result.unwrap();
        let rules = val.get("rules").and_then(|r| r.as_array()).cloned();
        assert!(rules.is_some(), "expected a rules array; got {:?}", val);
        let rules = rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].get("verbs"),
            Some(&serde_json::json!(["get"])),
            "must decode the real verbs, not a CRD-shaped fallback; got {:?}",
            val
        );
        assert_eq!(rules[0].get("resources"), Some(&serde_json::json!(["secrets"])));
        // The CRD-fallback bug's telltale signature: these fields must never
        // appear on a decoded Role.
        assert!(val.get("group").is_none());
        assert!(val.get("names").is_none());
        assert!(val.get("versions").is_none());
    }

    /// Regression test for a real bug found live in the same investigation,
    /// right after the PodDisruptionBudget/Role fixes above: CNPG's Cluster
    /// reconcile created the primary instance's PVC, and its `spec.resources.
    /// requests.storage` came back as `"\n\x038Gi"` instead of `"8Gi"`.
    /// `VolumeResourceRequirements.limits`/`.requests` (and the identical
    /// `ResourceRequirements`/`overhead` fields elsewhere) are
    /// `map<string, resource.Quantity>`, not `map<string, string>` — each map
    /// entry's *value* is itself a nested `Quantity` message
    /// (`{ optional string string = 1; }`). Treating that value's raw message
    /// bytes as a plain UTF-8 string (the pre-fix `StringMap` behavior) leaks
    /// the wrapping message's own tag (`\n` = 0x0a) and length (`\x03`) bytes
    /// straight into the string.
    #[test]
    fn test_decode_quantity_map_unwraps_nested_quantity_message() {
        let registry = ProtoRegistry::new();

        // A Quantity message wrapping the string "8Gi"
        let mut quantity = vec![0x0a, 3]; // field 1, wire type 2, length 3
        quantity.extend_from_slice(b"8Gi");

        // A MapEntry: field 1 = key "storage", field 2 = the Quantity message above
        let mut map_entry = Vec::new();
        map_entry.push(0x0a); // key field 1, wire type 2
        map_entry.push(7);
        map_entry.extend_from_slice(b"storage");
        map_entry.push(0x12); // value field 2, wire type 2
        map_entry.push(quantity.len() as u8);
        map_entry.extend_from_slice(&quantity);

        // VolumeResourceRequirements.requests (field 2, repeated MapEntry)
        let mut requirements = Vec::new();
        requirements.push(0x12); // field 2, wire type 2
        requirements.push(map_entry.len() as u8);
        requirements.extend_from_slice(&map_entry);

        let result = registry.decode_message("VolumeResourceRequirements", &requirements);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(
            val.get("requests"),
            Some(&serde_json::json!({"storage": "8Gi"})),
            "must unwrap the nested Quantity message to a plain string, not leak its tag/length bytes; got {:?}",
            val
        );
    }

    /// Regression test for a real bug found live continuing the same
    /// investigation, right after the Quantity fix above: CNPG's initdb Job
    /// pod template has an `emptyDir` scratch volume, and it decoded as a
    /// broken, empty `hostPath` object (missing its required `path`), which
    /// then failed axum's `Json<Job>` extraction. Real k8s's `Volume` message
    /// wraps every source type in a nested `VolumeSource` sub-message at
    /// field 2 — the old schema wrongly treated Volume's OWN field 2 as
    /// directly being `hostPath`.
    #[test]
    fn test_decode_volume_flattens_nested_volume_source() {
        let registry = ProtoRegistry::new();

        // EmptyDirVolumeSource { medium: "Memory" }
        let mut empty_dir = vec![0x0a, 6]; // field 1, wire type 2, length 6
        empty_dir.extend_from_slice(b"Memory");

        // VolumeSource { emptyDir = 2: <empty_dir> }
        let mut volume_source = Vec::new();
        volume_source.push(0x12); // field 2, wire type 2
        volume_source.push(empty_dir.len() as u8);
        volume_source.extend_from_slice(&empty_dir);

        // Volume { name = 1: "scratch-data", volumeSource = 2: <volume_source> }
        let mut volume = Vec::new();
        volume.push(0x0a); // field 1, wire type 2
        volume.push(12);
        volume.extend_from_slice(b"scratch-data");
        volume.push(0x12); // field 2, wire type 2
        volume.push(volume_source.len() as u8);
        volume.extend_from_slice(&volume_source);

        let result = registry.decode_message("Volume", &volume);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val.get("name"), Some(&Value::String("scratch-data".into())));
        assert_eq!(
            val.get("emptyDir"),
            Some(&serde_json::json!({"medium": "Memory"})),
            "must flatten VolumeSource's emptyDir onto Volume directly, not decode it as a broken hostPath; got {:?}",
            val
        );
        // The bug's telltale signature: a spurious, empty hostPath object
        // (missing its required `path`) must never appear.
        assert!(val.get("hostPath").is_none());
    }

    /// Regression test for a real bug found live getting CNPG's own instance
    /// pod running: Go's `corev1.Probe` embeds `ProbeHandler` via
    /// `json:",inline"` — exec/httpGet/tcpSocket appear directly on the
    /// probe object in JSON, matching this crate's own `Probe` struct.
    /// Decoding `handler` as a literal nested message (rather than
    /// flattening it) produced JSON shaped like `{"handler": {"httpGet":
    /// ...}}`, which doesn't match the Rust struct's fields at all — this
    /// silently failed strict-field-validation with "unknown field
    /// ...handler" on every real client's Pod create, since the decoded
    /// `handler` key never survives a deserialize+reserialize round-trip
    /// through `Probe`.
    #[test]
    fn test_decode_probe_flattens_nested_probe_handler() {
        let registry = ProtoRegistry::new();

        // HTTPGetAction { path = 1: "/healthz" }
        let mut http_get = vec![0x0a, 8];
        http_get.extend_from_slice(b"/healthz");

        // ProbeHandler { httpGet = 2: <http_get> }
        let mut handler = vec![0x12, http_get.len() as u8];
        handler.extend_from_slice(&http_get);

        // Probe { handler = 1: <handler> }
        let mut probe = vec![0x0a, handler.len() as u8];
        probe.extend_from_slice(&handler);

        let result = registry.decode_message("Probe", &probe);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(
            val.get("httpGet"),
            Some(&serde_json::json!({"path": "/healthz"})),
            "must flatten ProbeHandler's httpGet onto Probe directly, matching corev1.Probe's json:\",inline\"; got {:?}",
            val
        );
        // The bug's telltale signature: a nested "handler" wrapper key,
        // which this crate's own Probe struct has no field for at all.
        assert!(val.get("handler").is_none());
    }

    /// Regression test for a real bug found live in the same Job/pod-template
    /// investigation as the Volume fix above: a container's
    /// `env[].valueFrom.secretKeyRef` decoded with `name` set to
    /// `"\n\x17platform-db-cluster-app"` instead of
    /// `"platform-db-cluster-app"`. Real k8s's `SecretKeySelector` (and
    /// `ConfigMapKeySelector`/`SecretEnvSource`/`ConfigMapEnvSource`) embed
    /// `LocalObjectReference` FLATTENED at field 1 — treating that field as a
    /// plain string (the pre-fix behavior) decoded the wrapping message's own
    /// tag+length bytes straight into the name, the same bug class as the
    /// Volume/VolumeSource fix, just recurring in a different family of
    /// embedded types.
    #[test]
    fn test_decode_secret_key_selector_flattens_local_object_reference() {
        let registry = ProtoRegistry::new();

        // LocalObjectReference { name: "platform-db-cluster-app" }
        let mut local_ref = vec![0x0a, 23]; // field 1, wire type 2, length 23
        local_ref.extend_from_slice(b"platform-db-cluster-app");

        // SecretKeySelector { localObjectReference = 1: <local_ref>, key = 2: "username" }
        let mut selector = Vec::new();
        selector.push(0x0a); // field 1, wire type 2
        selector.push(local_ref.len() as u8);
        selector.extend_from_slice(&local_ref);
        selector.push(0x12); // field 2, wire type 2
        selector.push(8);
        selector.extend_from_slice(b"username");

        let result = registry.decode_message("SecretKeySelector", &selector);
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(
            val.get("name"),
            Some(&Value::String("platform-db-cluster-app".into())),
            "must flatten LocalObjectReference's name directly, not leak the wrapping message's tag/length bytes; got {:?}",
            val
        );
        assert_eq!(val.get("key"), Some(&Value::String("username".into())));
    }

    #[test]
    fn test_decode_deployment_spec_with_template() {
        let registry = ProtoRegistry::new();

        // Build a minimal DeploymentSpec protobuf:
        // field 1 (replicas): varint 1
        // field 3 (template): PodTemplateSpec with a container
        let mut spec = Vec::new();

        // replicas = 1 (field 1, wire type 0 = varint)
        spec.push(0x08); // field 1, varint
        spec.push(0x01); // value = 1

        // Build a minimal PodTemplateSpec
        let mut template = Vec::new();
        // PodTemplateSpec.spec (field 2) = PodSpec
        let mut pod_spec = Vec::new();
        // PodSpec.containers (field 2) = repeated Container
        let mut container = Vec::new();
        // Container.name (field 1) = "test"
        container.push(0x0a); // field 1, length-delimited
        container.push(0x04); // length = 4
        container.extend_from_slice(b"test");
        // Container.image (field 2) = "nginx"
        container.push(0x12); // field 2, length-delimited
        container.push(0x05); // length = 5
        container.extend_from_slice(b"nginx");

        // PodSpec field 2 (containers)
        pod_spec.push(0x12); // field 2, length-delimited
        pod_spec.push(container.len() as u8);
        pod_spec.extend_from_slice(&container);

        // PodTemplateSpec field 2 (spec)
        template.push(0x12); // field 2, length-delimited
        template.push(pod_spec.len() as u8);
        template.extend_from_slice(&pod_spec);

        // DeploymentSpec field 3 (template)
        spec.push(0x1a); // field 3, length-delimited
        spec.push(template.len() as u8);
        spec.extend_from_slice(&template);

        let result = registry.decode_message("DeploymentSpec", &spec);
        assert!(result.is_some());
        let val = result.unwrap();

        // Verify replicas
        assert_eq!(val.get("replicas"), Some(&json!(1)));

        // Verify template exists and has containers
        let tmpl = val.get("template").expect("template should exist");
        let spec_inner = tmpl.get("spec").expect("template.spec should exist");
        let containers = spec_inner
            .get("containers")
            .expect("containers should exist");
        assert!(containers.is_array());
        let first = &containers.as_array().unwrap()[0];
        assert_eq!(first.get("name"), Some(&Value::String("test".into())));
        assert_eq!(first.get("image"), Some(&Value::String("nginx".into())));
    }
}
