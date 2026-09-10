/// Table output format support for kubectl get commands
///
/// This module implements the Table output format that kubectl uses to display
/// resources in a human-readable table format.
use rusternetes_common::types::ObjectMeta;
use serde::{Deserialize, Serialize};

/// Table is the response format for kubectl get requests with Accept: application/json;as=Table
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    /// APIVersion defines the versioned schema
    pub api_version: String,

    /// Kind is always "Table"
    pub kind: String,

    /// Standard list metadata
    pub metadata: TableMetadata,

    /// Column definitions for the table
    pub column_definitions: Vec<ColumnDefinition>,

    /// Rows of data
    pub rows: Vec<TableRow>,
}

/// Metadata for the table
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableMetadata {
    /// Resource version for the list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,

    /// Continue token for pagination
    #[serde(skip_serializing_if = "Option::is_none", rename = "continue")]
    pub continue_token: Option<String>,

    /// Remaining items count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_item_count: Option<i64>,
}

/// Column definition in the table
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnDefinition {
    /// Name of the column
    pub name: String,

    /// Type of the column (e.g., "string", "integer", "date")
    #[serde(rename = "type")]
    pub column_type: String,

    /// Format hint (e.g., "name", "date-time")
    pub format: String,

    /// Description of the column
    pub description: String,

    /// Priority determines visibility (0 = always shown)
    pub priority: i32,
}

/// Single row in the table
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableRow {
    /// Cells contain the actual data
    pub cells: Vec<serde_json::Value>,

    /// Object contains the full resource (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<serde_json::Value>,
}

impl Table {
    /// Create a new Table
    pub fn new() -> Self {
        Self {
            api_version: "meta.k8s.io/v1".to_string(),
            kind: "Table".to_string(),
            metadata: TableMetadata {
                resource_version: None,
                continue_token: None,
                remaining_item_count: None,
            },
            column_definitions: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Add a column definition
    pub fn add_column(
        mut self,
        name: &str,
        column_type: &str,
        format: &str,
        description: &str,
        priority: i32,
    ) -> Self {
        self.column_definitions.push(ColumnDefinition {
            name: name.to_string(),
            column_type: column_type.to_string(),
            format: format.to_string(),
            description: description.to_string(),
            priority,
        });
        self
    }

    /// Add a row of data
    pub fn add_row(
        mut self,
        cells: Vec<serde_json::Value>,
        object: Option<serde_json::Value>,
    ) -> Self {
        self.rows.push(TableRow { cells, object });
        self
    }

    /// Set metadata
    pub fn with_metadata(
        mut self,
        resource_version: Option<String>,
        continue_token: Option<String>,
        remaining: Option<i64>,
    ) -> Self {
        self.metadata.resource_version = resource_version;
        self.metadata.continue_token = continue_token;
        self.metadata.remaining_item_count = remaining;
        self
    }
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create a table for Pods
pub fn pods_table<T>(pods: Vec<T>, resource_version: Option<String>) -> Table
where
    T: Serialize + HasPodInfo,
{
    let mut table = Table::new()
        .add_column(
            "NAME",
            "string",
            "name",
            "Name must be unique within a namespace",
            0,
        )
        .add_column(
            "READY",
            "string",
            "",
            "The aggregate readiness state of this pod for accepting traffic",
            0,
        )
        .add_column(
            "STATUS",
            "string",
            "",
            "The aggregate state of the containers in this pod",
            0,
        )
        .add_column(
            "RESTARTS",
            "integer",
            "",
            "The number of times the containers in this pod have been restarted",
            0,
        )
        .add_column("AGE", "string", "", "Age of the pod", 0);

    for pod in pods {
        let info = pod.pod_info();
        let cells = vec![
            serde_json::Value::String(info.name),
            serde_json::Value::String(info.ready),
            serde_json::Value::String(info.status),
            serde_json::Value::Number(info.restarts.into()),
            serde_json::Value::String(info.age),
        ];
        let object = serde_json::to_value(&pod).ok();
        table = table.add_row(cells, object);
    }

    table.with_metadata(resource_version, None, None)
}

/// Helper function to create a table for generic resources with just NAME and AGE
pub fn generic_table<T>(
    resources: Vec<T>,
    resource_version: Option<String>,
    resource_kind: &str,
) -> Table
where
    T: Serialize + HasMetadata,
{
    let mut table = Table::new()
        .add_column(
            "NAME",
            "string",
            "name",
            &format!(
                "Name must be unique within a namespace for {}",
                resource_kind
            ),
            0,
        )
        .add_column(
            "AGE",
            "string",
            "",
            &format!("Age of the {}", resource_kind),
            0,
        );

    for resource in resources {
        let metadata = resource.metadata();
        let name = metadata.name.clone();
        let age = format_age(metadata);

        let cells = vec![
            serde_json::Value::String(name),
            serde_json::Value::String(age),
        ];
        let object = serde_json::to_value(&resource).ok();
        table = table.add_row(cells, object);
    }

    table.with_metadata(resource_version, None, None)
}

/// Trait for extracting metadata from resources
pub trait HasMetadata {
    fn metadata(&self) -> &ObjectMeta;
}

/// Pod-specific information for table display
pub struct PodInfo {
    pub name: String,
    pub ready: String,
    pub status: String,
    pub restarts: i32,
    pub age: String,
}

/// Trait for extracting pod information
pub trait HasPodInfo {
    fn pod_info(&self) -> PodInfo;
}

/// Format age from metadata
fn format_age(metadata: &ObjectMeta) -> String {
    if let Some(creation_time) = &metadata.creation_timestamp {
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(*creation_time);

        if duration.num_days() > 0 {
            format!("{}d", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{}h", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{}m", duration.num_minutes())
        } else {
            format!("{}s", duration.num_seconds().max(0))
        }
    } else {
        "<unknown>".to_string()
    }
}

/// Build a `Table` for a list of custom resources, using the CRD version's
/// own `additionalPrinterColumns` when declared — mirrors real Kubernetes'
/// `kubectl get <cr>` behavior, where a CRD author's declared columns fully
/// replace the generic NAME+AGE view (no automatic AGE column is added; a
/// CRD wanting one declares it explicitly, e.g. pointing at
/// `.metadata.creationTimestamp` with `type: date` — which is exactly what
/// most real-world CRDs, including CNPG's, do). Falls back to
/// [`generic_table`]'s plain NAME+AGE view when no columns are declared,
/// matching a CRD with no `additionalPrinterColumns` at all.
pub fn custom_resource_table(
    columns: Option<&[rusternetes_common::resources::CustomResourceColumnDefinition]>,
    resources: Vec<rusternetes_common::resources::CustomResource>,
    resource_version: Option<String>,
    resource_kind: &str,
) -> Table {
    let Some(columns) = columns.filter(|c| !c.is_empty()) else {
        return generic_table(resources, resource_version, resource_kind);
    };

    let mut table = Table::new().add_column(
        "NAME",
        "string",
        "name",
        &format!(
            "Name must be unique within a namespace for {}",
            resource_kind
        ),
        0,
    );
    for col in columns {
        table = table.add_column(
            &col.name,
            &col.type_,
            col.format.as_deref().unwrap_or(""),
            col.description.as_deref().unwrap_or(""),
            col.priority.unwrap_or(0),
        );
    }

    for resource in resources {
        let metadata = resource.metadata.clone();
        let object = serde_json::to_value(&resource).ok();
        let mut cells = vec![serde_json::Value::String(metadata.name.clone())];
        for col in columns {
            let value = object
                .as_ref()
                .and_then(|v| resolve_json_path(v, &col.json_path))
                .unwrap_or(serde_json::Value::Null);
            let cell = if col.type_ == "date" {
                match value.as_str() {
                    Some(_) => serde_json::Value::String(format_age(&metadata)),
                    None => serde_json::Value::String("<unknown>".to_string()),
                }
            } else {
                value
            };
            cells.push(cell);
        }
        table = table.add_row(cells, object);
    }

    table.with_metadata(resource_version, None, None)
}

/// Resolve Kubernetes' restricted JSONPath subset used by
/// `additionalPrinterColumns.jsonPath` (and `kubectl get -o
/// jsonpath=...`'s single-path form) — dot-separated field names, with an
/// optional `[<index>]` or `['<key>']`/`[<key>]` suffix per segment. Not
/// full JSONPath (no wildcards, filters, or recursive descent) — real
/// Kubernetes' own implementation is this same restricted subset.
/// `path` is expected to start with `.` (e.g. `.status.phase`); `.` alone
/// (or an empty string) resolves to the root value.
fn resolve_json_path(root: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let path = path.trim();
    if path.is_empty() || path == "." {
        return Some(root.clone());
    }
    let path = path.strip_prefix('.').unwrap_or(path);

    let mut current = root.clone();
    for raw_segment in path.split('.') {
        if raw_segment.is_empty() {
            continue;
        }
        let (field, indices) = split_segment(raw_segment);
        if !field.is_empty() {
            current = current.as_object()?.get(field)?.clone();
        }
        for index in indices {
            current = match index {
                BracketIndex::Numeric(i) => current.as_array()?.get(i)?.clone(),
                BracketIndex::Key(k) => current.as_object()?.get(&k)?.clone(),
            };
        }
    }
    Some(current)
}

enum BracketIndex {
    Numeric(usize),
    Key(String),
}

/// Splits `foo[0]['bar'][2]` into (`"foo"`, `[Numeric(0), Key("bar"),
/// Numeric(2)]`) — a segment with no brackets returns an empty index list.
fn split_segment(segment: &str) -> (&str, Vec<BracketIndex>) {
    let Some(bracket_start) = segment.find('[') else {
        return (segment, Vec::new());
    };
    let field = &segment[..bracket_start];
    let mut indices = Vec::new();
    let mut rest = &segment[bracket_start..];
    while let Some(stripped) = rest.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            break;
        };
        let inner = &stripped[..end];
        let key = inner.trim_matches(|c| c == '\'' || c == '"');
        if let Ok(i) = key.parse::<usize>() {
            indices.push(BracketIndex::Numeric(i));
        } else {
            indices.push(BracketIndex::Key(key.to_string()));
        }
        rest = &stripped[end + 1..];
    }
    (field, indices)
}

/// Check if the request wants table format
pub fn wants_table(accept_header: Option<&str>) -> bool {
    if let Some(accept) = accept_header {
        accept.contains("as=Table") || accept.contains("application/json;as=Table")
    } else {
        false
    }
}

// Trait implementations for common resource types

impl HasMetadata for rusternetes_common::resources::Pod {
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl HasMetadata for rusternetes_common::resources::Deployment {
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl HasMetadata for rusternetes_common::resources::CustomResource {
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl HasMetadata for rusternetes_common::resources::Service {
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl HasMetadata for rusternetes_common::resources::ReplicationController {
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl HasMetadata for rusternetes_common::resources::ReplicaSet {
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl HasPodInfo for rusternetes_common::resources::Pod {
    fn pod_info(&self) -> PodInfo {
        use rusternetes_common::types::Phase;

        let name = self.metadata.name.clone();
        let age = format_age(&self.metadata);

        // Calculate ready count and status
        let (ready_count, total_count, status, restarts) = if let Some(pod_status) = &self.status {
            let status_str = match &pod_status.phase {
                Some(Phase::Pending) => "Pending",
                Some(Phase::Running) => "Running",
                Some(Phase::Succeeded) => "Succeeded",
                Some(Phase::Failed) => "Failed",
                Some(Phase::Unknown) => "Unknown",
                Some(Phase::Active) => "Active",
                Some(Phase::Terminating) => "Terminating",
                None => "Pending",
            }
            .to_string();

            // Count ready containers
            let container_statuses = pod_status.container_statuses.as_ref();
            let ready = container_statuses
                .map(|statuses| statuses.iter().filter(|s| s.ready).count())
                .unwrap_or(0);
            let total = container_statuses
                .map(|statuses| statuses.len())
                .unwrap_or(0);

            // Calculate total restarts
            let restart_count = container_statuses
                .map(|statuses| statuses.iter().map(|s| s.restart_count).sum::<u32>())
                .unwrap_or(0);

            (ready, total, status_str, restart_count as i32)
        } else {
            (0, 0, "Pending".to_string(), 0)
        };

        let ready = format!("{}/{}", ready_count, total_count);

        PodInfo {
            name,
            ready,
            status,
            restarts,
            age,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_creation() {
        let table = Table::new()
            .add_column("NAME", "string", "name", "Resource name", 0)
            .add_column("AGE", "string", "", "Resource age", 0);

        assert_eq!(table.kind, "Table");
        assert_eq!(table.api_version, "meta.k8s.io/v1");
        assert_eq!(table.column_definitions.len(), 2);
    }

    #[test]
    fn test_wants_table() {
        assert!(wants_table(Some("application/json;as=Table")));
        assert!(wants_table(Some("application/json;as=Table;v=v1")));
        assert!(!wants_table(Some("application/json")));
        assert!(!wants_table(None));
    }

    #[test]
    fn resolve_json_path_reads_a_simple_nested_field() {
        let v = serde_json::json!({"status": {"phase": "Running"}});
        assert_eq!(
            resolve_json_path(&v, ".status.phase"),
            Some(serde_json::json!("Running"))
        );
    }

    #[test]
    fn resolve_json_path_root_alone_returns_the_whole_value() {
        let v = serde_json::json!({"a": 1});
        assert_eq!(resolve_json_path(&v, "."), Some(v.clone()));
        assert_eq!(resolve_json_path(&v, ""), Some(v));
    }

    #[test]
    fn resolve_json_path_returns_none_for_a_missing_field() {
        let v = serde_json::json!({"status": {}});
        assert_eq!(resolve_json_path(&v, ".status.phase"), None);
        assert_eq!(resolve_json_path(&v, ".spec.doesNotExist"), None);
    }

    #[test]
    fn resolve_json_path_supports_numeric_array_index() {
        let v = serde_json::json!({"spec": {"containers": [{"image": "a"}, {"image": "b"}]}});
        assert_eq!(
            resolve_json_path(&v, ".spec.containers[1].image"),
            Some(serde_json::json!("b"))
        );
    }

    #[test]
    fn resolve_json_path_supports_bracketed_map_key() {
        let v = serde_json::json!({"metadata": {"labels": {"app": "cnpg"}}});
        assert_eq!(
            resolve_json_path(&v, ".metadata.labels['app']"),
            Some(serde_json::json!("cnpg"))
        );
        assert_eq!(
            resolve_json_path(&v, ".metadata.labels[app]"),
            Some(serde_json::json!("cnpg"))
        );
    }

    #[test]
    fn custom_resource_table_falls_back_to_name_and_age_with_no_columns_declared() {
        let cr = rusternetes_common::resources::CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(serde_json::json!({"cronSpec": "* * * * */5"})),
            status: None,
            extra: Default::default(),
        };
        let table = custom_resource_table(None, vec![cr], None, "CronTab");
        assert_eq!(
            table
                .column_definitions
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["NAME", "AGE"]
        );
    }

    #[test]
    fn custom_resource_table_uses_declared_additional_printer_columns() {
        let cr = rusternetes_common::resources::CustomResource {
            api_version: "postgresql.cnpg.io/v1".to_string(),
            kind: "Cluster".to_string(),
            metadata: ObjectMeta::new("platform-db-cluster"),
            spec: Some(serde_json::json!({"instances": 1})),
            status: Some(serde_json::json!({"phase": "Cluster in healthy state"})),
            extra: Default::default(),
        };
        let columns = vec![
            rusternetes_common::resources::CustomResourceColumnDefinition {
                name: "Instances".to_string(),
                type_: "integer".to_string(),
                format: None,
                description: None,
                priority: None,
                json_path: ".spec.instances".to_string(),
            },
            rusternetes_common::resources::CustomResourceColumnDefinition {
                name: "Status".to_string(),
                type_: "string".to_string(),
                format: None,
                description: None,
                priority: None,
                json_path: ".status.phase".to_string(),
            },
        ];
        let table = custom_resource_table(Some(&columns), vec![cr], None, "Cluster");

        assert_eq!(
            table
                .column_definitions
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["NAME", "Instances", "Status"]
        );
        assert_eq!(
            table.rows[0].cells,
            vec![
                serde_json::json!("platform-db-cluster"),
                serde_json::json!(1),
                serde_json::json!("Cluster in healthy state"),
            ]
        );
    }

    #[test]
    fn custom_resource_table_renders_null_for_a_missing_column_value() {
        let cr = rusternetes_common::resources::CustomResource {
            api_version: "stable.example.com/v1".to_string(),
            kind: "CronTab".to_string(),
            metadata: ObjectMeta::new("my-crontab"),
            spec: Some(serde_json::json!({})),
            status: None,
            extra: Default::default(),
        };
        let columns = vec![rusternetes_common::resources::CustomResourceColumnDefinition {
            name: "Schedule".to_string(),
            type_: "string".to_string(),
            format: None,
            description: None,
            priority: None,
            json_path: ".spec.cronSpec".to_string(),
        }];
        let table = custom_resource_table(Some(&columns), vec![cr], None, "CronTab");
        assert_eq!(table.rows[0].cells[1], serde_json::Value::Null);
    }
}
