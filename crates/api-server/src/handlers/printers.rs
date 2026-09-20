//! What `kubectl get <kind>` prints, per kind.
//!
//! The api-server used to answer every table request with NAME and AGE for
//! everything except pods, which makes `kubectl get` close to useless: a
//! Service without its ports, type and cluster IP, a Deployment without its
//! ready count, a PVC without its capacity or bound volume. Those columns are
//! the reason the command is reached for at all.
//!
//! Real Kubernetes prints server-side from typed printers. This works from the
//! serialized object instead, which keeps one table of columns for every kind
//! in one file and lets the response layer (`table_response`) handle any
//! handler's output uniformly, including handlers that never knew about tables.
//! A kind with no entry here falls back to NAME and AGE — the previous
//! behaviour, and still correct, just sparse.

use serde_json::Value;

/// A column's header and its type, as `meta.k8s.io/v1.Table` wants them.
pub struct Column {
    pub name: &'static str,
    pub kind: &'static str,
}

const fn col(name: &'static str, kind: &'static str) -> Column {
    Column { name, kind }
}

/// The columns for `kind`, or `None` when nothing specific is known about it.
pub fn columns_for(kind: &str) -> Option<Vec<Column>> {
    let cols = match kind {
        "Pod" => vec![
            col("NAME", "string"),
            col("READY", "string"),
            col("STATUS", "string"),
            col("RESTARTS", "integer"),
            col("AGE", "string"),
        ],
        "Service" => vec![
            col("NAME", "string"),
            col("TYPE", "string"),
            col("CLUSTER-IP", "string"),
            col("EXTERNAL-IP", "string"),
            col("PORT(S)", "string"),
            col("AGE", "string"),
        ],
        "Deployment" => vec![
            col("NAME", "string"),
            col("READY", "string"),
            col("UP-TO-DATE", "integer"),
            col("AVAILABLE", "integer"),
            col("AGE", "string"),
        ],
        "StatefulSet" => vec![
            col("NAME", "string"),
            col("READY", "string"),
            col("AGE", "string"),
        ],
        "DaemonSet" => vec![
            col("NAME", "string"),
            col("DESIRED", "integer"),
            col("CURRENT", "integer"),
            col("READY", "integer"),
            col("UP-TO-DATE", "integer"),
            col("AVAILABLE", "integer"),
            col("AGE", "string"),
        ],
        "ReplicaSet" | "ReplicationController" => vec![
            col("NAME", "string"),
            col("DESIRED", "integer"),
            col("CURRENT", "integer"),
            col("READY", "integer"),
            col("AGE", "string"),
        ],
        "Job" => vec![
            col("NAME", "string"),
            col("COMPLETIONS", "string"),
            col("DURATION", "string"),
            col("AGE", "string"),
        ],
        "CronJob" => vec![
            col("NAME", "string"),
            col("SCHEDULE", "string"),
            col("SUSPEND", "string"),
            col("ACTIVE", "integer"),
            col("LAST SCHEDULE", "string"),
            col("AGE", "string"),
        ],
        "Node" => vec![
            col("NAME", "string"),
            col("STATUS", "string"),
            col("ROLES", "string"),
            col("AGE", "string"),
            col("VERSION", "string"),
        ],
        "Namespace" => vec![
            col("NAME", "string"),
            col("STATUS", "string"),
            col("AGE", "string"),
        ],
        "ConfigMap" => vec![
            col("NAME", "string"),
            col("DATA", "integer"),
            col("AGE", "string"),
        ],
        "Secret" => vec![
            col("NAME", "string"),
            col("TYPE", "string"),
            col("DATA", "integer"),
            col("AGE", "string"),
        ],
        "PersistentVolumeClaim" => vec![
            col("NAME", "string"),
            col("STATUS", "string"),
            col("VOLUME", "string"),
            col("CAPACITY", "string"),
            col("ACCESS MODES", "string"),
            col("STORAGECLASS", "string"),
            col("AGE", "string"),
        ],
        "PersistentVolume" => vec![
            col("NAME", "string"),
            col("CAPACITY", "string"),
            col("ACCESS MODES", "string"),
            col("RECLAIM POLICY", "string"),
            col("STATUS", "string"),
            col("CLAIM", "string"),
            col("STORAGECLASS", "string"),
            col("AGE", "string"),
        ],
        "ServiceAccount" => vec![
            col("NAME", "string"),
            col("SECRETS", "integer"),
            col("AGE", "string"),
        ],
        "Endpoints" => vec![
            col("NAME", "string"),
            col("ENDPOINTS", "string"),
            col("AGE", "string"),
        ],
        "Ingress" => vec![
            col("NAME", "string"),
            col("CLASS", "string"),
            col("HOSTS", "string"),
            col("ADDRESS", "string"),
            col("PORTS", "string"),
            col("AGE", "string"),
        ],
        _ => return None,
    };
    Some(cols)
}

/// The row for one object of `kind`. Must return exactly as many cells as
/// [`columns_for`] gave columns: kubectl lines them up by position, so a
/// mismatch prints a table with the values under the wrong headers.
pub fn cells_for(kind: &str, obj: &Value) -> Option<Vec<Value>> {
    let name = || s(obj.pointer("/metadata/name"));
    let age = || Value::String(age_of(obj));
    let cells = match kind {
        "Pod" => vec![
            name(),
            Value::String(pod_ready(obj)),
            Value::String(pod_status(obj)),
            Value::Number(pod_restarts(obj).into()),
            age(),
        ],
        "Service" => vec![
            name(),
            Value::String(
                obj.pointer("/spec/type")
                    .and_then(Value::as_str)
                    .unwrap_or("ClusterIP")
                    .to_string(),
            ),
            Value::String(
                obj.pointer("/spec/clusterIP")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .unwrap_or("None")
                    .to_string(),
            ),
            Value::String(external_ips(obj)),
            Value::String(service_ports(obj)),
            age(),
        ],
        "Deployment" => vec![
            name(),
            Value::String(format!(
                "{}/{}",
                n(obj.pointer("/status/readyReplicas")),
                n(obj.pointer("/spec/replicas"))
            )),
            Value::Number(n(obj.pointer("/status/updatedReplicas")).into()),
            Value::Number(n(obj.pointer("/status/availableReplicas")).into()),
            age(),
        ],
        "StatefulSet" => vec![
            name(),
            Value::String(format!(
                "{}/{}",
                n(obj.pointer("/status/readyReplicas")),
                n(obj.pointer("/spec/replicas"))
            )),
            age(),
        ],
        "DaemonSet" => vec![
            name(),
            Value::Number(n(obj.pointer("/status/desiredNumberScheduled")).into()),
            Value::Number(n(obj.pointer("/status/currentNumberScheduled")).into()),
            Value::Number(n(obj.pointer("/status/numberReady")).into()),
            Value::Number(n(obj.pointer("/status/updatedNumberScheduled")).into()),
            Value::Number(n(obj.pointer("/status/numberAvailable")).into()),
            age(),
        ],
        "ReplicaSet" | "ReplicationController" => vec![
            name(),
            Value::Number(n(obj.pointer("/spec/replicas")).into()),
            Value::Number(n(obj.pointer("/status/replicas")).into()),
            Value::Number(n(obj.pointer("/status/readyReplicas")).into()),
            age(),
        ],
        "Job" => vec![
            name(),
            Value::String(format!(
                "{}/{}",
                n(obj.pointer("/status/succeeded")),
                obj.pointer("/spec/completions")
                    .and_then(Value::as_i64)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "1".to_string())
            )),
            Value::String(job_duration(obj)),
            age(),
        ],
        "CronJob" => vec![
            name(),
            s(obj.pointer("/spec/schedule")),
            Value::String(
                obj.pointer("/spec/suspend")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    .to_string(),
            ),
            Value::Number(
                (obj.pointer("/status/active")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .unwrap_or(0) as i64)
                    .into(),
            ),
            Value::String(
                obj.pointer("/status/lastScheduleTime")
                    .and_then(Value::as_str)
                    .map(elapsed_since)
                    .unwrap_or_else(|| "<none>".to_string()),
            ),
            age(),
        ],
        "Node" => vec![
            name(),
            Value::String(node_status(obj)),
            Value::String(node_roles(obj)),
            age(),
            s(obj.pointer("/status/nodeInfo/kubeletVersion")),
        ],
        "Namespace" => vec![name(), s(obj.pointer("/status/phase")), age()],
        "ConfigMap" => vec![
            name(),
            Value::Number((count_keys(obj, "/data") + count_keys(obj, "/binaryData")).into()),
            age(),
        ],
        "Secret" => vec![
            name(),
            s(obj.pointer("/type")),
            Value::Number(count_keys(obj, "/data").into()),
            age(),
        ],
        "PersistentVolumeClaim" => vec![
            name(),
            s(obj.pointer("/status/phase")),
            s(obj.pointer("/spec/volumeName")),
            s(obj.pointer("/status/capacity/storage")),
            Value::String(access_modes(obj, "/spec/accessModes")),
            s(obj.pointer("/spec/storageClassName")),
            age(),
        ],
        "PersistentVolume" => vec![
            name(),
            s(obj.pointer("/spec/capacity/storage")),
            Value::String(access_modes(obj, "/spec/accessModes")),
            s(obj.pointer("/spec/persistentVolumeReclaimPolicy")),
            s(obj.pointer("/status/phase")),
            Value::String(claim_ref(obj)),
            s(obj.pointer("/spec/storageClassName")),
            age(),
        ],
        "ServiceAccount" => vec![
            name(),
            Value::Number(
                (obj.pointer("/secrets")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .unwrap_or(0) as i64)
                    .into(),
            ),
            age(),
        ],
        "Endpoints" => vec![name(), Value::String(endpoint_summary(obj)), age()],
        "Ingress" => vec![
            name(),
            s(obj.pointer("/spec/ingressClassName")),
            Value::String(ingress_hosts(obj)),
            Value::String(ingress_address(obj)),
            Value::String(ingress_ports(obj)),
            age(),
        ],
        _ => return None,
    };
    Some(cells)
}

// ---- cell helpers -------------------------------------------------------

/// A string cell, rendering an absent value the way kubectl does rather than
/// as an empty column.
fn s(v: Option<&Value>) -> Value {
    Value::String(
        v.and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .unwrap_or("<none>")
            .to_string(),
    )
}

fn n(v: Option<&Value>) -> i64 {
    v.and_then(Value::as_i64).unwrap_or(0)
}

fn count_keys(obj: &Value, ptr: &str) -> i64 {
    obj.pointer(ptr)
        .and_then(Value::as_object)
        .map(|m| m.len() as i64)
        .unwrap_or(0)
}

/// `80/TCP,443/TCP`, with a NodePort rendered as `80:31234/TCP` — the form
/// that tells you which host port to reach.
fn service_ports(obj: &Value) -> String {
    let Some(ports) = obj.pointer("/spec/ports").and_then(Value::as_array) else {
        return "<none>".to_string();
    };
    if ports.is_empty() {
        return "<none>".to_string();
    }
    ports
        .iter()
        .map(|p| {
            let port = p.get("port").and_then(Value::as_i64).unwrap_or(0);
            let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
            match p.get("nodePort").and_then(Value::as_i64) {
                Some(node_port) => format!("{port}:{node_port}/{proto}"),
                None => format!("{port}/{proto}"),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn external_ips(obj: &Value) -> String {
    let from_spec = obj
        .pointer("/spec/externalIPs")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    if !from_spec.is_empty() {
        return from_spec;
    }
    let from_lb = obj
        .pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|i| {
                    i.get("ip")
                        .or_else(|| i.get("hostname"))
                        .and_then(Value::as_str)
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    if from_lb.is_empty() {
        "<none>".to_string()
    } else {
        from_lb
    }
}

/// `2/3` — ready containers over total, counted from the container statuses
/// rather than the pod phase, which is what makes a pod that is Running but
/// not serving visible at a glance.
fn pod_ready(obj: &Value) -> String {
    let statuses = obj
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array);
    let total = obj
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .map(|c| c.len())
        .unwrap_or(0);
    let ready = statuses
        .map(|s| {
            s.iter()
                .filter(|c| c.get("ready").and_then(Value::as_bool).unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    format!("{ready}/{total}")
}

fn pod_status(obj: &Value) -> String {
    // A deleted pod reports its phase until it actually goes away; kubectl
    // shows Terminating, which is the more useful truth.
    if obj.pointer("/metadata/deletionTimestamp").is_some() {
        return "Terminating".to_string();
    }
    // A container's own waiting/terminated reason (CrashLoopBackOff,
    // ImagePullBackOff, Error) says far more than the pod phase Running.
    if let Some(statuses) = obj
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
    {
        for c in statuses {
            if let Some(reason) = c
                .pointer("/state/waiting/reason")
                .and_then(Value::as_str)
                .or_else(|| {
                    c.pointer("/state/terminated/reason")
                        .and_then(Value::as_str)
                })
            {
                if reason != "Completed" {
                    return reason.to_string();
                }
            }
        }
    }
    obj.pointer("/status/phase")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string()
}

fn pod_restarts(obj: &Value) -> i64 {
    obj.pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .map(|s| {
            s.iter()
                .map(|c| c.get("restartCount").and_then(Value::as_i64).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

fn node_status(obj: &Value) -> String {
    let ready = obj
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
                .and_then(|c| c.get("status").and_then(Value::as_str))
        });
    let base = match ready {
        Some("True") => "Ready",
        Some(_) => "NotReady",
        None => "Unknown",
    };
    if obj
        .pointer("/spec/unschedulable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        format!("{base},SchedulingDisabled")
    } else {
        base.to_string()
    }
}

fn node_roles(obj: &Value) -> String {
    let Some(labels) = obj.pointer("/metadata/labels").and_then(Value::as_object) else {
        return "<none>".to_string();
    };
    let mut roles: Vec<&str> = labels
        .keys()
        .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
        .filter(|r| !r.is_empty())
        .collect();
    roles.sort_unstable();
    if roles.is_empty() {
        "<none>".to_string()
    } else {
        roles.join(",")
    }
}

fn access_modes(obj: &Value, ptr: &str) -> String {
    let Some(modes) = obj.pointer(ptr).and_then(Value::as_array) else {
        return "<none>".to_string();
    };
    let short: Vec<&str> = modes
        .iter()
        .filter_map(Value::as_str)
        .map(|m| match m {
            "ReadWriteOnce" => "RWO",
            "ReadOnlyMany" => "ROX",
            "ReadWriteMany" => "RWX",
            "ReadWriteOncePod" => "RWOP",
            other => other,
        })
        .collect();
    if short.is_empty() {
        "<none>".to_string()
    } else {
        short.join(",")
    }
}

fn claim_ref(obj: &Value) -> String {
    match (
        obj.pointer("/spec/claimRef/namespace")
            .and_then(Value::as_str),
        obj.pointer("/spec/claimRef/name").and_then(Value::as_str),
    ) {
        (Some(ns), Some(name)) => format!("{ns}/{name}"),
        (None, Some(name)) => name.to_string(),
        _ => "<none>".to_string(),
    }
}

/// `10.0.0.1:8080,10.0.0.2:8080`, truncated the way kubectl truncates: a
/// Service backed by many pods would otherwise make the column unreadable.
fn endpoint_summary(obj: &Value) -> String {
    let Some(subsets) = obj.get("subsets").and_then(Value::as_array) else {
        return "<none>".to_string();
    };
    let mut out = Vec::new();
    let mut total = 0usize;
    for subset in subsets {
        let ports: Vec<i64> = subset
            .get("ports")
            .and_then(Value::as_array)
            .map(|ps| ps.iter().filter_map(|p| p.get("port")?.as_i64()).collect())
            .unwrap_or_default();
        let addresses = subset.get("addresses").and_then(Value::as_array);
        for addr in addresses.into_iter().flatten() {
            let Some(ip) = addr.get("ip").and_then(Value::as_str) else {
                continue;
            };
            total += 1;
            if out.len() < 3 {
                match ports.first() {
                    Some(port) => out.push(format!("{ip}:{port}")),
                    None => out.push(ip.to_string()),
                }
            }
        }
    }
    if total == 0 {
        return "<none>".to_string();
    }
    if total > out.len() {
        format!("{} + {} more...", out.join(","), total - out.len())
    } else {
        out.join(",")
    }
}

fn ingress_hosts(obj: &Value) -> String {
    let hosts: Vec<&str> = obj
        .pointer("/spec/rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|r| r.get("host").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if hosts.is_empty() {
        "*".to_string()
    } else {
        hosts.join(",")
    }
}

fn ingress_address(obj: &Value) -> String {
    obj.pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|i| {
                    i.get("ip")
                        .or_else(|| i.get("hostname"))
                        .and_then(Value::as_str)
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "<none>".to_string())
}

fn ingress_ports(obj: &Value) -> String {
    let has_tls = obj
        .pointer("/spec/tls")
        .and_then(Value::as_array)
        .map(|t| !t.is_empty())
        .unwrap_or(false);
    if has_tls {
        "80, 443".to_string()
    } else {
        "80".to_string()
    }
}

/// How long a Job ran: completion minus start, or how long it has been running
/// when it has not completed.
fn job_duration(obj: &Value) -> String {
    let Some(start) = obj
        .pointer("/status/startTime")
        .and_then(Value::as_str)
        .and_then(parse_time)
    else {
        return "<none>".to_string();
    };
    let end = obj
        .pointer("/status/completionTime")
        .and_then(Value::as_str)
        .and_then(parse_time)
        .unwrap_or_else(chrono::Utc::now);
    compact_duration(end.signed_duration_since(start))
}

fn age_of(obj: &Value) -> String {
    obj.pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str)
        .map(elapsed_since)
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn elapsed_since(timestamp: &str) -> String {
    match parse_time(timestamp) {
        Some(t) => compact_duration(chrono::Utc::now().signed_duration_since(t)),
        None => "<unknown>".to_string(),
    }
}

fn parse_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// The same shape `format_age` produces, so every AGE column reads alike.
fn compact_duration(d: chrono::Duration) -> String {
    if d.num_days() > 0 {
        format!("{}d", d.num_days())
    } else if d.num_hours() > 0 {
        format!("{}h", d.num_hours())
    } else if d.num_minutes() > 0 {
        format!("{}m", d.num_minutes())
    } else {
        format!("{}s", d.num_seconds().max(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_kind_returns_one_cell_per_column() {
        // kubectl lines cells up with headers by position, so a kind whose row
        // is a different length prints values under the wrong headers.
        for kind in [
            "Pod",
            "Service",
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "ReplicaSet",
            "ReplicationController",
            "Job",
            "CronJob",
            "Node",
            "Namespace",
            "ConfigMap",
            "Secret",
            "PersistentVolumeClaim",
            "PersistentVolume",
            "ServiceAccount",
            "Endpoints",
            "Ingress",
        ] {
            let columns = columns_for(kind).unwrap_or_else(|| panic!("{kind} has no columns"));
            let cells = cells_for(kind, &json!({"metadata": {"name": "x"}}))
                .unwrap_or_else(|| panic!("{kind} has no cells"));
            assert_eq!(
                columns.len(),
                cells.len(),
                "{kind}: {} columns but {} cells",
                columns.len(),
                cells.len()
            );
        }
    }

    #[test]
    fn an_unknown_kind_has_no_printer() {
        assert!(columns_for("Widget").is_none());
        assert!(cells_for("Widget", &json!({})).is_none());
    }

    #[test]
    fn service_shows_its_ports_type_and_cluster_ip() {
        let svc = json!({
            "metadata": {"name": "guts"},
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.96.0.12",
                "ports": [{"port": 3000, "protocol": "TCP"}]
            }
        });
        let cells = cells_for("Service", &svc).unwrap();
        assert_eq!(cells[1], json!("ClusterIP"));
        assert_eq!(cells[2], json!("10.96.0.12"));
        assert_eq!(cells[3], json!("<none>"));
        assert_eq!(cells[4], json!("3000/TCP"));
    }

    #[test]
    fn a_headless_service_says_none_not_empty() {
        let svc = json!({"metadata": {"name": "h"}, "spec": {"clusterIP": "", "ports": []}});
        let cells = cells_for("Service", &svc).unwrap();
        assert_eq!(cells[2], json!("None"));
        assert_eq!(cells[4], json!("<none>"));
    }

    #[test]
    fn a_node_port_shows_the_host_port_too() {
        let svc = json!({
            "metadata": {"name": "np"},
            "spec": {"type": "NodePort", "clusterIP": "10.96.0.5",
                     "ports": [{"port": 80, "nodePort": 31234, "protocol": "TCP"}]}
        });
        assert_eq!(
            cells_for("Service", &svc).unwrap()[4],
            json!("80:31234/TCP")
        );
    }

    #[test]
    fn pod_status_prefers_a_container_failure_over_the_phase() {
        let pod = json!({
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c"}]},
            "status": {
                "phase": "Running",
                "containerStatuses": [{
                    "ready": false,
                    "restartCount": 7,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}}
                }]
            }
        });
        let cells = cells_for("Pod", &pod).unwrap();
        assert_eq!(cells[1], json!("0/1"));
        assert_eq!(cells[2], json!("CrashLoopBackOff"));
        assert_eq!(cells[3], json!(7));
    }

    #[test]
    fn a_deleted_pod_reads_as_terminating() {
        let pod = json!({
            "metadata": {"name": "p", "deletionTimestamp": "2026-09-18T10:00:00Z"},
            "spec": {"containers": [{"name": "c"}]},
            "status": {"phase": "Running", "containerStatuses": [{"ready": true}]}
        });
        assert_eq!(cells_for("Pod", &pod).unwrap()[2], json!("Terminating"));
    }

    #[test]
    fn deployment_ready_counts_come_from_both_spec_and_status() {
        let dep = json!({
            "metadata": {"name": "d"},
            "spec": {"replicas": 3},
            "status": {"readyReplicas": 2, "updatedReplicas": 3, "availableReplicas": 2}
        });
        let cells = cells_for("Deployment", &dep).unwrap();
        assert_eq!(cells[1], json!("2/3"));
        assert_eq!(cells[2], json!(3));
        assert_eq!(cells[3], json!(2));
    }

    #[test]
    fn a_missing_status_reads_as_zero_not_as_an_error() {
        // A Deployment that has never been reconciled has no status at all.
        let dep = json!({"metadata": {"name": "d"}, "spec": {"replicas": 2}});
        assert_eq!(cells_for("Deployment", &dep).unwrap()[1], json!("0/2"));
    }

    #[test]
    fn pvc_shows_capacity_volume_and_shortened_access_modes() {
        let pvc = json!({
            "metadata": {"name": "data"},
            "spec": {"volumeName": "pv-1", "accessModes": ["ReadWriteOnce"],
                     "storageClassName": "standard"},
            "status": {"phase": "Bound", "capacity": {"storage": "1Gi"}}
        });
        let cells = cells_for("PersistentVolumeClaim", &pvc).unwrap();
        assert_eq!(cells[1], json!("Bound"));
        assert_eq!(cells[2], json!("pv-1"));
        assert_eq!(cells[3], json!("1Gi"));
        assert_eq!(cells[4], json!("RWO"));
        assert_eq!(cells[5], json!("standard"));
    }

    #[test]
    fn endpoints_are_summarised_and_truncated() {
        let ep = json!({
            "metadata": {"name": "e"},
            "subsets": [{
                "ports": [{"port": 8080}],
                "addresses": [
                    {"ip": "10.0.0.1"}, {"ip": "10.0.0.2"},
                    {"ip": "10.0.0.3"}, {"ip": "10.0.0.4"}
                ]
            }]
        });
        assert_eq!(
            cells_for("Endpoints", &ep).unwrap()[1],
            json!("10.0.0.1:8080,10.0.0.2:8080,10.0.0.3:8080 + 1 more...")
        );
    }

    #[test]
    fn a_service_with_no_backends_says_none() {
        let ep = json!({"metadata": {"name": "e"}, "subsets": []});
        assert_eq!(cells_for("Endpoints", &ep).unwrap()[1], json!("<none>"));
    }

    #[test]
    fn node_roles_come_from_labels_and_unschedulable_shows() {
        let node = json!({
            "metadata": {"name": "n", "labels": {"node-role.kubernetes.io/control-plane": ""}},
            "spec": {"unschedulable": true},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "nodeInfo": {"kubeletVersion": "v1.31.0"}
            }
        });
        let cells = cells_for("Node", &node).unwrap();
        assert_eq!(cells[1], json!("Ready,SchedulingDisabled"));
        assert_eq!(cells[2], json!("control-plane"));
        assert_eq!(cells[4], json!("v1.31.0"));
    }

    #[test]
    fn configmap_counts_both_data_and_binary_data() {
        let cm = json!({
            "metadata": {"name": "c"},
            "data": {"a": "1", "b": "2"},
            "binaryData": {"c": "eA=="}
        });
        assert_eq!(cells_for("ConfigMap", &cm).unwrap()[1], json!(3));
    }
}
