//! `autoscaling/v1` ↔ `autoscaling/v2` conversion for HorizontalPodAutoscaler.
//!
//! One HPA is stored, in the v2 shape, and both API versions are served from
//! it. Before this module the two versions shared a handler that stamped
//! `autoscaling/v2` unconditionally, so a request to
//! `/apis/autoscaling/v1/namespaces/x/horizontalpodautoscalers` came back
//! carrying `apiVersion: autoscaling/v2` and a `spec.metrics` field that v1 has
//! no schema for. A strict client decoding into its v1 type fails on it, and
//! the reply is wrong about itself either way: the endpoint a client asked is
//! the version it must be answered in.
//!
//! Conversion runs as a layer rather than in the handlers because the handlers
//! cannot see which route reached them — the router registers both paths
//! against the same functions — and because the request direction needs the
//! same treatment: a v1 client writes `targetCPUUtilizationPercentage`, which
//! the stored type does not have and was silently discarding.
//!
//! ## Losslessness
//!
//! v2 can express metrics v1 cannot. Dropping them on the way out would make a
//! read-modify-write through the v1 endpoint — `kubectl edit` against an old
//! client, a v1-era controller — silently delete the metrics of a v2 HPA. So
//! the v2-only parts travel in annotations, which is how upstream solves the
//! same problem:
//!
//!   * `autoscaling.alpha.kubernetes.io/metrics`  — the full v2 `spec.metrics`
//!   * `autoscaling.alpha.kubernetes.io/behavior` — `spec.behavior`
//!   * `autoscaling.alpha.kubernetes.io/conditions`     — `status.conditions`
//!   * `autoscaling.alpha.kubernetes.io/current-metrics` — `status.currentMetrics`
//!
//! and are lifted back out when a v1 object is written.

use axum::{body::Body, extract::Request, http::header, middleware::Next, response::Response};
use futures::StreamExt;

const V1: &str = "autoscaling/v1";
const V2: &str = "autoscaling/v2";

const ANN_METRICS: &str = "autoscaling.alpha.kubernetes.io/metrics";
const ANN_BEHAVIOR: &str = "autoscaling.alpha.kubernetes.io/behavior";
const ANN_CONDITIONS: &str = "autoscaling.alpha.kubernetes.io/conditions";
const ANN_CURRENT_METRICS: &str = "autoscaling.alpha.kubernetes.io/current-metrics";

/// Is this a request against the `autoscaling/v1` HPA endpoints?
fn is_v1_hpa_path(path: &str) -> bool {
    path.starts_with("/apis/autoscaling/v1/") && path.contains("horizontalpodautoscalers")
}

/// Pull an annotation out, parsing it as JSON. Returns `None` and leaves the
/// annotation in place if it does not parse — a value a client hand-wrote
/// badly should surface as an unexpected annotation, not as a silently empty
/// `metrics`.
fn take_json_annotation(obj: &mut serde_json::Map<String, serde_json::Value>, key: &str) -> Option<serde_json::Value> {
    let annotations = obj
        .get_mut("metadata")?
        .as_object_mut()?
        .get_mut("annotations")?
        .as_object_mut()?;
    let raw = annotations.get(key)?.as_str()?.to_string();
    let parsed = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    annotations.remove(key);
    Some(parsed)
}

fn set_json_annotation(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &serde_json::Value,
) {
    let Ok(encoded) = serde_json::to_string(value) else {
        return;
    };
    let metadata = obj
        .entry("metadata")
        .or_insert_with(|| serde_json::json!({}));
    let Some(metadata) = metadata.as_object_mut() else {
        return;
    };
    let annotations = metadata
        .entry("annotations")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(annotations) = annotations.as_object_mut() {
        annotations.insert(key.to_string(), serde_json::json!(encoded));
    }
}

/// Find the CPU utilization target in a v2 `spec.metrics`, which is the one
/// thing v1 can express natively.
fn cpu_utilization_target(metrics: &serde_json::Value) -> Option<i64> {
    for m in metrics.as_array()? {
        if m.get("type").and_then(|t| t.as_str()) != Some("Resource") {
            continue;
        }
        let resource = m.get("resource")?;
        if resource.get("name").and_then(|n| n.as_str()) != Some("cpu") {
            continue;
        }
        let target = resource.get("target")?;
        if target.get("type").and_then(|t| t.as_str()) != Some("Utilization") {
            continue;
        }
        if let Some(v) = target.get("averageUtilization").and_then(|v| v.as_i64()) {
            return Some(v);
        }
    }
    None
}

/// Same, for `status.currentMetrics`.
fn cpu_current_utilization(metrics: &serde_json::Value) -> Option<i64> {
    for m in metrics.as_array()? {
        if m.get("type").and_then(|t| t.as_str()) != Some("Resource") {
            continue;
        }
        let resource = m.get("resource")?;
        if resource.get("name").and_then(|n| n.as_str()) != Some("cpu") {
            continue;
        }
        let current = resource.get("current")?;
        if let Some(v) = current.get("averageUtilization").and_then(|v| v.as_i64()) {
            return Some(v);
        }
    }
    None
}

/// v2 → v1, for a single HorizontalPodAutoscaler.
pub(crate) fn to_v1(mut value: serde_json::Value) -> serde_json::Value {
    let Some(obj) = value.as_object_mut() else {
        return value;
    };
    if obj.get("kind").and_then(|k| k.as_str()) == Some("Status") {
        return value;
    }
    obj.insert("apiVersion".into(), serde_json::json!(V1));

    if let Some(spec) = obj.get_mut("spec").and_then(|s| s.as_object_mut()) {
        let metrics = spec.remove("metrics");
        let behavior = spec.remove("behavior");
        if let Some(ref metrics) = metrics {
            if let Some(pct) = cpu_utilization_target(metrics) {
                spec.insert("targetCPUUtilizationPercentage".into(), serde_json::json!(pct));
            }
        }
        // Stash after the projection so a v1 client's write can restore the
        // full list rather than only the CPU part it could see.
        let (metrics, behavior) = (metrics, behavior);
        if let Some(metrics) = metrics {
            if !metrics.is_null() {
                set_json_annotation(obj, ANN_METRICS, &metrics);
            }
        }
        if let Some(behavior) = behavior {
            if !behavior.is_null() {
                set_json_annotation(obj, ANN_BEHAVIOR, &behavior);
            }
        }
    }

    if let Some(status) = obj.get_mut("status").and_then(|s| s.as_object_mut()) {
        let current = status.remove("currentMetrics");
        let conditions = status.remove("conditions");
        if let Some(ref current) = current {
            if let Some(pct) = cpu_current_utilization(current) {
                spec_insert_status_cpu(status, pct);
            }
        }
        if let Some(current) = current {
            if !current.is_null() {
                set_json_annotation(obj, ANN_CURRENT_METRICS, &current);
            }
        }
        if let Some(conditions) = conditions {
            if !conditions.is_null() {
                set_json_annotation(obj, ANN_CONDITIONS, &conditions);
            }
        }
    }

    value
}

fn spec_insert_status_cpu(status: &mut serde_json::Map<String, serde_json::Value>, pct: i64) {
    status.insert(
        "currentCPUUtilizationPercentage".into(),
        serde_json::json!(pct),
    );
}

/// v1 → v2, for a single HorizontalPodAutoscaler written through a v1 endpoint.
pub(crate) fn to_v2(mut value: serde_json::Value) -> serde_json::Value {
    let Some(obj) = value.as_object_mut() else {
        return value;
    };
    obj.insert("apiVersion".into(), serde_json::json!(V2));

    // The annotations are authoritative when present: they carry the full v2
    // shape this object was last read with, including metrics v1 cannot name.
    let stashed_metrics = take_json_annotation(obj, ANN_METRICS);
    let stashed_behavior = take_json_annotation(obj, ANN_BEHAVIOR);
    let stashed_conditions = take_json_annotation(obj, ANN_CONDITIONS);
    let stashed_current = take_json_annotation(obj, ANN_CURRENT_METRICS);

    if let Some(spec) = obj.get_mut("spec").and_then(|s| s.as_object_mut()) {
        let v1_cpu = spec
            .remove("targetCPUUtilizationPercentage")
            .and_then(|v| v.as_i64());

        match stashed_metrics {
            Some(mut metrics) => {
                // The client may have edited the CPU number it could see. That
                // edit wins over the stashed copy of the same metric; every
                // other metric is preserved untouched.
                if let Some(pct) = v1_cpu {
                    overwrite_cpu_utilization(&mut metrics, pct);
                }
                spec.insert("metrics".into(), metrics);
            }
            None => {
                if let Some(pct) = v1_cpu {
                    spec.insert(
                        "metrics".into(),
                        serde_json::json!([{
                            "type": "Resource",
                            "resource": {
                                "name": "cpu",
                                "target": {"type": "Utilization", "averageUtilization": pct},
                            },
                        }]),
                    );
                }
            }
        }
        if let Some(behavior) = stashed_behavior {
            spec.insert("behavior".into(), behavior);
        }
    }

    if let Some(status) = obj.get_mut("status").and_then(|s| s.as_object_mut()) {
        status.remove("currentCPUUtilizationPercentage");
        if let Some(current) = stashed_current {
            status.insert("currentMetrics".into(), current);
        }
        if let Some(conditions) = stashed_conditions {
            status.insert("conditions".into(), conditions);
        }
    }

    value
}

/// Replace the CPU utilization target in place, or append one if the list has
/// no CPU Resource metric.
fn overwrite_cpu_utilization(metrics: &mut serde_json::Value, pct: i64) {
    if let Some(arr) = metrics.as_array_mut() {
        for m in arr.iter_mut() {
            let is_cpu = m.get("type").and_then(|t| t.as_str()) == Some("Resource")
                && m.get("resource")
                    .and_then(|r| r.get("name"))
                    .and_then(|n| n.as_str())
                    == Some("cpu")
                && m.get("resource")
                    .and_then(|r| r.get("target"))
                    .and_then(|t| t.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("Utilization");
            if is_cpu {
                if let Some(target) = m
                    .get_mut("resource")
                    .and_then(|r| r.get_mut("target"))
                    .and_then(|t| t.as_object_mut())
                {
                    target.insert("averageUtilization".into(), serde_json::json!(pct));
                }
                return;
            }
        }
        arr.push(serde_json::json!({
            "type": "Resource",
            "resource": {
                "name": "cpu",
                "target": {"type": "Utilization", "averageUtilization": pct},
            },
        }));
    }
}

/// Apply a per-object conversion across a whole body: a List converts each
/// item and restamps its own `apiVersion`; anything else converts directly.
fn convert_body(
    mut value: serde_json::Value,
    api_version: &str,
    convert: fn(serde_json::Value) -> serde_json::Value,
) -> serde_json::Value {
    let is_list = value
        .get("kind")
        .and_then(|k| k.as_str())
        .is_some_and(|k| k.ends_with("List"))
        && value.get("items").is_some();
    if !is_list {
        return convert(value);
    }
    if let Some(obj) = value.as_object_mut() {
        obj.insert("apiVersion".into(), serde_json::json!(api_version));
        if let Some(serde_json::Value::Array(items)) = obj.get_mut("items") {
            for item in items.iter_mut() {
                *item = convert(item.take());
            }
        }
    }
    value
}

/// Convert the `object` inside one newline-delimited watch event.
fn convert_watch_event(line: &str, convert: fn(serde_json::Value) -> serde_json::Value) -> String {
    let Ok(mut event) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string();
    };
    let Some(obj) = event.as_object_mut() else {
        return line.to_string();
    };
    let Some(inner) = obj.remove("object") else {
        return line.to_string();
    };
    obj.insert("object".into(), convert(inner));
    serde_json::to_string(&event).unwrap_or_else(|_| line.to_string())
}

/// Serve the `autoscaling/v1` HPA endpoints in v1, converting both ways.
///
/// Requests to any other path are passed through without buffering.
pub async fn autoscaling_v1_middleware(request: Request, next: Next) -> Response {
    if !is_v1_hpa_path(request.uri().path()) {
        return next.run(request).await;
    }

    let is_watch = request
        .uri()
        .query()
        .map(crate::handlers::watch::query_is_watch)
        .unwrap_or(false);

    // Request direction: a v1 body becomes a v2 body before the handler
    // deserializes it into the stored type.
    let (parts, body) = request.into_parts();
    let has_body = matches!(
        parts.method,
        axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH
    );
    let request = if has_body {
        match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
            Ok(bytes) if !bytes.is_empty() => {
                match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(value) => {
                        let converted = to_v2(value);
                        let out = serde_json::to_vec(&converted).unwrap_or_else(|_| bytes.to_vec());
                        let mut parts = parts;
                        // The rewritten body has a different length; leaving the
                        // old one would truncate it.
                        parts.headers.remove(header::CONTENT_LENGTH);
                        Request::from_parts(parts, Body::from(out))
                    }
                    // Not JSON (a merge-patch in some other encoding, a
                    // malformed body): leave it to the handler to reject.
                    Err(_) => Request::from_parts(parts, Body::from(bytes)),
                }
            }
            Ok(bytes) => Request::from_parts(parts, Body::from(bytes)),
            Err(_) => {
                return Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .body(Body::from("failed to read request body"))
                    .unwrap();
            }
        }
    } else {
        Request::from_parts(parts, body)
    };

    let response = next.run(request).await;
    if !response.status().is_success() {
        return response;
    }

    let (mut parts, body) = response.into_parts();

    if is_watch {
        let stream = body.into_data_stream();
        let mut pending = String::new();
        let converted = stream.flat_map(move |chunk| {
            let mut out: Vec<std::result::Result<bytes::Bytes, axum::Error>> = Vec::new();
            match chunk {
                Ok(bytes) => {
                    pending.push_str(&String::from_utf8_lossy(&bytes));
                    while let Some(idx) = pending.find('\n') {
                        let line: String = pending.drain(..=idx).collect();
                        let trimmed = line.trim_end_matches('\n');
                        if trimmed.is_empty() {
                            continue;
                        }
                        out.push(Ok(bytes::Bytes::from(format!(
                            "{}\n",
                            convert_watch_event(trimmed, to_v1)
                        ))));
                    }
                }
                Err(e) => out.push(Err(e)),
            }
            futures::stream::iter(out)
        });
        return Response::from_parts(parts, Body::from_stream(converted));
    }

    let bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("failed to read response body"))
                .unwrap();
        }
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let converted = convert_body(value, V1, to_v1);
    let out = serde_json::to_vec(&converted).unwrap_or_else(|_| bytes.to_vec());
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_hpa() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "web", "namespace": "default"},
            "spec": {
                "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "web"},
                "minReplicas": 2,
                "maxReplicas": 10,
                "metrics": [
                    {"type": "Resource", "resource": {"name": "cpu",
                        "target": {"type": "Utilization", "averageUtilization": 80}}},
                    {"type": "Resource", "resource": {"name": "memory",
                        "target": {"type": "Utilization", "averageUtilization": 70}}},
                ],
                "behavior": {"scaleDown": {"stabilizationWindowSeconds": 300}},
            },
            "status": {"currentReplicas": 2, "desiredReplicas": 3},
        })
    }

    #[test]
    fn only_the_v1_hpa_paths_are_claimed() {
        assert!(is_v1_hpa_path(
            "/apis/autoscaling/v1/namespaces/default/horizontalpodautoscalers"
        ));
        assert!(is_v1_hpa_path("/apis/autoscaling/v1/horizontalpodautoscalers"));
        assert!(!is_v1_hpa_path(
            "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers"
        ));
        assert!(!is_v1_hpa_path("/apis/autoscaling/v1/scale"));
        assert!(!is_v1_hpa_path("/api/v1/pods"));
    }

    /// The bug this module exists for: the v1 endpoint used to answer with
    /// `apiVersion: autoscaling/v2` and a `spec.metrics` v1 cannot decode.
    #[test]
    fn a_v1_read_is_stamped_v1_and_carries_no_v2_only_fields() {
        let out = to_v1(v2_hpa());
        assert_eq!(out["apiVersion"], "autoscaling/v1");
        assert!(out["spec"].get("metrics").is_none());
        assert!(out["spec"].get("behavior").is_none());
        assert_eq!(out["spec"]["targetCPUUtilizationPercentage"], 80);
        assert_eq!(out["spec"]["maxReplicas"], 10);
    }

    /// A v1 client that reads, edits and writes back must not delete the
    /// memory metric it never saw.
    #[test]
    fn a_v1_round_trip_preserves_metrics_v1_cannot_express() {
        let as_v1 = to_v1(v2_hpa());
        let back = to_v2(as_v1);
        assert_eq!(back["apiVersion"], "autoscaling/v2");
        let metrics = back["spec"]["metrics"].as_array().unwrap();
        assert_eq!(metrics.len(), 2, "lost a metric: {metrics:?}");
        assert_eq!(metrics[1]["resource"]["name"], "memory");
        assert_eq!(metrics[1]["resource"]["target"]["averageUtilization"], 70);
        assert_eq!(back["spec"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"], 300);
        // The transport annotations do not linger on the stored object.
        let ann = back["metadata"].get("annotations");
        if let Some(ann) = ann {
            assert!(ann.get(ANN_METRICS).is_none(), "annotation leaked: {ann:?}");
            assert!(ann.get(ANN_BEHAVIOR).is_none());
        }
    }

    /// An edit a v1 client *can* make must win over the stashed copy.
    #[test]
    fn a_v1_edit_of_the_cpu_target_is_applied_and_others_kept() {
        let mut as_v1 = to_v1(v2_hpa());
        as_v1["spec"]["targetCPUUtilizationPercentage"] = serde_json::json!(55);
        let back = to_v2(as_v1);
        let metrics = back["spec"]["metrics"].as_array().unwrap();
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0]["resource"]["target"]["averageUtilization"], 55);
        assert_eq!(metrics[1]["resource"]["target"]["averageUtilization"], 70);
        assert!(back["spec"].get("targetCPUUtilizationPercentage").is_none());
    }

    /// A plain v1 create, with no annotations, becomes a valid v2 object.
    #[test]
    fn a_fresh_v1_create_becomes_a_cpu_resource_metric() {
        let v1 = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "web"},
            "spec": {
                "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "web"},
                "maxReplicas": 5,
                "targetCPUUtilizationPercentage": 65,
            },
        });
        let out = to_v2(v1);
        assert_eq!(out["apiVersion"], "autoscaling/v2");
        let metrics = out["spec"]["metrics"].as_array().unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0]["type"], "Resource");
        assert_eq!(metrics[0]["resource"]["name"], "cpu");
        assert_eq!(metrics[0]["resource"]["target"]["type"], "Utilization");
        assert_eq!(metrics[0]["resource"]["target"]["averageUtilization"], 65);
        assert!(out["spec"].get("targetCPUUtilizationPercentage").is_none());
    }

    /// v1's status field is `currentCPUUtilizationPercentage`, not
    /// `currentMetrics`.
    #[test]
    fn status_is_projected_and_restored() {
        let mut hpa = v2_hpa();
        hpa["status"]["currentMetrics"] = serde_json::json!([
            {"type": "Resource", "resource": {"name": "cpu", "current": {"averageUtilization": 42}}}
        ]);
        hpa["status"]["conditions"] = serde_json::json!([{"type": "AbleToScale", "status": "True"}]);
        let as_v1 = to_v1(hpa);
        assert_eq!(as_v1["status"]["currentCPUUtilizationPercentage"], 42);
        assert!(as_v1["status"].get("currentMetrics").is_none());
        assert!(as_v1["status"].get("conditions").is_none());

        let back = to_v2(as_v1);
        assert!(back["status"].get("currentCPUUtilizationPercentage").is_none());
        assert_eq!(back["status"]["currentMetrics"][0]["resource"]["name"], "cpu");
        assert_eq!(back["status"]["conditions"][0]["type"], "AbleToScale");
    }

    #[test]
    fn a_list_restamps_itself_and_every_item() {
        let list = serde_json::json!({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscalerList",
            "metadata": {"resourceVersion": "9"},
            "items": [v2_hpa(), v2_hpa()],
        });
        let out = convert_body(list, V1, to_v1);
        assert_eq!(out["apiVersion"], "autoscaling/v1");
        assert_eq!(out["kind"], "HorizontalPodAutoscalerList");
        assert_eq!(out["metadata"]["resourceVersion"], "9");
        for item in out["items"].as_array().unwrap() {
            assert_eq!(item["apiVersion"], "autoscaling/v1");
            assert_eq!(item["spec"]["targetCPUUtilizationPercentage"], 80);
            assert!(item["spec"].get("metrics").is_none());
        }
    }

    #[test]
    fn a_watch_event_is_converted_inside_its_envelope() {
        let line = serde_json::to_string(&serde_json::json!({
            "type": "MODIFIED", "object": v2_hpa(),
        }))
        .unwrap();
        let out: serde_json::Value =
            serde_json::from_str(&convert_watch_event(&line, to_v1)).unwrap();
        assert_eq!(out["type"], "MODIFIED");
        assert_eq!(out["object"]["apiVersion"], "autoscaling/v1");
        assert!(out["object"]["spec"].get("metrics").is_none());
    }

    /// An error reply is a Status and must reach the client intact.
    #[test]
    fn a_status_reply_is_not_restamped() {
        let status = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "reason": "NotFound", "code": 404, "metadata": {},
        });
        assert_eq!(to_v1(status.clone()), status);
    }

    /// An HPA with no CPU metric has nothing v1 can name; it must still come
    /// back as a well-formed v1 object rather than carrying v2 fields.
    #[test]
    fn an_hpa_with_no_cpu_metric_still_converts() {
        let mut hpa = v2_hpa();
        hpa["spec"]["metrics"] = serde_json::json!([
            {"type": "Resource", "resource": {"name": "memory",
                "target": {"type": "Utilization", "averageUtilization": 70}}}
        ]);
        let as_v1 = to_v1(hpa);
        assert_eq!(as_v1["apiVersion"], "autoscaling/v1");
        assert!(as_v1["spec"].get("metrics").is_none());
        assert!(as_v1["spec"].get("targetCPUUtilizationPercentage").is_none());
        // And it survives the trip back.
        let back = to_v2(as_v1);
        assert_eq!(back["spec"]["metrics"].as_array().unwrap().len(), 1);
        assert_eq!(back["spec"]["metrics"][0]["resource"]["name"], "memory");
    }

    /// A malformed annotation is left alone rather than producing an empty
    /// `metrics`, which would silently unconfigure the autoscaler.
    #[test]
    fn a_malformed_stash_does_not_erase_metrics() {
        let v1 = serde_json::json!({
            "apiVersion": "autoscaling/v1",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "web", "annotations": {ANN_METRICS: "{not json"}},
            "spec": {"maxReplicas": 5, "targetCPUUtilizationPercentage": 65},
        });
        let out = to_v2(v1);
        // Falls back to the CPU target the client did send.
        assert_eq!(out["spec"]["metrics"].as_array().unwrap().len(), 1);
        assert_eq!(out["spec"]["metrics"][0]["resource"]["name"], "cpu");
        // And the unparseable annotation is still visible, not swallowed.
        assert_eq!(out["metadata"]["annotations"][ANN_METRICS], "{not json");
    }
}
