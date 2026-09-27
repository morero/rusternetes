//! `as=PartialObjectMetadata` content negotiation.
//!
//! A client that only needs names, labels and resourceVersions asks for them
//! in `Accept`:
//!
//! ```text
//! Accept: application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io, application/json
//! ```
//!
//! Until this module existed the header was ignored and the full object went
//! back. For most resources that is merely wasteful. For Secrets it is a
//! disclosure: cert-manager's cainjector watches Secrets in
//! `PartialObjectMetadata` form precisely so that secret material never enters
//! its process, and it was being handed every `data` value in the cluster. The
//! client then failed to decode the reply into its metadata-only type, so the
//! data was both leaked and useless.
//!
//! The projection happens on the way out, in one layer, rather than in each of
//! the ~150 handlers: a handler cannot forget to apply something it does not
//! participate in.

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};
use futures::StreamExt;

/// `meta.k8s.io/v1`, the group/version PartialObjectMetadata is served under.
const META_API_VERSION: &str = "meta.k8s.io/v1";
const KIND_SINGLE: &str = "PartialObjectMetadata";
const KIND_LIST: &str = "PartialObjectMetadataList";

/// What the `Accept` header asked for, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartialRequest {
    /// No `as=PartialObjectMetadata*` clause — serve the object unchanged.
    No,
    Yes,
}

/// Parse `Accept` for an `as=PartialObjectMetadata` or
/// `as=PartialObjectMetadataList` clause.
///
/// Both spellings are treated the same, because the shape of the *response*
/// decides which kind is correct: a client that asks for
/// `PartialObjectMetadataList` on a single-object GET still wants the single
/// kind back, and upstream answers by the resource, not by the header's
/// spelling. The `v=`/`g=` parameters are accepted only for `meta.k8s.io`/`v1`;
/// anything else is not a format this server knows and is left alone rather
/// than silently mis-served.
pub(crate) fn parse_accept(accept: &str) -> PartialRequest {
    for media in accept.split(',') {
        let mut parts = media.split(';').map(str::trim);
        let Some(base) = parts.next() else { continue };
        if !(base.eq_ignore_ascii_case("application/json")
            || base.eq_ignore_ascii_case("application/vnd.kubernetes.protobuf")
            || base == "*/*")
        {
            continue;
        }
        let (mut as_kind, mut group, mut version) = (None, None, None);
        for p in parts {
            let Some((k, v)) = p.split_once('=') else {
                continue;
            };
            match k.trim() {
                "as" => as_kind = Some(v.trim()),
                "g" => group = Some(v.trim()),
                "v" => version = Some(v.trim()),
                _ => {}
            }
        }
        let Some(as_kind) = as_kind else { continue };
        if as_kind != KIND_SINGLE && as_kind != KIND_LIST {
            continue;
        }
        // Defaulting an absent g/v to meta.k8s.io/v1 matches what clients send
        // in practice; a *different* group or version is a format we do not
        // implement, so fall through to the next media range.
        if group.unwrap_or("meta.k8s.io") != "meta.k8s.io" {
            continue;
        }
        if version.unwrap_or("v1") != "v1" {
            continue;
        }
        return PartialRequest::Yes;
    }
    PartialRequest::No
}

/// Project one object to its metadata, keeping nothing else.
///
/// Anything without a `metadata` is returned unchanged: a Status reply to a
/// failed request is not an object and must reach the client as a Status, not
/// as an empty PartialObjectMetadata that would read as success.
fn project_object(mut value: serde_json::Value) -> serde_json::Value {
    let Some(obj) = value.as_object_mut() else {
        return value;
    };
    if obj.get("kind").and_then(|k| k.as_str()) == Some("Status") {
        return value;
    }
    let Some(metadata) = obj.remove("metadata") else {
        return value;
    };
    serde_json::json!({
        "kind": KIND_SINGLE,
        "apiVersion": META_API_VERSION,
        "metadata": metadata,
    })
}

/// Project a whole response body — a List becomes a PartialObjectMetadataList
/// with each item projected; anything else is projected as a single object.
pub(crate) fn project_body(value: serde_json::Value) -> serde_json::Value {
    let is_list = value
        .get("kind")
        .and_then(|k| k.as_str())
        .is_some_and(|k| k.ends_with("List"))
        && value.get("items").is_some();

    if !is_list {
        return project_object(value);
    }

    let mut out = serde_json::Map::new();
    out.insert("kind".into(), serde_json::json!(KIND_LIST));
    out.insert("apiVersion".into(), serde_json::json!(META_API_VERSION));
    // The list's own metadata carries the resourceVersion a watch resumes
    // from, so it is preserved rather than projected away.
    if let Some(md) = value.get("metadata") {
        out.insert("metadata".into(), md.clone());
    }
    let items = match value.get("items") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|i| project_object(i.clone()))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    out.insert("items".into(), serde_json::Value::Array(items));
    serde_json::Value::Object(out)
}

/// Project a single newline-delimited watch event, leaving the `type` and
/// replacing only the `object`.
pub(crate) fn project_watch_event(line: &str) -> String {
    let Ok(mut event) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string();
    };
    let Some(obj) = event.as_object_mut() else {
        return line.to_string();
    };
    let Some(inner) = obj.remove("object") else {
        return line.to_string();
    };
    obj.insert("object".into(), project_object(inner));
    serde_json::to_string(&event).unwrap_or_else(|_| line.to_string())
}

/// Honour `as=PartialObjectMetadata` in `Accept` by projecting the response.
///
/// Applied as one outer layer so no handler can forget it. Non-JSON replies,
/// non-2xx replies and replies to requests that did not ask for the format are
/// passed through untouched.
pub async fn partial_object_metadata_middleware(request: Request, next: Next) -> Response {
    let wants = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(parse_accept)
        .unwrap_or(PartialRequest::No);

    // A watch response is a stream that never ends within one buffering read,
    // so the two cases are handled differently and the decision is made before
    // the body is touched.
    let is_watch = request
        .uri()
        .query()
        .map(crate::handlers::watch::query_is_watch)
        .unwrap_or(false);

    let response = next.run(request).await;

    if wants == PartialRequest::No || !response.status().is_success() {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    if is_watch {
        // Transform the stream line by line. A chunk is not guaranteed to be a
        // whole line, so partial lines are carried across chunks; dropping that
        // buffer would corrupt the last event of every chunk boundary.
        let stream = body.into_data_stream();
        let mut pending = String::new();
        let projected = stream.flat_map(move |chunk| {
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
                            project_watch_event(trimmed)
                        ))));
                    }
                }
                Err(e) => out.push(Err(e)),
            }
            futures::stream::iter(out)
        });
        return Response::from_parts(parts, Body::from_stream(projected));
    }

    let bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        // The body could not be buffered; there is nothing left to forward, so
        // report that rather than returning a truncated object.
        Err(_) => {
            return Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("failed to read response body"))
                .unwrap();
        }
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        // Not JSON — pass it through exactly as the handler wrote it.
        return Response::from_parts(parts, Body::from(bytes));
    };
    let projected = project_body(value);
    let out = serde_json::to_vec(&projected).unwrap_or_else(|_| bytes.to_vec());
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_accept_asks_for_nothing() {
        assert_eq!(parse_accept("application/json"), PartialRequest::No);
        assert_eq!(parse_accept("*/*"), PartialRequest::No);
        assert_eq!(parse_accept(""), PartialRequest::No);
    }

    #[test]
    fn the_header_clients_actually_send_is_recognized() {
        // Verbatim from cert-manager's cainjector.
        assert_eq!(
            parse_accept(
                "application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io, application/json"
            ),
            PartialRequest::Yes
        );
        assert_eq!(
            parse_accept("application/json;as=PartialObjectMetadata;v=v1;g=meta.k8s.io"),
            PartialRequest::Yes
        );
    }

    /// A group or version this server does not implement must not be answered
    /// as if it were `meta.k8s.io/v1` — that would hand the client a shape it
    /// did not ask for.
    #[test]
    fn an_unknown_group_or_version_is_not_claimed() {
        assert_eq!(
            parse_accept("application/json;as=PartialObjectMetadata;v=v1;g=example.com"),
            PartialRequest::No
        );
        assert_eq!(
            parse_accept("application/json;as=PartialObjectMetadata;v=v2;g=meta.k8s.io"),
            PartialRequest::No
        );
        assert_eq!(
            parse_accept("application/json;as=Table;v=v1;g=meta.k8s.io"),
            PartialRequest::No
        );
    }

    /// The point of the whole module.
    #[test]
    fn a_secrets_data_does_not_survive_the_projection() {
        let secret = serde_json::json!({
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": "guts-internal-api-key", "namespace": "guts-system"},
            "type": "Opaque",
            "data": {"api-key": "c3VwZXItc2VjcmV0"},
        });
        let out = project_body(secret);
        assert_eq!(out["kind"], "PartialObjectMetadata");
        assert_eq!(out["apiVersion"], "meta.k8s.io/v1");
        assert_eq!(out["metadata"]["name"], "guts-internal-api-key");
        assert!(out.get("data").is_none(), "data survived: {out}");
        assert!(out.get("type").is_none());
        assert!(!serde_json::to_string(&out).unwrap().contains("c3VwZXItc2VjcmV0"));
    }

    #[test]
    fn a_list_projects_every_item_and_keeps_its_resource_version() {
        let list = serde_json::json!({
            "kind": "SecretList",
            "apiVersion": "v1",
            "metadata": {"resourceVersion": "4711"},
            "items": [
                {"kind": "Secret", "metadata": {"name": "a"}, "data": {"k": "dg=="}},
                {"kind": "Secret", "metadata": {"name": "b"}, "data": {"k": "dg=="}},
            ],
        });
        let out = project_body(list);
        assert_eq!(out["kind"], "PartialObjectMetadataList");
        assert_eq!(out["metadata"]["resourceVersion"], "4711");
        assert_eq!(out["items"].as_array().unwrap().len(), 2);
        for item in out["items"].as_array().unwrap() {
            assert_eq!(item["kind"], "PartialObjectMetadata");
            assert!(item.get("data").is_none());
        }
        assert!(!serde_json::to_string(&out).unwrap().contains("dg=="));
    }

    #[test]
    fn a_watch_event_keeps_its_type_and_loses_the_body() {
        let line = r#"{"type":"MODIFIED","object":{"kind":"Secret","metadata":{"name":"a"},"data":{"k":"dg=="}}}"#;
        let out: serde_json::Value = serde_json::from_str(&project_watch_event(line)).unwrap();
        assert_eq!(out["type"], "MODIFIED");
        assert_eq!(out["object"]["kind"], "PartialObjectMetadata");
        assert_eq!(out["object"]["metadata"]["name"], "a");
        assert!(out["object"].get("data").is_none());
    }

    /// An error reply is a Status, not an object. Projecting it would strip the
    /// reason and message and leave a body that reads as a successful empty
    /// result.
    #[test]
    fn a_status_reply_is_left_alone() {
        let status = serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": "secrets \"nope\" not found", "reason": "NotFound", "code": 404,
            "metadata": {},
        });
        let out = project_body(status.clone());
        assert_eq!(out, status);
    }

    /// Empty lists and objects without metadata must not panic or invent one.
    #[test]
    fn degenerate_bodies_survive() {
        let empty = serde_json::json!({"kind": "SecretList", "apiVersion": "v1", "items": []});
        assert_eq!(project_body(empty)["items"].as_array().unwrap().len(), 0);
        let no_md = serde_json::json!({"kind": "Weird", "apiVersion": "v1"});
        assert_eq!(project_body(no_md.clone()), no_md);
        assert_eq!(project_watch_event("not json at all"), "not json at all");
    }
}
