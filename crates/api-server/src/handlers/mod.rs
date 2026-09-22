pub mod admission_webhook;
pub mod apply;
pub mod authentication;
pub mod authorization;
pub mod certificates;
pub mod componentstatus;
pub mod configmap;
pub mod controllerrevision;
pub mod crd;
pub mod cronjob;
pub mod csidriver;
pub mod csinode;
pub mod csistoragecapacity;
pub mod custom_metrics;
pub mod custom_resource;
pub mod daemonset;
pub mod defaults;
pub mod deployment;
pub mod deviceclass;
pub mod discovery;
pub mod dryrun;
pub mod endpoints;
pub mod endpointslice;
pub mod event;
#[allow(dead_code)]
pub mod filtering;
pub mod finalizers;
pub mod flowcontrol;
pub mod generic;
pub mod generic_patch;
#[allow(dead_code)]
pub mod health;
pub mod horizontalpodautoscaler;
pub mod ingress;
pub mod ingressclass;
pub mod ipaddress;
pub mod job;
pub mod lease;
pub mod lifecycle;
pub mod limitrange;
pub mod metrics;
pub mod namespace;
pub mod networkpolicy;
pub mod node;
pub mod openapi;
pub mod persistentvolume;
pub mod persistentvolumeclaim;
pub mod pod;
pub mod pod_subresources;
pub mod poddisruptionbudget;
pub mod podtemplate;
pub mod printers;
pub mod priorityclass;
pub mod proxy;
pub mod rbac;
pub mod replicaset;
pub mod replicationcontroller;
pub mod resourceclaim;
pub mod resourceclaimtemplate;
pub mod resourcequota;
pub mod resourceslice;
pub mod runtimeclass;
pub mod scale;
pub mod secret;
pub mod service;
pub mod service_account;
pub mod servicecidr;
pub mod statefulset;
pub mod status;
pub mod storageclass;
pub mod table;
pub mod validating_admission_policy;
pub mod validation;
pub mod volumeattachment;
pub mod volumeattributesclass;
pub mod volumesnapshot;
pub mod volumesnapshotclass;
pub mod volumesnapshotcontent;
pub mod watch;

/// Compute the list-level resourceVersion from the max item resourceVersion.
/// This uses etcd mod_revisions (from individual items) rather than timestamps.
/// Using timestamps causes LIST+WATCH failures because watches start from a
/// revision that etcd never reaches.
pub fn list_resource_version<T: serde::Serialize>(items: &[T]) -> String {
    let mut max_rv: i64 = 0;
    for item in items {
        if let Ok(v) = serde_json::to_value(item) {
            if let Some(rv_str) = v
                .get("metadata")
                .and_then(|m| m.get("resourceVersion"))
                .and_then(|r| r.as_str())
            {
                if let Ok(rv) = rv_str.parse::<i64>() {
                    if rv > max_rv {
                        max_rv = rv;
                    }
                }
            }
        }
    }
    if max_rv > 0 {
        max_rv.to_string()
    } else {
        "1".to_string()
    }
}

/// Renders a handler's list output as a `meta.k8s.io/v1.Table` when the
/// request asked for one, using [`printers`]' per-kind columns.
///
/// Returns `None` when the request did not ask for a table, so a call site
/// reads as `if let Some(table) = table_response(...) { return Json(table) }`
/// and otherwise falls through to whatever it served before. That is the
/// point: a handler gets real `kubectl get` columns without knowing anything
/// about tables beyond one line, and handlers that never knew about them at
/// all can be converted one at a time.
///
/// A kind [`printers`] has no entry for falls back to NAME and AGE — the
/// behaviour every kind had before that module existed, and still correct,
/// just sparse.
///
/// So does a kind whose cells do not line up with its columns. kubectl matches
/// them by position, so a mismatch prints values under the wrong headers —
/// a `Service`'s ports under `TYPE` — which is worse than sparse, because it
/// is wrong and looks right. The whole table falls back rather than only the
/// offending row: a table whose rows have different shapes is not a table.
pub fn table_response<T: serde::Serialize>(
    accept: Option<&str>,
    kind: &str,
    items: &[T],
    resource_version: Option<String>,
) -> Option<table::Table> {
    if !table::wants_table(accept) {
        return None;
    }

    let objects: Vec<serde_json::Value> = items
        .iter()
        .map(|i| serde_json::to_value(i).unwrap_or(serde_json::Value::Null))
        .collect();

    let rendered = printers::columns_for(kind).and_then(|columns| {
        let rows: Option<Vec<Vec<serde_json::Value>>> = objects
            .iter()
            .map(|obj| printers::cells_for(kind, obj).filter(|c| c.len() == columns.len()))
            .collect();
        rows.map(|rows| (columns, rows))
    });

    let mut table = table::Table::new();
    match rendered {
        Some((columns, rows)) => {
            for column in &columns {
                table = table.add_column(column.name, column.kind, "", "", 0);
            }
            for (cells, obj) in rows.into_iter().zip(objects) {
                table = table.add_row(cells, Some(obj));
            }
        }
        None => {
            table = table
                .add_column("NAME", "string", "name", "", 0)
                .add_column("AGE", "string", "", "", 0);
            for obj in objects {
                let name = obj
                    .pointer("/metadata/name")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let age = serde_json::Value::String(printers::age_of(&obj));
                table = table.add_row(vec![name, age], Some(obj));
            }
        }
    }
    Some(table.with_metadata(resource_version, None, None))
}

/// The `Status` body a `deletecollection` must answer with.
///
/// Kubernetes answers deleteCollection with a `Status` object, not an empty
/// 200 — see staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go.
/// Clients deserialize the body unconditionally, so a bodyless 200 is not a
/// lenient success, it is a parse error:
///
///   Error deserializing response: EOF while parsing a value at line 1 column 0
///
/// Found with `workflow-operator`, which deletes a `Workflow`'s runner Jobs
/// by label selector on cleanup. Every such call failed on the empty body, so
/// the operator logged "the Jobs are leaked and must be removed by hand" and
/// leaked them — the deletes had in fact succeeded, and only the reply was
/// wrong. `statefulsets` already answered correctly; the other 57
/// `deletecollection` handlers did not.
pub fn deletecollection_status(kind: &str) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Success",
        "code": 200,
        "details": { "kind": kind }
    }))
}

#[cfg(test)]
mod deletecollection_tests {
    use super::*;

    /// A `deletecollection` reply has to be a parseable `Status`. The bug this
    /// guards is not a wrong field, it is *no body at all*: clients
    /// deserialize unconditionally, so an empty 200 reads as
    /// "EOF while parsing a value at line 1 column 0" and a successful
    /// delete is reported as a failure.
    #[test]
    fn deletecollection_answers_with_a_status() {
        let axum::Json(body) = deletecollection_status("Job");
        assert_eq!(body["kind"], "Status");
        assert_eq!(body["apiVersion"], "v1");
        assert_eq!(body["status"], "Success");
        assert_eq!(body["code"], 200);
        assert_eq!(body["details"]["kind"], "Job");
        // It must survive a round trip as JSON, which is all the client does.
        let encoded = serde_json::to_string(&body).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded["status"], "Success");
    }
}

#[cfg(test)]
mod table_response_tests {
    use super::*;
    use serde_json::json;

    fn service() -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "guts", "creationTimestamp": "2026-09-20T00:00:00Z"},
            "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.12",
                     "ports": [{"port": 3000, "protocol": "TCP"}]},
        })
    }

    /// The whole reason `printers` exists: `kubectl get svc` used to print a
    /// Service with NAME and AGE and nothing that makes the command worth
    /// running.
    #[test]
    fn a_known_kind_gets_its_real_columns() {
        let table = table_response(
            Some("application/json;as=Table"),
            "Service",
            &[service()],
            None,
        )
        .expect("asked for a table");
        let headers: Vec<&str> = table
            .column_definitions
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(headers.contains(&"TYPE"), "got {headers:?}");
        assert!(headers.contains(&"CLUSTER-IP"), "got {headers:?}");
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].cells.len(), table.column_definitions.len());
    }

    /// Not a table request: the caller serves what it always served.
    #[test]
    fn a_plain_request_is_left_alone() {
        assert!(table_response(Some("application/json"), "Service", &[service()], None).is_none());
        assert!(table_response(None, "Service", &[service()], None).is_none());
    }

    /// A kind `printers` has no entry for still gets a usable table — the
    /// behaviour every kind had before that module existed.
    #[test]
    fn an_unknown_kind_falls_back_to_name_and_age() {
        let obj = json!({
            "kind": "WidgetThing",
            "metadata": {"name": "w1", "creationTimestamp": "2026-09-20T00:00:00Z"},
        });
        let table = table_response(Some("as=Table"), "WidgetThing", &[obj], None).unwrap();
        let headers: Vec<&str> = table
            .column_definitions
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(headers, vec!["NAME", "AGE"]);
        assert_eq!(table.rows[0].cells[0], json!("w1"));
    }

    /// kubectl lines cells up with headers by position, so a row of the wrong
    /// width prints values under the wrong headers — a Service's ports under
    /// TYPE. That is worse than sparse, because it is wrong and looks right.
    /// An object that does not carry what its kind's cells need must not be
    /// able to produce one.
    #[test]
    fn a_row_that_cannot_be_built_falls_back_for_the_whole_table() {
        // Not a Service at all, rendered as one.
        let bogus = json!({"metadata": {"name": "not-a-service"}});
        let table = table_response(Some("as=Table"), "Service", &[service(), bogus], None).unwrap();
        for row in &table.rows {
            assert_eq!(
                row.cells.len(),
                table.column_definitions.len(),
                "every row must match the header count"
            );
        }
    }

    /// The full object rides along in each row, which is what `kubectl get -o
    /// wide` and client-side printers read back.
    #[test]
    fn each_row_carries_its_object() {
        let table = table_response(Some("as=Table"), "Service", &[service()], None).unwrap();
        assert_eq!(
            table.rows[0]
                .object
                .as_ref()
                .unwrap()
                .pointer("/metadata/name"),
            Some(&json!("guts"))
        );
    }
}
