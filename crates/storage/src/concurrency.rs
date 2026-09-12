/// Concurrency control module for optimistic locking with resourceVersion
use rusternetes_common::Error;

/// Extract resourceVersion from metadata
pub fn extract_resource_version(metadata: &serde_json::Value) -> Option<String> {
    metadata
        .get("resourceVersion")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Validate that the provided resourceVersion matches the expected version
pub fn validate_resource_version(
    expected: Option<&str>,
    actual: Option<&str>,
) -> Result<(), Error> {
    match (expected, actual) {
        (Some(expected_rv), Some(actual_rv)) => {
            if expected_rv != actual_rv {
                return Err(Error::Conflict(format!(
                    "resourceVersion mismatch: expected '{}', got '{}'",
                    expected_rv, actual_rv
                )));
            }
            Ok(())
        }
        (Some(expected_rv), None) => Err(Error::Conflict(format!(
            "resourceVersion mismatch: expected '{}', got none",
            expected_rv
        ))),
        _ => Ok(()), // If no expected version specified, allow update
    }
}

/// Whether an incoming write is a genuine no-op — identical to the
/// currently-stored resource except for `metadata.resourceVersion` (the
/// incoming resource legitimately carries the client's own last-known,
/// about-to-be-stale resourceVersion; that's expected and must not count as
/// a difference).
///
/// Real Kubernetes' `storage.Interface.GuaranteedUpdate` contract requires
/// this: "updating an object twice with the same data except
/// ResourceVersion... must be a no-op" (no revision bump, no watch event) —
/// otherwise a well-behaved controller's own repeated identical
/// status/resource writes re-trigger its own watch and loop forever.
/// Confirmed live: an unmodified real-world operator (CloudNativePG)
/// re-issuing identical RoleBinding/Lease/status writes against a backend
/// with no no-op detection produced a tight, indefinite reconcile loop (see
/// ISSUES.md).
pub fn is_no_op_update(incoming_json: &str, stored_json: &str) -> bool {
    let Ok(mut incoming) = serde_json::from_str::<serde_json::Value>(incoming_json) else {
        return false;
    };
    let Ok(mut stored) = serde_json::from_str::<serde_json::Value>(stored_json) else {
        return false;
    };
    if let Some(m) = incoming.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        m.remove("resourceVersion");
    }
    if let Some(m) = stored.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        m.remove("resourceVersion");
    }
    incoming == stored
}

/// Convert etcd mod_revision to resourceVersion string
pub fn mod_revision_to_resource_version(mod_revision: i64) -> String {
    mod_revision.to_string()
}

/// Parse resourceVersion string to mod_revision
pub fn resource_version_to_mod_revision(resource_version: &str) -> Result<i64, Error> {
    resource_version.parse::<i64>().map_err(|_| {
        Error::InvalidResource(format!("Invalid resourceVersion: {}", resource_version))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_resource_version() {
        let metadata = json!({
            "name": "test",
            "resourceVersion": "12345"
        });

        assert_eq!(
            extract_resource_version(&metadata),
            Some("12345".to_string())
        );

        let no_rv = json!({"name": "test"});
        assert_eq!(extract_resource_version(&no_rv), None);
    }

    #[test]
    fn test_validate_resource_version() {
        // Matching versions should succeed
        assert!(validate_resource_version(Some("100"), Some("100")).is_ok());

        // No expected version should succeed
        assert!(validate_resource_version(None, Some("100")).is_ok());

        // Mismatched versions should fail
        assert!(validate_resource_version(Some("100"), Some("200")).is_err());

        // Expected version but actual is missing should fail
        assert!(validate_resource_version(Some("100"), None).is_err());
    }

    #[test]
    fn is_no_op_update_true_when_only_resource_version_differs() {
        let incoming = json!({"metadata": {"name": "x", "resourceVersion": "5"}, "spec": {"a": 1}}).to_string();
        let stored = json!({"metadata": {"name": "x", "resourceVersion": "4"}, "spec": {"a": 1}}).to_string();
        assert!(is_no_op_update(&incoming, &stored));
    }

    #[test]
    fn is_no_op_update_false_when_content_actually_differs() {
        let incoming = json!({"metadata": {"name": "x", "resourceVersion": "5"}, "spec": {"a": 2}}).to_string();
        let stored = json!({"metadata": {"name": "x", "resourceVersion": "4"}, "spec": {"a": 1}}).to_string();
        assert!(!is_no_op_update(&incoming, &stored));
    }

    #[test]
    fn is_no_op_update_false_on_unparseable_json() {
        assert!(!is_no_op_update("not json", "{}"));
    }

    #[test]
    fn test_mod_revision_conversion() {
        let rv = mod_revision_to_resource_version(12345);
        assert_eq!(rv, "12345");

        let mod_rev = resource_version_to_mod_revision("12345").unwrap();
        assert_eq!(mod_rev, 12345);

        assert!(resource_version_to_mod_revision("invalid").is_err());
    }
}
