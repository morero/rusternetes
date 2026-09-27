//! The kubelet's `/stats/summary` payload, as this platform publishes it.
//!
//! Upstream, a kubelet serves this over HTTPS on :10250 and the api-server
//! forwards a `nodes/proxy` request to it. rusternetes has no kubelet HTTP
//! server — `metrics_bind_port` defaults to `None` — because its components
//! share storage rather than calling one another: the kubelet publishes and the
//! api-server serves, which is already how `metrics.k8s.io` works here.
//!
//! So this type is what the kubelet writes to storage each tick, and the
//! api-server serves at the `nodes/proxy/stats/summary` path. A client cannot
//! tell the difference and does not need to — the contract is the upstream one,
//! and how it is satisfied is this platform's business. What a reader of the
//! api-server MUST be able to tell is which kubelet endpoints are served
//! natively and which are genuinely proxied, which is why those have separate
//! routes rather than a branch inside the proxy.
//!
//! Deliberately a subset. Only the fields something here actually reads are
//! modelled: `node.fs` for disk utilization, which is the one thing
//! `metrics.k8s.io` cannot express. Inventing the rest of the summary schema
//! would be fabricating numbers we do not measure.

use crate::time::k8s_time;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Filesystem usage, in the shape the kubelet's summary API reports it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FsStats {
    /// Bytes in use on the filesystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    /// The filesystem's total size. Upstream calls this `capacityBytes`, and a
    /// consumer computing a percentage needs both halves from one source —
    /// mixing this with the Node's `allocatable` would compare a real
    /// filesystem against a scheduling budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_bytes: Option<u64>,
    /// Bytes available to an unprivileged writer. Less than
    /// `capacity - used` on a filesystem with reserved blocks, which is why it
    /// is reported rather than derived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_bytes: Option<u64>,
}

/// The `node` half of a summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeStats {
    pub node_name: String,
    #[serde(
        serialize_with = "k8s_time::serialize_required",
        deserialize_with = "k8s_time::deserialize_required"
    )]
    pub start_time: DateTime<Utc>,
    /// The node's root filesystem — what `disk_pct` consumers read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsStats>,
}

/// What `GET /api/v1/nodes/<name>/proxy/stats/summary` answers with.
///
/// `pods` is deliberately absent rather than empty: an empty list asserts "this
/// node runs no pods", which would be a lie. A consumer needing per-pod stats
/// should read `metrics.k8s.io` PodMetrics, which this platform does serve.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatsSummary {
    pub node: NodeStats,
}

/// Where a node's stats summary lives in storage.
///
/// One definition, used by the kubelet that writes it and the api-server that
/// serves it. Two string literals in two crates is how a producer and a consumer
/// end up disagreeing about a key and nobody notices until the data is silently
/// absent.
pub fn node_stats_summary_key(node_name: &str) -> String {
    format!("/registry/rusternetes.io/nodestats/{node_name}")
}

impl FsStats {
    /// Reads filesystem usage for `path` via `statvfs`.
    ///
    /// `f_bavail` (available to an unprivileged writer) rather than `f_bfree`
    /// (free including reserved blocks) is what a client should compare against,
    /// and `used` is computed as total minus free so it matches what `df`
    /// reports rather than what a caller could derive from `available`.
    #[cfg(unix)]
    pub fn for_path(path: &std::path::Path) -> Option<FsStats> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: statvfs writes into a zeroed struct we own, and c_path is a
        // valid NUL-terminated string that outlives the call.
        let stat = unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
                return None;
            }
            stat
        };
        // f_frsize is the fragment size, which is the unit f_blocks counts in.
        // f_bsize is the preferred I/O block size and is NOT interchangeable —
        // on some filesystems they differ and using the wrong one misreports
        // capacity by a whole multiple.
        let unit = if stat.f_frsize > 0 {
            stat.f_frsize as u64
        } else {
            stat.f_bsize as u64
        };
        let capacity = stat.f_blocks as u64 * unit;
        let free = stat.f_bfree as u64 * unit;
        Some(FsStats {
            used_bytes: Some(capacity.saturating_sub(free)),
            capacity_bytes: Some(capacity),
            available_bytes: Some(stat.f_bavail as u64 * unit),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node's own filesystem always exists, so this must produce real
    /// numbers rather than None — a test that accepts None would pass on a
    /// broken statvfs binding.
    #[cfg(unix)]
    #[test]
    fn fs_stats_reads_a_real_filesystem() {
        let stats = FsStats::for_path(std::path::Path::new("/")).expect("/ is a filesystem");
        let capacity = stats.capacity_bytes.expect("capacity");
        let used = stats.used_bytes.expect("used");
        let available = stats.available_bytes.expect("available");

        assert!(capacity > 0, "a real filesystem has a size");
        assert!(used <= capacity, "used {used} exceeds capacity {capacity}");
        assert!(
            available <= capacity,
            "available {available} exceeds capacity {capacity}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fs_stats_is_none_for_a_path_that_does_not_exist() {
        assert!(FsStats::for_path(std::path::Path::new("/nonexistent-zzz")).is_none());
    }

    /// The wire shape is the upstream one, because the contract is upstream's
    /// even though the implementation is not.
    #[test]
    fn summary_serialises_in_the_kubelet_shape() {
        let summary = NodeStatsSummary {
            node: NodeStats {
                node_name: "n1".to_string(),
                start_time: Utc::now(),
                fs: Some(FsStats {
                    used_bytes: Some(10),
                    capacity_bytes: Some(100),
                    available_bytes: Some(85),
                }),
            },
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["node"]["nodeName"], "n1");
        assert_eq!(json["node"]["fs"]["usedBytes"], 10);
        assert_eq!(json["node"]["fs"]["capacityBytes"], 100);
        assert_eq!(json["node"]["fs"]["availableBytes"], 85);
        assert!(
            json["node"].get("pods").is_none(),
            "pods is absent, not empty"
        );
    }
}
