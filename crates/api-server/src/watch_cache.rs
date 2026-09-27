//! Watch Cache / Multiplexer
//!
//! Maintains a single etcd watch per resource prefix and fans out events
//! to all subscribed client watches. This avoids creating N etcd watches
//! for N clients, which overwhelms etcd and exhausts HTTP/2 stream limits.

use rusternetes_common::Error;
use rusternetes_storage::StorageBackend;
use rusternetes_storage::{Storage, WatchEvent, WatchStream};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

/// Maximum number of events to retain in the history ring buffer per prefix
/// K8s default watch cache capacity is 1000 events.
/// 5000 × 26 prefixes × ~3KB = ~390MB of memory.
const HISTORY_CAPACITY: usize = 500;

/// A cached watch event with metadata
#[derive(Debug, Clone)]
pub struct CachedWatchEvent {
    pub event: WatchEventData,
    pub revision: i64,
}

/// The event data (simplified from WatchEvent).
/// Uses Arc<String> for value JSON to avoid cloning large JSON strings
/// across multiple broadcast subscribers and the history buffer.
#[derive(Debug, Clone)]
pub enum WatchEventData {
    Added(String, Arc<String>),    // key, value JSON
    Modified(String, Arc<String>), // key, value JSON
    Deleted(String, Arc<String>),  // key, previous value JSON
}

/// WatchCache manages shared watch streams for resource prefixes.
/// Instead of one etcd watch per client, we have one per prefix.
pub struct WatchCache {
    /// Map of resource prefix → broadcast sender
    /// Each prefix has one etcd watch that broadcasts to all subscribers
    watchers: RwLock<HashMap<String, broadcast::Sender<CachedWatchEvent>>>,
    storage: Arc<StorageBackend>,
    /// Current revision counter (approximation based on timestamp)
    #[allow(dead_code)]
    revision: RwLock<i64>,
    /// Ring buffer of recent events per prefix for history replay
    history: Arc<RwLock<HashMap<String, VecDeque<CachedWatchEvent>>>>,
}

impl WatchCache {
    pub fn new(storage: Arc<StorageBackend>) -> Self {
        Self {
            watchers: RwLock::new(HashMap::new()),
            storage,
            revision: RwLock::new(0), // Will be populated from etcd events
            history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to watch events for a resource prefix.
    /// Returns a broadcast receiver that will receive all events for this prefix.
    /// If no etcd watch exists for this prefix, one is started.
    pub async fn subscribe(&self, prefix: &str) -> broadcast::Receiver<CachedWatchEvent> {
        // Check if we already have a watcher for this prefix
        {
            let watchers = self.watchers.read().await;
            if let Some(tx) = watchers.get(prefix) {
                return tx.subscribe();
            }
        }

        // Create a new watcher
        // Buffer size: K8s default watch cache is 1000 events. 16384 used ~1.2GB
        // of memory with 26 prefixes × 16K events × ~3KB each.
        let (tx, rx) = broadcast::channel(1000);
        {
            let mut watchers = self.watchers.write().await;
            // Double-check after acquiring write lock
            if let Some(existing_tx) = watchers.get(prefix) {
                return existing_tx.subscribe();
            }
            watchers.insert(prefix.to_string(), tx.clone());
        }

        // Start the etcd watch in a background task
        let storage = self.storage.clone();
        let prefix_owned = prefix.to_string();
        let tx_clone = tx.clone();
        let history_ref = self.history.clone();

        tokio::spawn(async move {
            info!(
                "WatchCache: starting shared watch for prefix {}",
                prefix_owned
            );
            loop {
                match storage.watch(&prefix_owned).await {
                    Ok(mut stream) => {
                        use futures::StreamExt;
                        while let Some(event_result) = stream.next().await {
                            // Extract the resourceVersion from the event value's metadata.
                            // Uses string search instead of full JSON parse since the format
                            // is controlled by our inject_resource_version() and is always
                            // "resourceVersion":"<digits>".
                            fn extract_rv(value: &str) -> i64 {
                                const NEEDLE: &str = "\"resourceVersion\":\"";
                                if let Some(start) = value.find(NEEDLE) {
                                    let num_start = start + NEEDLE.len();
                                    if let Some(end) = value[num_start..].find('"') {
                                        return value[num_start..num_start + end]
                                            .parse::<i64>()
                                            .unwrap_or(0);
                                    }
                                }
                                0
                            }

                            let cached = match event_result {
                                Ok(WatchEvent::Added(key, value)) => {
                                    let rev = extract_rv(&value);
                                    CachedWatchEvent {
                                        event: WatchEventData::Added(key, Arc::new(value)),
                                        revision: rev,
                                    }
                                }
                                Ok(WatchEvent::Modified(key, value)) => {
                                    let rev = extract_rv(&value);
                                    CachedWatchEvent {
                                        event: WatchEventData::Modified(key, Arc::new(value)),
                                        revision: rev,
                                    }
                                }
                                Ok(WatchEvent::Deleted(key, prev_value)) => {
                                    let rev = extract_rv(&prev_value);
                                    CachedWatchEvent {
                                        event: WatchEventData::Deleted(key, Arc::new(prev_value)),
                                        revision: rev,
                                    }
                                }
                                Err(_) => {
                                    // Transient error, continue
                                    continue;
                                }
                            };

                            // Append to history ring buffer
                            {
                                let mut hist: tokio::sync::RwLockWriteGuard<
                                    '_,
                                    HashMap<String, VecDeque<CachedWatchEvent>>,
                                > = history_ref.write().await;
                                let buf = hist.entry(prefix_owned.clone()).or_default();
                                buf.push_back(cached.clone());
                                while buf.len() > HISTORY_CAPACITY {
                                    buf.pop_front();
                                }
                            }

                            // Broadcast to live subscribers (Err is OK if no receivers)
                            let _ = tx_clone.send(cached);
                        }
                        // Stream ended, reconnect after brief pause
                        // Don't check subscriber count here — new subscribers may arrive
                        debug!(
                            "WatchCache: stream ended for {}, reconnecting",
                            prefix_owned
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        error!(
                            "WatchCache: failed to create watch for {}: {}",
                            prefix_owned, e
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        rx
    }

    /// Get the current approximate revision
    #[allow(dead_code)]
    pub async fn current_revision(&self) -> i64 {
        *self.revision.read().await
    }

    /// Get all cached events for a prefix with revision > the given revision.
    pub async fn get_events_since(&self, prefix: &str, revision: i64) -> Vec<CachedWatchEvent> {
        let hist = self.history.read().await;
        match hist.get(prefix) {
            Some(buf) => buf
                .iter()
                .filter(|e| e.revision > revision)
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Subscribe to watch events and replay any historical events since the
    /// given resourceVersion. Returns (historical_events, live_receiver).
    /// The caller should send historical events first, then consume the receiver.
    pub async fn subscribe_from(
        &self,
        prefix: &str,
        since_revision: i64,
    ) -> (Vec<CachedWatchEvent>, broadcast::Receiver<CachedWatchEvent>) {
        // Subscribe first to avoid missing events between history query and subscribe
        let rx = self.subscribe(prefix).await;
        // Then get historical events
        let history = self.get_events_since(prefix, since_revision).await;
        (history, rx)
    }
}

/// Convert a broadcast receiver into a WatchStream compatible with existing handlers.
pub fn broadcast_to_stream(mut rx: broadcast::Receiver<CachedWatchEvent>) -> WatchStream {
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(cached) => {
                    let event = match cached.event {
                        WatchEventData::Added(key, value) => WatchEvent::Added(key, (*value).clone()),
                        WatchEventData::Modified(key, value) => WatchEvent::Modified(key, (*value).clone()),
                        WatchEventData::Deleted(key, prev) => WatchEvent::Deleted(key, (*prev).clone()),
                    };
                    yield Ok(event);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // The subscriber fell behind and the channel dropped `n`
                    // events for it. Continuing here — which is what this used
                    // to do — hands the client a stream that silently skipped
                    // events it will never learn about, so its cache stays
                    // wrong for as long as the watch lives. That is how
                    // kube-state-metrics came to export several copies of one
                    // EndpointSlice, each with the creationTimestamp of a
                    // recreation whose DELETE it never saw.
                    //
                    // The API contract for a gap is a 410 Gone with
                    // reason=Expired, which makes the client re-LIST and
                    // rebuild. Ending the stream with that error is the only
                    // honest option: the events are gone and cannot be
                    // replayed from a broadcast channel.
                    warn!(
                        "Watch stream lagged by {} events; ending it with 410 Gone \
                         so the client re-lists",
                        n
                    );
                    yield Err(Error::Gone(format!(
                        "too old resource version: watch fell behind by {n} events"
                    )));
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };
    Box::pin(stream)
}

/// Convert historical events + a broadcast receiver into a WatchStream.
/// Historical events are replayed first (in order), then live events follow.
pub fn broadcast_to_stream_with_history(
    history: Vec<CachedWatchEvent>,
    mut rx: broadcast::Receiver<CachedWatchEvent>,
) -> WatchStream {
    // Track the highest revision we replayed so we can deduplicate
    let max_history_rev = history.iter().map(|e| e.revision).max().unwrap_or(0);

    let stream = async_stream::stream! {
        // Replay historical events first
        for cached in history {
            let event = match cached.event {
                WatchEventData::Added(key, value) => WatchEvent::Added(key, (*value).clone()),
                WatchEventData::Modified(key, value) => WatchEvent::Modified(key, (*value).clone()),
                WatchEventData::Deleted(key, prev) => WatchEvent::Deleted(key, (*prev).clone()),
            };
            yield Ok(event);
        }

        // Then stream live events, skipping any that overlap with history
        loop {
            match rx.recv().await {
                Ok(cached) => {
                    // Skip events we already replayed from history
                    if cached.revision <= max_history_rev {
                        continue;
                    }
                    let event = match cached.event {
                        WatchEventData::Added(key, value) => WatchEvent::Added(key, (*value).clone()),
                        WatchEventData::Modified(key, value) => WatchEvent::Modified(key, (*value).clone()),
                        WatchEventData::Deleted(key, prev) => WatchEvent::Deleted(key, (*prev).clone()),
                    };
                    yield Ok(event);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // The subscriber fell behind and the channel dropped `n`
                    // events for it. Continuing here — which is what this used
                    // to do — hands the client a stream that silently skipped
                    // events it will never learn about, so its cache stays
                    // wrong for as long as the watch lives. That is how
                    // kube-state-metrics came to export several copies of one
                    // EndpointSlice, each with the creationTimestamp of a
                    // recreation whose DELETE it never saw.
                    //
                    // The API contract for a gap is a 410 Gone with
                    // reason=Expired, which makes the client re-LIST and
                    // rebuild. Ending the stream with that error is the only
                    // honest option: the events are gone and cannot be
                    // replayed from a broadcast channel.
                    warn!(
                        "Watch stream lagged by {} events; ending it with 410 Gone \
                         so the client re-lists",
                        n
                    );
                    yield Err(Error::Gone(format!(
                        "too old resource version: watch fell behind by {n} events"
                    )));
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };
    Box::pin(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn added(key: &str) -> CachedWatchEvent {
        CachedWatchEvent {
            event: WatchEventData::Added(key.into(), Arc::new("{}".into())),
            revision: 1,
        }
    }

    /// A subscriber that falls behind must be told, not quietly skipped.
    ///
    /// The old behaviour logged the lag at debug and continued, so the client
    /// kept a stream it believed was complete and never re-listed. That is how
    /// kube-state-metrics ended up exporting several copies of one
    /// EndpointSlice: the DELETEs for the earlier ones fell in a lag window.
    #[tokio::test]
    async fn a_lagged_watch_ends_with_gone_instead_of_skipping_events() {
        let (tx, rx) = broadcast::channel(2);
        // Overrun the channel before anything reads from it.
        for i in 0..8 {
            let _ = tx.send(added(&format!("/registry/pods/default/p{i}")));
        }
        drop(tx);

        let mut stream = broadcast_to_stream(rx);
        let first = stream
            .next()
            .await
            .expect("the stream must yield the lag, not end silently");
        match first {
            Err(Error::Gone(message)) => {
                assert!(
                    message.contains("fell behind"),
                    "unhelpful gap message: {message}"
                );
            }
            other => panic!("expected Gone for a lagged subscriber, got {other:?}"),
        }
        // And it stops there: the remaining events cannot be replayed, so
        // continuing would resume a stream with a hole in it.
        assert!(
            stream.next().await.is_none(),
            "the stream continued past a gap"
        );
    }

    /// The ordinary path is unaffected: events a subscriber keeps up with are
    /// delivered in order and the stream ends when the sender is dropped.
    #[tokio::test]
    async fn a_subscriber_that_keeps_up_sees_every_event() {
        let (tx, rx) = broadcast::channel(16);
        for i in 0..3 {
            let _ = tx.send(added(&format!("/registry/pods/default/p{i}")));
        }
        drop(tx);

        let mut stream = broadcast_to_stream(rx);
        let mut keys = Vec::new();
        while let Some(item) = stream.next().await {
            match item.expect("no gap was created") {
                WatchEvent::Added(key, _) => keys.push(key),
                other => panic!("unexpected event {other:?}"),
            }
        }
        assert_eq!(
            keys,
            vec![
                "/registry/pods/default/p0",
                "/registry/pods/default/p1",
                "/registry/pods/default/p2"
            ]
        );
    }
}
