use async_trait::async_trait;
use rusternetes_common::authz::AuthzStorage;
use rusternetes_common::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

pub mod concurrency;
pub mod etcd;
pub mod memory;
#[cfg(any(feature = "sqlite", feature = "redis"))]
pub mod rhino;
pub mod workqueue;

// Re-export MemoryStorage for convenient testing
pub use memory::MemoryStorage;

// Re-export work queue types
pub use workqueue::{extract_key, WorkQueue, WorkQueueConfig, RECONCILE_ALL_SENTINEL};

// Re-export RhinoStorage when sqlite or redis features are enabled
#[cfg(feature = "sqlite")]
pub type RhinoStorage = rhino::RhinoStorage<::rhino::SqliteBackend>;
#[cfg(feature = "redis")]
pub type RhinoRedisStorage = rhino::RhinoStorage<::rhino::RedisBackend>;

/// Storage trait for persisting Kubernetes resources
#[async_trait]
pub trait Storage: Send + Sync {
    /// Create a new resource
    async fn create<T>(&self, key: &str, value: &T) -> Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    /// Get a resource by key
    async fn get<T>(&self, key: &str) -> Result<T>
    where
        T: DeserializeOwned + Send + Sync;

    /// Update an existing resource
    async fn update<T>(&self, key: &str, value: &T) -> Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    /// Update a resource with raw JSON value (for GC operations)
    async fn update_raw(&self, key: &str, value: &serde_json::Value) -> Result<()>;

    /// Delete a resource
    async fn delete(&self, key: &str) -> Result<()>;

    /// List resources with a given prefix
    async fn list<T>(&self, prefix: &str) -> Result<Vec<T>>
    where
        T: Serialize + DeserializeOwned + Send + Sync;

    /// Watch for changes to resources with a given prefix
    async fn watch(&self, prefix: &str) -> Result<WatchStream>;

    /// Watch for changes starting from a specific revision
    async fn watch_from_revision(&self, prefix: &str, revision: i64) -> Result<WatchStream>;

    /// Get the current storage revision (etcd mod_revision)
    async fn current_revision(&self) -> Result<i64>;

    /// Check if a revision has been compacted (no longer available)
    async fn is_revision_compacted(&self, revision: i64) -> Result<bool>;
}

/// Event types for watch operations
#[derive(Debug, Clone)]
pub enum WatchEvent {
    Added(String, String),    // key, value
    Modified(String, String), // key, value
    Deleted(String, String),  // key, previous value (for Kubernetes compliance)
}

/// Stream of watch events
pub type WatchStream = futures::stream::BoxStream<'static, Result<WatchEvent>>;

/// Blanket implementation so `Arc<S>` can be used wherever `S: Storage` is required.
#[async_trait]
impl<S: Storage> Storage for std::sync::Arc<S> {
    async fn create<T>(&self, key: &str, value: &T) -> Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        (**self).create(key, value).await
    }

    async fn get<T>(&self, key: &str) -> Result<T>
    where
        T: DeserializeOwned + Send + Sync,
    {
        (**self).get(key).await
    }

    async fn update<T>(&self, key: &str, value: &T) -> Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        (**self).update(key, value).await
    }

    async fn update_raw(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        (**self).update_raw(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        (**self).delete(key).await
    }

    async fn list<T>(&self, prefix: &str) -> Result<Vec<T>>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        (**self).list(prefix).await
    }

    async fn watch(&self, prefix: &str) -> Result<WatchStream> {
        (**self).watch(prefix).await
    }

    async fn watch_from_revision(&self, prefix: &str, revision: i64) -> Result<WatchStream> {
        (**self).watch_from_revision(prefix, revision).await
    }

    async fn current_revision(&self) -> Result<i64> {
        (**self).current_revision().await
    }

    async fn is_revision_compacted(&self, revision: i64) -> Result<bool> {
        (**self).is_revision_compacted(revision).await
    }
}

/// Checks that the storage backend the operator asked for on the command line
/// is actually compiled into this binary, and returns a usable error if it is
/// not.
///
/// Every binary selects its backend with a `match` whose `sqlite` and `redis`
/// arms are behind `#[cfg(feature = ...)]`. Without the feature the arm does not
/// exist, so `--storage-backend sqlite` falls through to the catch-all and the
/// process comes up on **etcd** — a backend nobody asked for — logging
/// `Connecting to etcd` as though that had been the request. It then serves
/// HTTP perfectly happily and fails every single write with
/// `grpc request error: status: Unavailable, message: "tcp connect error"`,
/// which names etcd nowhere and reads like a network fault.
///
/// The cost of that is not theoretical: it has burned this project twice, once
/// on the kubelet and once on the api-server, and both times the visible
/// symptom was several layers away from a `cargo build` that omitted a feature
/// flag. A binary asked for a backend it cannot provide must say so and exit,
/// not substitute a different one silently. Being told "sqlite support was not
/// compiled into this binary" costs one line; discovering it from a gRPC error
/// costs an afternoon.
///
/// Call this before building the `StorageConfig`, so the refusal happens at
/// startup rather than at the first write.
pub fn ensure_backend_compiled_in(requested: &str) -> Result<()> {
    let available = match requested {
        "sqlite" => cfg!(feature = "sqlite"),
        "redis" => cfg!(feature = "redis"),
        // etcd is always compiled in, and an unrecognised name legitimately
        // falls through to the etcd default — neither is a silent substitution
        // of something the caller explicitly named.
        _ => true,
    };
    if available {
        return Ok(());
    }
    Err(Error::Internal(format!(
        "--storage-backend {requested} was requested, but `{requested}` support is not compiled \
         into this binary. Rebuild it with `cargo build --features {requested}`. Refusing to \
         start rather than silently falling back to etcd, which would come up, serve requests, \
         and fail every write with an opaque gRPC connection error."
    )))
}

/// Configuration for selecting a storage backend.
pub enum StorageConfig {
    /// Use an external etcd cluster.
    Etcd {
        /// Etcd endpoint URLs (e.g. `["http://localhost:2379"]`).
        endpoints: Vec<String>,
    },
    /// Use an embedded SQLite database via rhino (requires `sqlite` feature).
    #[cfg(feature = "sqlite")]
    Sqlite {
        /// Path to the SQLite database file.
        path: String,
    },
    /// Use Redis via rhino (requires `redis` feature).
    #[cfg(feature = "redis")]
    Redis {
        /// Redis connection URL (e.g. `"redis://localhost:6379"`).
        url: String,
    },
}

/// Unified storage backend that dispatches to etcd, SQLite, Redis, or in-memory at runtime.
///
/// This allows all components to remain generic over `S: Storage` while the
/// concrete backend is chosen once at startup via `StorageConfig`.
#[allow(clippy::large_enum_variant)]
pub enum StorageBackend {
    Etcd(etcd::EtcdStorage),
    #[cfg(feature = "sqlite")]
    Sqlite(RhinoStorage),
    #[cfg(feature = "redis")]
    Redis(RhinoRedisStorage),
    /// In-memory backend backed by `MemoryStorage`. Intended for unit/integration
    /// tests that need a full `ApiServerState` without an external store.
    Memory(Arc<MemoryStorage>),
}

impl StorageBackend {
    /// Create a new storage backend from the given configuration.
    pub async fn new(config: StorageConfig) -> Result<Self> {
        match config {
            StorageConfig::Etcd { endpoints } => {
                let storage = etcd::EtcdStorage::new(endpoints).await?;
                Ok(StorageBackend::Etcd(storage))
            }
            #[cfg(feature = "sqlite")]
            StorageConfig::Sqlite { path } => {
                let storage = RhinoStorage::new(&path).await?;
                Ok(StorageBackend::Sqlite(storage))
            }
            #[cfg(feature = "redis")]
            StorageConfig::Redis { url } => {
                let storage = RhinoRedisStorage::new_redis(&url).await?;
                Ok(StorageBackend::Redis(storage))
            }
        }
    }

    /// Construct an in-memory backend suitable for unit/integration tests.
    /// Wraps `MemoryStorage` in an `Arc` so the same handle can be cloned by
    /// the caller (e.g. for `inject_conflicts(...)`) while the enum owns one
    /// copy.
    pub fn new_memory() -> Self {
        StorageBackend::Memory(Arc::new(MemoryStorage::new()))
    }
}

#[async_trait]
impl Storage for StorageBackend {
    async fn create<T>(&self, key: &str, value: &T) -> Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        match self {
            StorageBackend::Etcd(s) => Storage::create(s, key, value).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::create(s, key, value).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::create(s, key, value).await,
            StorageBackend::Memory(s) => Storage::create(s.as_ref(), key, value).await,
        }
    }

    async fn get<T>(&self, key: &str) -> Result<T>
    where
        T: DeserializeOwned + Send + Sync,
    {
        match self {
            StorageBackend::Etcd(s) => Storage::get(s, key).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::get(s, key).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::get(s, key).await,
            StorageBackend::Memory(s) => Storage::get(s.as_ref(), key).await,
        }
    }

    async fn update<T>(&self, key: &str, value: &T) -> Result<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        match self {
            StorageBackend::Etcd(s) => Storage::update(s, key, value).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::update(s, key, value).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::update(s, key, value).await,
            StorageBackend::Memory(s) => Storage::update(s.as_ref(), key, value).await,
        }
    }

    async fn update_raw(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        match self {
            StorageBackend::Etcd(s) => Storage::update_raw(s, key, value).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::update_raw(s, key, value).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::update_raw(s, key, value).await,
            StorageBackend::Memory(s) => Storage::update_raw(s.as_ref(), key, value).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match self {
            StorageBackend::Etcd(s) => Storage::delete(s, key).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::delete(s, key).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::delete(s, key).await,
            StorageBackend::Memory(s) => Storage::delete(s.as_ref(), key).await,
        }
    }

    async fn list<T>(&self, prefix: &str) -> Result<Vec<T>>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        match self {
            StorageBackend::Etcd(s) => Storage::list(s, prefix).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::list(s, prefix).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::list(s, prefix).await,
            StorageBackend::Memory(s) => Storage::list(s.as_ref(), prefix).await,
        }
    }

    async fn watch(&self, prefix: &str) -> Result<WatchStream> {
        match self {
            StorageBackend::Etcd(s) => Storage::watch(s, prefix).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::watch(s, prefix).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::watch(s, prefix).await,
            StorageBackend::Memory(s) => Storage::watch(s.as_ref(), prefix).await,
        }
    }

    async fn watch_from_revision(&self, prefix: &str, revision: i64) -> Result<WatchStream> {
        match self {
            StorageBackend::Etcd(s) => Storage::watch_from_revision(s, prefix, revision).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::watch_from_revision(s, prefix, revision).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::watch_from_revision(s, prefix, revision).await,
            StorageBackend::Memory(s) => {
                Storage::watch_from_revision(s.as_ref(), prefix, revision).await
            }
        }
    }

    async fn current_revision(&self) -> Result<i64> {
        match self {
            StorageBackend::Etcd(s) => Storage::current_revision(s).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::current_revision(s).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::current_revision(s).await,
            StorageBackend::Memory(s) => Storage::current_revision(s.as_ref()).await,
        }
    }

    async fn is_revision_compacted(&self, revision: i64) -> Result<bool> {
        match self {
            StorageBackend::Etcd(s) => Storage::is_revision_compacted(s, revision).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => Storage::is_revision_compacted(s, revision).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => Storage::is_revision_compacted(s, revision).await,
            StorageBackend::Memory(s) => Storage::is_revision_compacted(s.as_ref(), revision).await,
        }
    }
}

// AuthzStorage for StorageBackend — delegates to the inner implementation.
#[async_trait]
impl rusternetes_common::authz::AuthzStorage for StorageBackend {
    async fn get<T>(&self, key: &str, namespace: Option<&str>) -> Result<T>
    where
        T: DeserializeOwned + Send + Sync,
    {
        match self {
            StorageBackend::Etcd(s) => AuthzStorage::get(s, key, namespace).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => AuthzStorage::get(s, key, namespace).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => AuthzStorage::get(s, key, namespace).await,
            StorageBackend::Memory(s) => AuthzStorage::get(s.as_ref(), key, namespace).await,
        }
    }

    async fn list<T>(&self, namespace: Option<&str>) -> Result<Vec<T>>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        match self {
            StorageBackend::Etcd(s) => AuthzStorage::list(s, namespace).await,
            #[cfg(feature = "sqlite")]
            StorageBackend::Sqlite(s) => AuthzStorage::list(s, namespace).await,
            #[cfg(feature = "redis")]
            StorageBackend::Redis(s) => AuthzStorage::list(s, namespace).await,
            StorageBackend::Memory(s) => AuthzStorage::list(s.as_ref(), namespace).await,
        }
    }
}

/// Helper function to build resource keys
pub fn build_key(resource_type: &str, namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(ns) => format!("/registry/{}/{}/{}", resource_type, ns, name),
        None => format!("/registry/{}/{}", resource_type, name),
    }
}

/// Helper function to build prefix for listing
pub fn build_prefix(resource_type: &str, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) => format!("/registry/{}/{}/", resource_type, ns),
        None => format!("/registry/{}/", resource_type),
    }
}
