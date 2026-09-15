use anyhow::Result;
use clap::Parser;
use rusternetes_kube_proxy::KubeProxyConfig;
use rusternetes_storage::{StorageBackend, StorageConfig};
use std::sync::Arc;
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(name = "rusternetes-kube-proxy")]
#[command(about = "Rusternetes Kube-proxy - Network proxy for service load balancing")]
struct Args {
    /// Node name
    #[arg(long)]
    node_name: String,

    /// Etcd endpoints (comma-separated)
    #[arg(long, default_value = "http://localhost:2379")]
    etcd_servers: String,

    /// Storage backend: "etcd" or "sqlite"
    #[arg(long, default_value = "etcd")]
    storage_backend: String,

    /// SQLite database path (only used when --storage-backend=sqlite)
    #[arg(long, default_value = "./data/rusternetes.db")]
    data_dir: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Sync interval in seconds
    #[arg(long, default_value = "1")]
    sync_interval: u64,

    /// Prefix for this instance's iptables chain names (default:
    /// "RUSTERNETES"). Set to a distinct value per instance when multiple
    /// kube-proxy instances share a network namespace.
    #[arg(long)]
    chain_prefix: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt().with_max_level(level).init();

    let storage_config = match args.storage_backend.as_str() {
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            info!("Using SQLite storage backend at: {}", args.data_dir);
            StorageConfig::Sqlite {
                path: args.data_dir,
            }
        }
        // Reached only when no cfg-gated arm above matched. An explicitly named
        // backend landing here means this binary has no compiled-in support for
        // it, and falling through to etcd would be the silent substitution
        // ISSUES.md #66 exists to prevent — so refuse instead. Decided here, in
        // the binary, because this is where the `#[cfg(feature = ...)]` arms
        // live; asking the storage crate answered about the wrong crate.
        other => {
            if matches!(other, "sqlite" | "redis") {
                return Err(rusternetes_storage::backend_not_compiled_in(other).into());
            }
            let endpoints: Vec<String> = args
                .etcd_servers
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            info!("Connecting to etcd at: {:?}", endpoints);
            StorageConfig::Etcd { endpoints }
        }
    };
    let storage = Arc::new(StorageBackend::new(storage_config).await?);

    let config = KubeProxyConfig {
        node_name: args.node_name,
        sync_interval: args.sync_interval,
        chain_prefix: args.chain_prefix,
    };

    rusternetes_kube_proxy::run(storage, config).await
}
