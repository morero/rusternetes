//! SPDY handlers for pod exec and attach (port-forward: see `portforward_session`)
//!
//! The API server proxies exec/attach requests to the kubelet,
//! which handles them via the container runtime (bollard/Docker).
//! This keeps the API server runtime-agnostic.

use crate::spdy::{SpdyChannel, SpdyConnection};
use rusternetes_common::resources::Pod;
use tracing::{debug, error};

/// Get the kubelet address for a pod's node.
/// In our Docker Compose setup, kubelets are reachable by container name.
fn get_kubelet_url(pod: &Pod) -> String {
    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_deref())
        .unwrap_or("node-1");

    // Map node names to kubelet container hostnames and ports
    let (host, port) = match node_name {
        "node-1" => ("rusternetes-kubelet", 10250),
        "node-2" => ("rusternetes-kubelet2", 10251),
        _ => ("rusternetes-kubelet", 10250),
    };

    format!("http://{}:{}", host, port)
}

/// Handle SPDY exec connection by proxying to the kubelet
#[allow(clippy::too_many_arguments)]
pub async fn handle_spdy_exec(
    spdy: SpdyConnection,
    pod: Pod,
    container_name: String,
    command: Vec<String>,
    stdin: bool,
    stdout: bool,
    stderr: bool,
    tty: bool,
) {
    debug!(
        "SPDY exec: pod={}, container={}, command={:?}, stdin={}, stdout={}, stderr={}, tty={}",
        pod.metadata.name, container_name, command, stdin, stdout, stderr, tty
    );

    let container_id = format!("{}_{}", pod.metadata.name, container_name);

    debug!("Direct Docker exec for container: {}", container_id);

    // Execute directly via Docker (API server has Docker socket mounted)
    use bollard::exec::{CreateExecOptions, StartExecResults};
    use bollard::Docker;
    use futures::StreamExt;

    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to connect to Docker: {}", e);
            let _ = spdy
                .write_error(&format!("Failed to connect to Docker: {}", e))
                .await;
            return;
        }
    };

    let exec_config = CreateExecOptions {
        cmd: Some(command.iter().map(|s| s.as_str()).collect()),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        attach_stdin: Some(false),
        tty: Some(tty),
        ..Default::default()
    };

    let exec = match docker.create_exec(&container_id, exec_config).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create exec: {}", e);
            let _ = spdy.write_error(&format!("Exec failed: {}", e)).await;
            return;
        }
    };

    let output = match docker
        .start_exec(
            &exec.id,
            Some(bollard::exec::StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
    {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to start exec: {}", e);
            let _ = spdy.write_error(&format!("Exec failed: {}", e)).await;
            return;
        }
    };

    // Collect output with timeout
    let mut stdout_data = Vec::new();
    let mut stderr_data = Vec::new();
    if let StartExecResults::Attached {
        output: mut stream, ..
    } = output
    {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1), stream.next()).await {
                Ok(Some(Ok(msg))) => match msg {
                    bollard::container::LogOutput::StdOut { message } => {
                        stdout_data.extend_from_slice(&message)
                    }
                    bollard::container::LogOutput::StdErr { message } => {
                        stderr_data.extend_from_slice(&message)
                    }
                    _ => {}
                },
                Ok(Some(Err(_))) | Ok(None) => break,
                Err(_) => {
                    // Timeout — check if exec finished
                    match docker.inspect_exec(&exec.id).await {
                        Ok(info) if !info.running.unwrap_or(false) => break,
                        _ => continue,
                    }
                }
            }
        }
    }

    // Send results back via SPDY
    if stdout && !stdout_data.is_empty() {
        let _ = spdy.write_channel(SpdyChannel::Stdout, stdout_data).await;
    }
    if stderr && !stderr_data.is_empty() {
        let _ = spdy.write_channel(SpdyChannel::Stderr, stderr_data).await;
    }

    let _ = spdy.close().await;
}

/// Simple URL encoding for the command string
fn urlencoding_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Handle SPDY attach connection by proxying to the kubelet
pub async fn handle_spdy_attach(
    spdy: SpdyConnection,
    pod: Pod,
    container_name: String,
    stdin: bool,
    stdout: bool,
    stderr: bool,
    tty: bool,
) {
    debug!(
        "SPDY attach: pod={}, container={}, stdin={}, stdout={}, stderr={}, tty={}",
        pod.metadata.name, container_name, stdin, stdout, stderr, tty
    );

    // Attach is similar to exec but attaches to the main process
    // For conformance, we can treat it like exec with no command
    let _ = spdy
        .write_error("Attach not fully implemented in proxy mode")
        .await;
    let _ = spdy.close().await;
}

