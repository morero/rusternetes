//! `exec` and `attach` over raw SPDY/3.1 — the remotecommand protocol that
//! `remotecommand.NewSPDYExecutor` speaks (ISSUES.md #78).
//!
//! Current kubectl uses WebSocket for both, so this path is invisible from the
//! command line. It is not invisible to the Go ecosystem: much of it still
//! execs into pods through the SPDY executor, and before this every such call
//! got the command's output back as the body of a non-101 response, with the
//! exit code and stdin lost.
//!
//! The protocol, as client-go's `streamProtocolV4` drives it: the client opens
//! one SPDY stream per role, each a `SYN_STREAM` with a `streamType` header —
//! `error` first, then `stdin`, `stdout`, `stderr` (never with a TTY, where the
//! two are merged), and `resize` (only with a TTY) — and waits for a
//! `SYN_REPLY` to each. Which of them to expect comes from the request's query
//! flags, so the command starts only once all have arrived. Output flows back
//! as `DATA` on `stdout`/`stderr`; the result is written to `error` and that
//! stream closed. Under `v4.channel.k8s.io` the result is a JSON
//! `metav1.Status` carrying the exit code; under older versions it is plain
//! text, written only on failure.

use crate::spdy3::{
    parse_frame, spawn_frame_writer, stream_id_of, syn_stream_header_block, ControlType, Frame,
    HeaderCodec, OutFrame, FLAG_FIN,
};
use futures::StreamExt;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Stream protocols this server speaks, in preference order.
pub const SUPPORTED_PROTOCOLS: &[&str] = &[
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
];

/// The kubelet's own limit for a client to finish opening its streams.
const STREAM_CREATION_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for a finished exec to report its exit code.
const EXIT_CODE_WAIT: Duration = Duration::from_secs(5);

/// Picks the protocol to speak from the versions the client offered.
///
/// `None` means none are supported, and the caller must refuse the upgrade:
/// client-go rejects a 101 whose `X-Stream-Protocol-Version` it did not offer.
pub fn negotiate<'a>(offered: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    let offered: Vec<&str> = offered
        .into_iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    SUPPORTED_PROTOCOLS
        .iter()
        .copied()
        .find(|p| offered.contains(p))
}

/// What the session runs once its streams are open.
#[derive(Debug, Clone)]
pub enum Target {
    Exec {
        container_id: String,
        command: Vec<String>,
    },
    Attach {
        container_id: String,
    },
}

/// The query flags that decide which streams the client will open.
#[derive(Debug, Clone, Copy)]
pub struct Streams {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub tty: bool,
}

impl Streams {
    /// The stream types the client will create for these flags. With a TTY,
    /// stderr is merged into stdout and never gets its own stream, and a resize
    /// stream appears instead — mirroring client-go, which would otherwise
    /// leave this side waiting for a stream that is never opened.
    fn expected(&self) -> Vec<&'static str> {
        let mut types = vec!["error"];
        if self.stdin {
            types.push("stdin");
        }
        if self.stdout {
            types.push("stdout");
        }
        if self.stderr && !self.tty {
            types.push("stderr");
        }
        if self.tty {
            types.push("resize");
        }
        types
    }
}

/// How the command ended.
enum Outcome {
    Exited(i64),
    /// The runtime could not start or attach at all.
    Failed(String),
}

/// Serves one remotecommand session over an upgraded SPDY connection.
pub async fn serve_upgraded(
    upgraded: hyper::upgrade::Upgraded,
    target: Target,
    streams: Streams,
    protocol: &'static str,
) {
    let (in_rx, out_tx) = crate::spdy3::bridge_upgraded(upgraded);
    run_session(in_rx, out_tx, target, streams, protocol).await;
}

/// The session, written against byte channels so it can be tested without a
/// socket.
pub async fn run_session(
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    target: Target,
    streams: Streams,
    protocol: &'static str,
) {
    let (out, writer) = spawn_frame_writer(outgoing);
    let expected = streams.expected();

    let mut inflate = HeaderCodec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut ids: HashMap<&'static str, u32> = HashMap::new();

    let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
    let (resize_tx, resize_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut stdin_tx = Some(stdin_tx);
    let mut pending_inputs = Some((stdin_rx, resize_rx));
    let mut command: Option<tokio::task::JoinHandle<()>> = None;

    let deadline = tokio::time::sleep(STREAM_CREATION_TIMEOUT);
    tokio::pin!(deadline);

    'session: loop {
        let chunk = tokio::select! {
            chunk = incoming.recv() => match chunk {
                Some(chunk) => chunk,
                None => break 'session,
            },
            _ = &mut deadline, if command.is_none() => {
                warn!(
                    "remotecommand: client opened {:?} of {:?} streams within {:?}; closing",
                    ids.keys().collect::<Vec<_>>(),
                    expected,
                    STREAM_CREATION_TIMEOUT
                );
                break 'session;
            }
        };
        buf.extend_from_slice(&chunk);

        loop {
            let (frame, used) = match parse_frame(&buf) {
                Ok(Some(parsed)) => parsed,
                Ok(None) => break,
                Err(e) => {
                    warn!("remotecommand: malformed SPDY stream: {e}");
                    break 'session;
                }
            };
            buf.drain(..used);

            match frame {
                Frame::Control {
                    control_type: ControlType::SynStream,
                    payload,
                    ..
                } => {
                    let Ok(stream_id) = stream_id_of(&payload) else {
                        break 'session;
                    };
                    // Inflated unconditionally: the compression state is shared,
                    // so skipping a block corrupts every later one.
                    let headers = match syn_stream_header_block(&payload)
                        .and_then(|block| inflate.decode_headers(block))
                    {
                        Ok(h) => h,
                        Err(e) => {
                            warn!("remotecommand: unreadable SYN_STREAM headers: {e}");
                            break 'session;
                        }
                    };
                    let stream_type = headers.get("streamtype").cloned().unwrap_or_default();
                    let Some(known) = expected.iter().copied().find(|t| *t == stream_type) else {
                        warn!("remotecommand: unexpected streamType {stream_type:?}, resetting");
                        let _ = out
                            .send(OutFrame::RstStream {
                                stream_id,
                                status: 1,
                            })
                            .await;
                        continue;
                    };
                    if out.send(OutFrame::SynReply { stream_id }).await.is_err() {
                        break 'session;
                    }
                    ids.insert(known, stream_id);

                    if command.is_none() && expected.iter().all(|t| ids.contains_key(t)) {
                        let (stdin_rx, resize_rx) =
                            pending_inputs.take().expect("taken once, when starting");
                        command = Some(tokio::spawn(run_command(
                            target.clone(),
                            streams,
                            protocol,
                            ids.clone(),
                            stdin_rx,
                            resize_rx,
                            out.clone(),
                        )));
                    }
                }

                Frame::Data {
                    stream_id,
                    flags,
                    data,
                } => {
                    let fin = flags & FLAG_FIN != 0;
                    if ids.get("stdin") == Some(&stream_id) {
                        if let Some(tx) = stdin_tx.as_ref() {
                            if !data.is_empty() {
                                let _ = tx.send(Some(data));
                            }
                            if fin {
                                let _ = tx.send(None);
                                stdin_tx = None;
                            }
                        }
                    } else if ids.get("resize") == Some(&stream_id) && !data.is_empty() {
                        let _ = resize_tx.send(data);
                    }
                    // DATA on the error, stdout or stderr streams is the client
                    // closing its own write side; there is nothing to do.
                }

                Frame::Control {
                    control_type: ControlType::Ping,
                    payload,
                    ..
                } => {
                    let _ = out.send(OutFrame::Ping(payload)).await;
                }

                Frame::Control {
                    control_type: ControlType::GoAway,
                    ..
                } => break 'session,

                _ => {}
            }
        }
    }

    // The client is gone (or never finished opening streams). Closing stdin
    // lets a command that is reading it finish on its own.
    if let Some(tx) = stdin_tx.take() {
        let _ = tx.send(None);
    }
    if let Some(handle) = command {
        let _ = handle.await;
    }
    drop(out);
    let _ = writer.await;
    debug!("remotecommand: session ended");
}

/// Runs the exec or attach and streams it to the client.
async fn run_command(
    target: Target,
    streams: Streams,
    protocol: &'static str,
    ids: HashMap<&'static str, u32>,
    mut stdin_rx: mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    mut resize_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    out: mpsc::Sender<OutFrame>,
) {
    use bollard::container::{AttachContainerOptions, LogOutput};
    use bollard::exec::{CreateExecOptions, StartExecResults};

    let docker = match bollard::Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(e) => {
            finish(&out, &ids, protocol, Outcome::Failed(e.to_string())).await;
            return;
        }
    };

    type Output = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>,
    >;
    type Input = std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>;

    let (mut output, input, exec_id): (Output, Option<Input>, Option<String>) = match &target {
        Target::Exec {
            container_id,
            command,
        } => {
            let created = docker
                .create_exec(
                    container_id,
                    CreateExecOptions {
                        cmd: Some(command.iter().map(String::as_str).collect()),
                        attach_stdin: Some(streams.stdin),
                        attach_stdout: Some(streams.stdout),
                        attach_stderr: Some(streams.stderr),
                        tty: Some(streams.tty),
                        ..Default::default()
                    },
                )
                .await;
            let exec_id = match created {
                Ok(e) => e.id,
                Err(e) => {
                    finish(&out, &ids, protocol, Outcome::Failed(e.to_string())).await;
                    return;
                }
            };
            match docker.start_exec(&exec_id, None).await {
                Ok(StartExecResults::Attached { output, input }) => {
                    (output, Some(input), Some(exec_id))
                }
                Ok(StartExecResults::Detached) => {
                    finish(&out, &ids, protocol, Outcome::Exited(0)).await;
                    return;
                }
                Err(e) => {
                    finish(&out, &ids, protocol, Outcome::Failed(e.to_string())).await;
                    return;
                }
            }
        }
        Target::Attach { container_id } => {
            match docker
                .attach_container::<String>(
                    container_id,
                    Some(AttachContainerOptions {
                        stdin: Some(streams.stdin),
                        stdout: Some(streams.stdout),
                        stderr: Some(streams.stderr),
                        stream: Some(true),
                        logs: Some(false),
                        detach_keys: None,
                    }),
                )
                .await
            {
                Ok(a) => (a.output, Some(a.input), None),
                Err(e) => {
                    finish(&out, &ids, protocol, Outcome::Failed(e.to_string())).await;
                    return;
                }
            }
        }
    };
    info!("remotecommand: started {:?}", target);

    let mut input = if streams.stdin { input } else { None };
    let mut resize_buf: Vec<u8> = Vec::new();
    let mut stdin_open = streams.stdin;

    loop {
        tokio::select! {
            item = output.next() => {
                let (role, message) = match item {
                    Some(Ok(LogOutput::StdErr { message })) => ("stderr", message),
                    Some(Ok(LogOutput::StdOut { message }))
                    | Some(Ok(LogOutput::Console { message })) => ("stdout", message),
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break,
                };
                // With a TTY there is no stderr stream; everything is stdout.
                let stream = ids.get(role).or_else(|| ids.get("stdout"));
                if let Some(&stream_id) = stream {
                    if out
                        .send(OutFrame::Data { stream_id, fin: false, data: message.to_vec() })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            chunk = stdin_rx.recv(), if stdin_open => match chunk {
                Some(Some(bytes)) => {
                    if let Some(w) = input.as_mut() {
                        if w.write_all(&bytes).await.is_err() || w.flush().await.is_err() {
                            input = None;
                        }
                    }
                }
                // The client closed stdin: the command sees EOF, as it would locally.
                Some(None) | None => {
                    stdin_open = false;
                    if let Some(mut w) = input.take() {
                        let _ = w.shutdown().await;
                    }
                }
            },
            Some(bytes) = resize_rx.recv() => {
                resize_buf.extend_from_slice(&bytes);
                // client-go writes one JSON object per resize, newline-separated.
                while let Some(pos) = resize_buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = resize_buf.drain(..=pos).collect();
                    apply_resize(&docker, &target, exec_id.as_deref(), &line).await;
                }
            }
        }
    }

    let outcome = match &exec_id {
        Some(id) => Outcome::Exited(wait_for_exit_code(&docker, id).await),
        // Attach carries no exit code in Kubernetes; the stream ending is the result.
        None => Outcome::Exited(0),
    };
    finish(&out, &ids, protocol, outcome).await;
}

async fn wait_for_exit_code(docker: &bollard::Docker, exec_id: &str) -> i64 {
    let deadline = tokio::time::Instant::now() + EXIT_CODE_WAIT;
    loop {
        if let Ok(info) = docker.inspect_exec(exec_id).await {
            if !info.running.unwrap_or(false) {
                return info.exit_code.unwrap_or(0);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return 0;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn apply_resize(
    docker: &bollard::Docker,
    target: &Target,
    exec_id: Option<&str>,
    line: &[u8],
) {
    #[derive(serde::Deserialize)]
    struct Size {
        #[serde(rename = "Width")]
        width: u16,
        #[serde(rename = "Height")]
        height: u16,
    }
    let Ok(size) = serde_json::from_slice::<Size>(line) else {
        return;
    };
    let result = match (target, exec_id) {
        (Target::Exec { .. }, Some(id)) => docker
            .resize_exec(
                id,
                bollard::exec::ResizeExecOptions {
                    height: size.height,
                    width: size.width,
                },
            )
            .await
            .map(|_| ()),
        (Target::Attach { container_id }, _) => docker
            .resize_container_tty(
                container_id,
                bollard::container::ResizeContainerTtyOptions {
                    height: size.height,
                    width: size.width,
                },
            )
            .await
            .map(|_| ()),
        _ => Ok(()),
    };
    if let Err(e) = result {
        debug!("remotecommand: resize ignored: {e}");
    }
}

/// Closes the output streams, then writes the result and closes the error
/// stream — in that order, because client-go waits for stdout and stderr to
/// finish before it reads the result.
async fn finish(
    out: &mpsc::Sender<OutFrame>,
    ids: &HashMap<&'static str, u32>,
    protocol: &'static str,
    outcome: Outcome,
) {
    for role in ["stdout", "stderr"] {
        if let Some(&stream_id) = ids.get(role) {
            let _ = out
                .send(OutFrame::Data {
                    stream_id,
                    fin: true,
                    data: Vec::new(),
                })
                .await;
        }
    }
    let Some(&error_stream) = ids.get("error") else {
        return;
    };
    if let Some(body) = status_body(protocol, &outcome) {
        let _ = out
            .send(OutFrame::Data {
                stream_id: error_stream,
                fin: false,
                data: body.into_bytes(),
            })
            .await;
    }
    let _ = out
        .send(OutFrame::Data {
            stream_id: error_stream,
            fin: true,
            data: Vec::new(),
        })
        .await;
}

/// What to write on the error stream for this outcome, if anything.
///
/// `v4.channel.k8s.io` always gets a JSON `metav1.Status` — client-go decodes a
/// non-zero exit from `NonZeroExitCode` with an `ExitCode` cause, and that is
/// the only way the exit code reaches the caller. Older protocols treat any
/// bytes on the error stream as failure, so they get text on failure only.
fn status_body(protocol: &str, outcome: &Outcome) -> Option<String> {
    let v4 = protocol == "v4.channel.k8s.io";
    match (v4, outcome) {
        (true, Outcome::Exited(0)) => Some(r#"{"metadata":{},"status":"Success"}"#.to_string()),
        (true, Outcome::Exited(code)) => Some(
            serde_json::json!({
                "metadata": {},
                "status": "Failure",
                "message": format!("command terminated with non-zero exit code: {code}"),
                "reason": "NonZeroExitCode",
                "details": { "causes": [ { "reason": "ExitCode", "message": code.to_string() } ] }
            })
            .to_string(),
        ),
        (true, Outcome::Failed(msg)) => Some(
            serde_json::json!({
                "metadata": {},
                "status": "Failure",
                "message": msg,
            })
            .to_string(),
        ),
        (false, Outcome::Exited(0)) => None,
        (false, Outcome::Exited(code)) => Some(format!(
            "command terminated with non-zero exit code: {code}"
        )),
        (false, Outcome::Failed(msg)) => Some(msg.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spdy3::{encode_control, HeaderCodec};

    #[test]
    fn v4_is_preferred_when_offered() {
        assert_eq!(
            negotiate(["channel.k8s.io", "v4.channel.k8s.io", "v3.channel.k8s.io"]),
            Some("v4.channel.k8s.io")
        );
    }

    /// Some clients send the offered versions as one comma-separated header.
    #[test]
    fn a_comma_separated_offer_is_understood() {
        assert_eq!(
            negotiate(["v2.channel.k8s.io, channel.k8s.io"]),
            Some("v2.channel.k8s.io")
        );
    }

    #[test]
    fn nothing_supported_means_no_protocol() {
        assert_eq!(negotiate(["v5.channel.k8s.io"]), None);
    }

    /// With a TTY there is no stderr stream and there is a resize stream.
    /// Expecting stderr would wait forever for a stream client-go never opens.
    #[test]
    fn tty_merges_stderr_and_adds_resize() {
        let s = Streams {
            stdin: true,
            stdout: true,
            stderr: true,
            tty: true,
        };
        assert_eq!(s.expected(), vec!["error", "stdin", "stdout", "resize"]);
        let s = Streams {
            stdin: false,
            stdout: true,
            stderr: true,
            tty: false,
        };
        assert_eq!(s.expected(), vec!["error", "stdout", "stderr"]);
    }

    /// The exit code reaches a v4 caller only through this exact shape.
    #[test]
    fn a_nonzero_exit_is_reported_the_way_client_go_decodes_it() {
        let body = status_body("v4.channel.k8s.io", &Outcome::Exited(3)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "Failure");
        assert_eq!(v["reason"], "NonZeroExitCode");
        assert_eq!(v["details"]["causes"][0]["reason"], "ExitCode");
        assert_eq!(v["details"]["causes"][0]["message"], "3");
    }

    /// Older protocols read any bytes on the error stream as failure, so
    /// success must write nothing at all.
    #[test]
    fn older_protocols_get_nothing_on_success() {
        assert_eq!(status_body("v2.channel.k8s.io", &Outcome::Exited(0)), None);
        assert!(status_body("v2.channel.k8s.io", &Outcome::Exited(1)).is_some());
    }

    /// A client that never finishes opening its streams must not hold the
    /// session forever — but this one opens a stream type nobody expects,
    /// which is reset rather than accepted.
    #[tokio::test]
    async fn an_unexpected_stream_type_is_reset() {
        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        tokio::spawn(run_session(
            in_rx,
            out_tx,
            Target::Attach {
                container_id: "unused".into(),
            },
            Streams {
                stdin: false,
                stdout: true,
                stderr: false,
                tty: false,
            },
            "v4.channel.k8s.io",
        ));

        let mut client = HeaderCodec::new();
        let block = client
            .encode_headers(&[("streamtype".to_string(), "nonsense".to_string())])
            .unwrap();
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        payload.extend_from_slice(&block);
        in_tx
            .send(encode_control(ControlType::SynStream, 0, &payload))
            .await
            .unwrap();

        let bytes = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let (frame, _) = parse_frame(&bytes).unwrap().unwrap();
        assert!(matches!(
            frame,
            Frame::Control {
                control_type: ControlType::RstStream,
                ..
            }
        ));
    }
}
