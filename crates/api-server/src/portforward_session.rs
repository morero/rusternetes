//! `kubectl port-forward`, served over real SPDY/3.1 (ISSUES.md #77).
//!
//! kubectl negotiates what to forward *inside* the upgraded connection. For
//! every local connection it opens two SPDY streams — `streamType: error` then
//! `streamType: data` — both carrying `port: <n>` and a shared `requestID`, and
//! it waits for a `SYN_REPLY` to each before continuing. Bytes then flow as
//! `DATA` frames on the data stream; anything written to the error stream is
//! reported to the user as a forwarding error.
//!
//! The session is written against a pair of byte channels rather than a socket,
//! because kubectl reaches it by two transports carrying identical SPDY:
//!
//! - **a WebSocket tunnel**, subprotocol `SPDY/3.1+portforward.k8s.io`, where
//!   each binary message is a slice of the SPDY byte stream. This is what
//!   kubectl 1.30+ tries first.
//! - **a raw `SPDY/3.1` upgrade**, which kubectl falls back to when the tunnel
//!   is refused.
//!
//! Termination mirrors containerd's CRI port-forward: when either direction
//! ends, the other gets one second to finish, then both are closed. The error
//! stream is always closed with an empty `FIN` rather than reset — kubectl reads
//! it to completion, and a reset reads as an error that makes it tear down the
//! whole connection, not just this forward.

use crate::spdy3::{
    encode_control, encode_data, parse_frame, stream_id_of, syn_stream_header_block, ControlType,
    Frame, HeaderCodec, FLAG_FIN,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// The subprotocol kubectl offers for its preferred, WebSocket-tunnelled transport.
pub const TUNNEL_SUBPROTOCOL: &str = "SPDY/3.1+portforward.k8s.io";
/// The stream protocol kubectl requires the server to echo back.
pub const STREAM_PROTOCOL: &str = "portforward.k8s.io";

/// SPDY `RST_STREAM` status codes used here.
const RST_PROTOCOL_ERROR: u32 = 1;

/// How long the second direction of a forward may keep going once the first
/// has finished. Matches containerd's CRI port-forward.
const HALF_CLOSE_GRACE: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 32 * 1024;

/// A frame waiting to be written. Encoding happens in one writer task, in wire
/// order, because header compression state is shared across the connection: a
/// `SYN_REPLY` compressed out of order would be unreadable to the client.
enum Outgoing {
    SynReply {
        stream_id: u32,
    },
    Data {
        stream_id: u32,
        fin: bool,
        data: Vec<u8>,
    },
    RstStream {
        stream_id: u32,
        status: u32,
    },
    Ping(Vec<u8>),
}

/// The two streams kubectl opens for one forwarded connection, until both exist.
#[derive(Default)]
struct PendingPair {
    port: String,
    error_stream: Option<u32>,
    data_stream: Option<u32>,
    data_rx: Option<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
}

/// Serves one port-forward session. Returns when the client's byte stream ends.
///
/// `incoming` carries raw bytes from the client in order; `outgoing` takes raw
/// bytes to send. `pod_ip` is where forwarded connections are opened.
pub async fn run_session(
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    pod_ip: String,
) {
    let (out_tx, mut out_rx) = mpsc::channel::<Outgoing>(256);

    let writer = tokio::spawn(async move {
        let mut codec = HeaderCodec::new();
        while let Some(frame) = out_rx.recv().await {
            let bytes = match frame {
                Outgoing::SynReply { stream_id } => match codec.encode_headers(&[]) {
                    Ok(block) => {
                        let mut payload = stream_id.to_be_bytes().to_vec();
                        payload.extend_from_slice(&block);
                        encode_control(ControlType::SynReply, 0, &payload)
                    }
                    Err(e) => {
                        warn!("port-forward: could not encode SYN_REPLY: {e}");
                        break;
                    }
                },
                Outgoing::Data {
                    stream_id,
                    fin,
                    data,
                } => encode_data(stream_id, if fin { FLAG_FIN } else { 0 }, &data),
                Outgoing::RstStream { stream_id, status } => {
                    let mut payload = stream_id.to_be_bytes().to_vec();
                    payload.extend_from_slice(&status.to_be_bytes());
                    encode_control(ControlType::RstStream, 0, &payload)
                }
                Outgoing::Ping(payload) => encode_control(ControlType::Ping, 0, &payload),
            };
            if outgoing.send(bytes).await.is_err() {
                break;
            }
        }
    });

    let mut inflate = HeaderCodec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK);
    let mut pending: HashMap<String, PendingPair> = HashMap::new();
    let mut data_senders: HashMap<u32, mpsc::UnboundedSender<Option<Vec<u8>>>> = HashMap::new();

    'session: while let Some(chunk) = incoming.recv().await {
        buf.extend_from_slice(&chunk);

        loop {
            let (frame, used) = match parse_frame(&buf) {
                Ok(Some(parsed)) => parsed,
                Ok(None) => break,
                Err(e) => {
                    warn!("port-forward: malformed SPDY stream, closing session: {e}");
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
                    // Always inflate, even for a stream about to be refused:
                    // the compression state is shared, and skipping one block
                    // makes every later one unreadable.
                    let headers = match syn_stream_header_block(&payload)
                        .and_then(|block| inflate.decode_headers(block))
                    {
                        Ok(h) => h,
                        Err(e) => {
                            warn!("port-forward: unreadable SYN_STREAM headers: {e}");
                            break 'session;
                        }
                    };

                    let stream_type = headers.get("streamtype").cloned().unwrap_or_default();
                    let port = headers.get("port").cloned().unwrap_or_default();
                    // Pair on requestID; older clients send none, and pair on
                    // port instead.
                    let key = headers
                        .get("requestid")
                        .cloned()
                        .unwrap_or_else(|| format!("port:{port}"));

                    if stream_type != "error" && stream_type != "data" {
                        warn!("port-forward: unknown streamType {stream_type:?}, resetting");
                        let _ = out_tx
                            .send(Outgoing::RstStream {
                                stream_id,
                                status: RST_PROTOCOL_ERROR,
                            })
                            .await;
                        continue;
                    }

                    // kubectl waits for this reply before it opens the data
                    // stream, so it must go out now, not once the pair is whole.
                    if out_tx.send(Outgoing::SynReply { stream_id }).await.is_err() {
                        break 'session;
                    }

                    let pair = pending.entry(key.clone()).or_default();
                    pair.port = port;
                    if stream_type == "error" {
                        pair.error_stream = Some(stream_id);
                    } else {
                        let (tx, rx) = mpsc::unbounded_channel();
                        data_senders.insert(stream_id, tx);
                        pair.data_stream = Some(stream_id);
                        pair.data_rx = Some(rx);
                    }

                    if pair.error_stream.is_some() && pair.data_stream.is_some() {
                        let pair = pending.remove(&key).expect("just inserted");
                        tokio::spawn(forward(
                            pod_ip.clone(),
                            pair.port,
                            pair.error_stream.expect("checked"),
                            pair.data_stream.expect("checked"),
                            pair.data_rx.expect("set with data_stream"),
                            out_tx.clone(),
                        ));
                    }
                }

                Frame::Data {
                    stream_id,
                    flags,
                    data,
                } => {
                    // Data on an error stream (kubectl closes its side at once)
                    // or on a stream already finished has nowhere to go.
                    if let Some(tx) = data_senders.get(&stream_id) {
                        let mut alive = data.is_empty() || tx.send(Some(data)).is_ok();
                        if flags & FLAG_FIN != 0 {
                            let _ = tx.send(None);
                            alive = false;
                        }
                        if !alive {
                            data_senders.remove(&stream_id);
                        }
                    }
                }

                Frame::Control {
                    control_type: ControlType::RstStream,
                    payload,
                    ..
                } => {
                    if let Ok(stream_id) = stream_id_of(&payload) {
                        if let Some(tx) = data_senders.remove(&stream_id) {
                            let _ = tx.send(None);
                        }
                    }
                }

                // A PING is answered with the same frame. client-go pings every
                // few seconds; unanswered pings are logged, not fatal, but
                // there is no reason to leave them unanswered.
                Frame::Control {
                    control_type: ControlType::Ping,
                    payload,
                    ..
                } => {
                    let _ = out_tx.send(Outgoing::Ping(payload)).await;
                }

                Frame::Control {
                    control_type: ControlType::GoAway,
                    ..
                } => break 'session,

                // SETTINGS, WINDOW_UPDATE, HEADERS and anything unrecognised
                // carry nothing port-forward needs. Flow control is not
                // implemented; client-go's SPDY stack does not enforce it.
                other => debug!("port-forward: ignoring frame {:?}", frame_kind(&other)),
            }
        }
    }

    // Closing the client->pod side of every open forward lets each finish
    // through its own grace period rather than being cut mid-response.
    for (_, tx) in data_senders.drain() {
        let _ = tx.send(None);
    }
    drop(out_tx);
    let _ = writer.await;
    debug!("port-forward: session ended");
}

fn frame_kind(frame: &Frame) -> String {
    match frame {
        Frame::Data { .. } => "DATA".to_string(),
        Frame::Control { control_type, .. } => format!("{control_type:?}"),
        Frame::UnknownControl { control_type, .. } => format!("unknown control {control_type}"),
    }
}

/// Serves one forwarded connection: opens the pod's port and pumps bytes both
/// ways until either side is done.
async fn forward(
    pod_ip: String,
    port: String,
    error_stream: u32,
    data_stream: u32,
    mut from_client: mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    out: mpsc::Sender<Outgoing>,
) {
    let finish = |out: mpsc::Sender<Outgoing>, message: Option<String>| async move {
        if let Some(message) = message {
            let _ = out
                .send(Outgoing::Data {
                    stream_id: error_stream,
                    fin: false,
                    data: message.into_bytes(),
                })
                .await;
        }
        let _ = out
            .send(Outgoing::Data {
                stream_id: data_stream,
                fin: true,
                data: Vec::new(),
            })
            .await;
        let _ = out
            .send(Outgoing::Data {
                stream_id: error_stream,
                fin: true,
                data: Vec::new(),
            })
            .await;
    };

    let port_number = match port.parse::<u16>() {
        Ok(p) if p > 0 => p,
        _ => {
            finish(out, Some(format!("invalid port {port:?}"))).await;
            return;
        }
    };

    let target = format!("{pod_ip}:{port_number}");
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            finish(
                out,
                Some(format!(
                    "error forwarding port {port_number} to pod at {target}: {e}"
                )),
            )
            .await;
            return;
        }
        Err(_) => {
            finish(
                out,
                Some(format!(
                    "error forwarding port {port_number} to pod at {target}: timed out connecting"
                )),
            )
            .await;
            return;
        }
    };
    info!("port-forward: forwarding stream {data_stream} to {target}");

    let (mut pod_read, mut pod_write) = tcp.into_split();

    let out_for_pod = out.clone();
    let mut pod_to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match pod_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_for_pod
                        .send(Outgoing::Data {
                            stream_id: data_stream,
                            fin: false,
                            data: buf[..n].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut client_to_pod = tokio::spawn(async move {
        while let Some(Some(bytes)) = from_client.recv().await {
            if pod_write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        // Half-close, so the pod sees end-of-request and can answer and close.
        let _ = pod_write.shutdown().await;
    });

    tokio::select! {
        _ = &mut pod_to_client => {
            let _ = tokio::time::timeout(HALF_CLOSE_GRACE, &mut client_to_pod).await;
        }
        _ = &mut client_to_pod => {
            let _ = tokio::time::timeout(HALF_CLOSE_GRACE, &mut pod_to_client).await;
        }
    }
    pod_to_client.abort();
    client_to_pod.abort();

    finish(out, None).await;
    debug!("port-forward: stream {data_stream} to {target} closed");
}

/// Serves a session over an upgraded raw `SPDY/3.1` connection.
pub async fn serve_upgraded(upgraded: hyper::upgrade::Upgraded, pod_ip: String) {
    let io = hyper_util::rt::TokioIo::new(upgraded);
    let (mut reader, mut writer) = tokio::io::split(io);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if in_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    run_session(in_rx, out_tx, pod_ip).await;
}

/// Serves a session tunnelled through a WebSocket: each binary message is a
/// slice of the SPDY byte stream, in both directions.
pub async fn serve_websocket(socket: axum::extract::ws::WebSocket, pod_ip: String) {
    use axum::extract::ws::Message;
    use futures::{SinkExt, StreamExt};

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);

    tokio::spawn(async move {
        while let Some(Ok(message)) = ws_rx.next().await {
            match message {
                Message::Binary(bytes) => {
                    if in_tx.send(bytes).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                // Ping/pong are answered by the WebSocket layer; text is not
                // part of the tunnel protocol.
                _ => {}
            }
        }
    });
    tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if ws_tx.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    run_session(in_rx, out_tx, pod_ip).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Builds a client SYN_STREAM exactly as kubectl does: `streamType`,
    /// `port` and `requestID` headers, compressed on the client's own codec.
    fn syn_stream(codec: &mut HeaderCodec, stream_id: u32, kind: &str, port: u16) -> Vec<u8> {
        let block = codec
            .encode_headers(&[
                ("streamtype".to_string(), kind.to_string()),
                ("port".to_string(), port.to_string()),
                ("requestid".to_string(), "0".to_string()),
            ])
            .unwrap();
        let mut payload = stream_id.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&[0, 0]);
        payload.extend_from_slice(&block);
        encode_control(ControlType::SynStream, 0, &payload)
    }

    /// Reads frames off the server's output until `done` says to stop.
    async fn collect_until(
        rx: &mut mpsc::Receiver<Vec<u8>>,
        buf: &mut Vec<u8>,
        mut done: impl FnMut(&[Frame]) -> bool,
    ) -> Vec<Frame> {
        let mut frames = Vec::new();
        while !done(&frames) {
            let chunk = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("server went quiet")
                .expect("server closed");
            buf.extend_from_slice(&chunk);
            while let Some((frame, used)) = parse_frame(buf).unwrap() {
                buf.drain(..used);
                frames.push(frame);
            }
        }
        frames
    }

    /// The whole protocol, end to end, against a real TCP "pod": both streams
    /// get a SYN_REPLY, request bytes reach the pod, the reply comes back on the
    /// data stream, and both streams are closed with FIN — the error stream
    /// empty, because nothing went wrong.
    #[tokio::test]
    async fn a_forwarded_connection_round_trips_bytes_and_closes_cleanly() {
        let pod = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = pod.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = pod.accept().await.unwrap();
            let mut req = vec![0u8; 4];
            sock.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"ping");
            sock.write_all(b"pong").await.unwrap();
            // closing is what ends the forward from the pod side
        });

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tokio::spawn(run_session(in_rx, out_tx, "127.0.0.1".to_string()));

        let mut client = HeaderCodec::new();
        let mut buf = Vec::new();

        in_tx
            .send(syn_stream(&mut client, 1, "error", port))
            .await
            .unwrap();
        let replies = collect_until(&mut out_rx, &mut buf, |f| !f.is_empty()).await;
        assert!(
            matches!(
                replies[0],
                Frame::Control {
                    control_type: ControlType::SynReply,
                    ..
                }
            ),
            "the error stream is answered before the data stream exists — kubectl waits for it"
        );

        in_tx
            .send(syn_stream(&mut client, 3, "data", port))
            .await
            .unwrap();
        in_tx.send(encode_data(3, 0, b"ping")).await.unwrap();

        let frames = collect_until(&mut out_rx, &mut buf, |frames| {
            frames.iter().any(
                |f| matches!(f, Frame::Data { stream_id: 1, flags, .. } if flags & FLAG_FIN != 0),
            )
        })
        .await;

        let data_to_client: Vec<u8> = frames
            .iter()
            .filter_map(|f| match f {
                Frame::Data {
                    stream_id: 3, data, ..
                } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(data_to_client, b"pong");

        let error_payload: Vec<u8> = frames
            .iter()
            .filter_map(|f| match f {
                Frame::Data {
                    stream_id: 1, data, ..
                } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            error_payload.is_empty(),
            "a clean forward writes nothing to the error stream; kubectl treats any bytes there as failure"
        );
        assert!(frames.iter().any(
            |f| matches!(f, Frame::Data { stream_id: 3, flags, .. } if flags & FLAG_FIN != 0)
        ));
    }

    /// A refused connection is reported *on the error stream*, which is the
    /// only place kubectl shows it to the user, and both streams still close.
    #[tokio::test]
    async fn a_refused_port_is_reported_on_the_error_stream() {
        // Bind then drop, so the port is very likely closed.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tokio::spawn(run_session(in_rx, out_tx, "127.0.0.1".to_string()));

        let mut client = HeaderCodec::new();
        let mut buf = Vec::new();
        in_tx
            .send(syn_stream(&mut client, 1, "error", port))
            .await
            .unwrap();
        in_tx
            .send(syn_stream(&mut client, 3, "data", port))
            .await
            .unwrap();

        let frames = collect_until(&mut out_rx, &mut buf, |frames| {
            frames.iter().any(
                |f| matches!(f, Frame::Data { stream_id: 1, flags, .. } if flags & FLAG_FIN != 0),
            )
        })
        .await;

        let message: Vec<u8> = frames
            .iter()
            .filter_map(|f| match f {
                Frame::Data {
                    stream_id: 1, data, ..
                } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let message = String::from_utf8_lossy(&message);
        assert!(
            message.contains(&format!("error forwarding port {port}")),
            "got {message:?}"
        );
    }

    /// A PING is answered with an identical frame.
    #[tokio::test]
    async fn a_ping_is_echoed() {
        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tokio::spawn(run_session(in_rx, out_tx, "127.0.0.1".to_string()));

        let ping = encode_control(ControlType::Ping, 0, &7u32.to_be_bytes());
        in_tx.send(ping.clone()).await.unwrap();
        let mut buf = Vec::new();
        let frames = collect_until(&mut out_rx, &mut buf, |f| !f.is_empty()).await;
        assert_eq!(parse_frame(&ping).unwrap().unwrap().0, frames[0]);
    }
}
