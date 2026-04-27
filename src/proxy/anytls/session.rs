//! anytls session layer — client side
//! (ports mihomo transport/anytls/session/{session,stream,client}.go).
//!
//! A single TCP+TLS connection carries many logical streams. Each frame is
//! `[cmd:1][sid:4][length:2][data:length]` big-endian. The first outbound
//! record carries a padding-scheme-shaped prologue so the handshake size
//! distribution stays scheme-consistent.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex as PlMutex, RwLock as PlRwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify};
use tracing::{debug, error, warn};

use super::frame::{
    decode_string_map, encode_header, encode_string_map, Header, CMD_ALERT, CMD_FIN,
    CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN,
    CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, HEADER_OVERHEAD,
};
use super::padding::{PaddingFactory, CHECK_MARK};

/// Async reader half of a TLS stream erased to a trait object.
pub type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
/// Async writer half of a TLS stream erased to a trait object.
pub type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

const WRITE_DEADLINE: Duration = Duration::from_secs(5);
const CLIENT_VERSION: &str = "2";

/// Shared session state. Hosted by [`Session`] and referenced from
/// [`AnytlsStream`] handles and the background recv loop.
pub struct SessionInner {
    writer: TokioMutex<WriterState>,
    streams: PlMutex<HashMap<u32, Arc<StreamSlot>>>,
    padding: PlRwLock<Arc<PaddingFactory>>,
    next_stream_id: AtomicU32,
    pub closed: AtomicBool,
    pub die: Notify,
    pub peer_version: AtomicU8,
    /// Session sequence number; bookkeeping kept to match mihomo even though
    /// our pool is a simple VecDeque instead of a skiplist.
    #[allow(dead_code)]
    pub seq: u64,
    pub idle_since: PlMutex<Instant>,
}

struct WriterState {
    writer: BoxedWriter,
    buffering: bool,
    buffer: Vec<u8>,
    send_padding: bool,
    pkt_counter: u32,
}

/// Per-stream read-side slot stored in the session map. The sender is cloned
/// by the recv loop when dispatching a PSH frame; the stream holds the
/// receiver.
struct StreamSlot {
    tx: mpsc::UnboundedSender<Bytes>,
    die_err: PlMutex<Option<String>>,
    die_notify: Arc<Notify>,
}

impl SessionInner {
    fn write_header_into(&self, buf: &mut Vec<u8>, cmd: u8, sid: u32, length: u16) {
        buf.extend_from_slice(&encode_header(cmd, sid, length));
    }

    fn build_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_OVERHEAD + data.len());
        self.write_header_into(&mut buf, cmd, sid, data.len() as u16);
        buf.extend_from_slice(data);
        buf
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn close(self: &Arc<Self>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.die.notify_waiters();

        // Close all streams locally.
        let slots: Vec<Arc<StreamSlot>> = {
            let mut map = self.streams.lock();
            let drained: Vec<_> = map.drain().map(|(_, v)| v).collect();
            drained
        };
        for slot in slots {
            {
                let mut e = slot.die_err.lock();
                if e.is_none() {
                    *e = Some("session closed".to_string());
                }
            }
            slot.die_notify.notify_waiters();
        }

        // Best-effort shutdown of the writer.
        let mut ws = self.writer.lock().await;
        let _ = ws.writer.shutdown().await;
    }

    /// Write a data frame for `sid`. Returns the number of payload bytes
    /// written (equal to `data.len()` on success).
    pub async fn write_data_frame(self: &Arc<Self>, sid: u32, data: &[u8]) -> io::Result<usize> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let frame = self.build_frame(CMD_PSH, sid, data);
        self.write_conn_framed(&frame).await?;
        Ok(data.len())
    }

    /// Write a control frame (SYN/FIN/SETTINGS/etc). Applies the 5s write
    /// deadline mihomo imposes on control frames.
    pub async fn write_control_frame(
        self: &Arc<Self>,
        cmd: u8,
        sid: u32,
        data: &[u8],
    ) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let frame = self.build_frame(cmd, sid, data);
        match tokio::time::timeout(WRITE_DEADLINE, self.write_conn_framed(&frame)).await {
            Ok(r) => r,
            Err(_) => {
                // mihomo closes the session on write-deadline expiry.
                self.close().await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "control write"))
            }
        }
    }

    /// Port of mihomo session.writeConn — handles buffering and padding.
    async fn write_conn_framed(self: &Arc<Self>, data: &[u8]) -> io::Result<()> {
        let mut ws = self.writer.lock().await;

        // Buffer mode: accumulate until something explicitly clears it.
        if ws.buffering {
            ws.buffer.extend_from_slice(data);
            return Ok(());
        }
        // Drain any previously buffered bytes ahead of `data`.
        let mut payload: Vec<u8> = if ws.buffer.is_empty() {
            data.to_vec()
        } else {
            let mut v = std::mem::take(&mut ws.buffer);
            v.extend_from_slice(data);
            v
        };

        if ws.send_padding {
            let paddingf = self.padding.read().clone();
            ws.pkt_counter += 1;
            let pkt = ws.pkt_counter;
            if pkt < paddingf.stop {
                let sizes = paddingf.generate_record_payload_sizes(pkt);
                for l in sizes {
                    let remain = payload.len();
                    if l == CHECK_MARK {
                        if remain == 0 {
                            break;
                        } else {
                            continue;
                        }
                    }
                    let l = l as usize;
                    if remain > l {
                        // all payload, write l bytes
                        ws.writer.write_all(&payload[..l]).await?;
                        payload.drain(..l);
                    } else if remain > 0 {
                        // payload + padding
                        let pad_len = l.saturating_sub(remain).saturating_sub(HEADER_OVERHEAD);
                        if pad_len > 0 {
                            let mut hdr = encode_header(CMD_WASTE, 0, pad_len as u16).to_vec();
                            hdr.extend(std::iter::repeat_n(0u8, pad_len));
                            payload.extend_from_slice(&hdr);
                        }
                        ws.writer.write_all(&payload).await?;
                        payload.clear();
                    } else {
                        // all padding
                        let mut hdr = encode_header(CMD_WASTE, 0, l as u16).to_vec();
                        hdr.extend(std::iter::repeat_n(0u8, l));
                        ws.writer.write_all(&hdr).await?;
                    }
                }
                if payload.is_empty() {
                    return Ok(());
                } else {
                    ws.writer.write_all(&payload).await?;
                    return Ok(());
                }
            } else {
                ws.send_padding = false;
            }
        }

        ws.writer.write_all(&payload).await
    }

    fn register_stream(&self, sid: u32, slot: Arc<StreamSlot>) {
        self.streams.lock().insert(sid, slot);
    }

    fn remove_stream(&self, sid: u32) -> Option<Arc<StreamSlot>> {
        self.streams.lock().remove(&sid)
    }

    fn take_stream_sender(&self, sid: u32) -> Option<mpsc::UnboundedSender<Bytes>> {
        self.streams.lock().get(&sid).map(|s| s.tx.clone())
    }
}

/// Client-mode session. Hold onto this via `Arc` to share with streams.
pub struct Session {
    pub inner: Arc<SessionInner>,
}

impl Session {
    /// Wrap a connected, TLS-handshook stream and start the recv loop. The
    /// caller must already have written the anytls prologue (password hash +
    /// initial padding) onto the TLS conn.
    pub fn new_client(
        reader: BoxedReader,
        writer: BoxedWriter,
        padding: Arc<PaddingFactory>,
        seq: u64,
    ) -> Self {
        let inner = Arc::new(SessionInner {
            writer: TokioMutex::new(WriterState {
                writer,
                buffering: true, // we'll accumulate the initial settings+SYN together
                buffer: Vec::new(),
                send_padding: true,
                pkt_counter: 0,
            }),
            streams: PlMutex::new(HashMap::new()),
            padding: PlRwLock::new(padding),
            next_stream_id: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            die: Notify::new(),
            peer_version: AtomicU8::new(0),
            seq,
            idle_since: PlMutex::new(Instant::now()),
        });
        // Spawn the recv loop.
        let loop_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            if let Err(e) = recv_loop(loop_inner.clone(), reader).await {
                debug!("anytls recv_loop exited: {e}");
            }
            loop_inner.close().await;
        });
        Self { inner }
    }

    /// Send the client settings frame. mihomo's client does this in Run();
    /// we do it once, lazily, before the first stream is opened.
    pub async fn send_initial_settings(&self) -> io::Result<()> {
        let md5 = self.inner.padding.read().md5_hex.clone();
        let data = encode_string_map(&[
            ("v", CLIENT_VERSION),
            ("client", "miemietron"),
            ("padding-md5", md5.as_str()),
        ]);
        self.inner.write_control_frame(CMD_SETTINGS, 0, &data).await
    }

    /// Open a new stream on this session.
    pub async fn open_stream(&self) -> io::Result<AnytlsStream> {
        if self.inner.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let sid = self.inner.next_stream_id.fetch_add(1, Ordering::AcqRel) + 1;

        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        let die_notify = Arc::new(Notify::new());
        let slot = Arc::new(StreamSlot {
            tx,
            die_err: PlMutex::new(None),
            die_notify: Arc::clone(&die_notify),
        });
        self.inner.register_stream(sid, Arc::clone(&slot));

        // Write SYN (still in buffer mode).
        self.inner.write_control_frame(CMD_SYN, sid, &[]).await?;

        // Clear buffering — the next writeDataFrame will flush settings+SYN
        // alongside the first payload chunk.
        {
            let mut ws = self.inner.writer.lock().await;
            ws.buffering = false;
        }

        Ok(AnytlsStream {
            sid,
            session: Arc::clone(&self.inner),
            rx,
            leftover: Bytes::new(),
            write_closed: false,
            die_err: slot,
            die_notify,
            fin_sent: false,
            pending_write: None,
            pending_shutdown: None,
        })
    }
}

async fn recv_loop(inner: Arc<SessionInner>, mut reader: BoxedReader) -> io::Result<()> {
    let mut hdr_buf = [0u8; HEADER_OVERHEAD];
    loop {
        if inner.is_closed() {
            return Ok(());
        }
        reader.read_exact(&mut hdr_buf).await?;
        let hdr = Header::parse(&hdr_buf);
        let len = hdr.length as usize;
        let data = if len > 0 {
            let mut buf = BytesMut::with_capacity(len);
            buf.resize(len, 0);
            reader.read_exact(&mut buf[..]).await?;
            buf.freeze()
        } else {
            Bytes::new()
        };
        match hdr.cmd {
            CMD_PSH => {
                if let Some(tx) = inner.take_stream_sender(hdr.sid) {
                    let _ = tx.send(data);
                }
            }
            CMD_SYNACK if !data.is_empty() => {
                // Error report on stream creation (only when data is present).
                let msg = format!("remote: {}", String::from_utf8_lossy(&data));
                if let Some(slot) = inner.remove_stream(hdr.sid) {
                    *slot.die_err.lock() = Some(msg);
                    slot.die_notify.notify_waiters();
                }
            }
            CMD_FIN => {
                if let Some(slot) = inner.remove_stream(hdr.sid) {
                    slot.die_notify.notify_waiters();
                    // Drop the sender by dropping slot → stream.rx closes.
                    drop(slot);
                }
            }
            CMD_WASTE => { /* discard */ }
            CMD_SETTINGS => { /* server->client direction not expected */ }
            CMD_ALERT => {
                if !data.is_empty() {
                    error!(
                        "anytls alert from server: {}",
                        String::from_utf8_lossy(&data)
                    );
                }
                inner.close().await;
                return Ok(());
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if let Some(new_pad) = PaddingFactory::new(&data) {
                    *inner.padding.write() = Arc::new(new_pad);
                    debug!("anytls padding scheme updated by server");
                } else {
                    warn!("anytls failed to parse server-pushed padding scheme");
                }
            }
            CMD_HEART_REQUEST => {
                let _ = inner
                    .write_control_frame(CMD_HEART_RESPONSE, hdr.sid, &[])
                    .await;
            }
            CMD_HEART_RESPONSE => { /* no-op */ }
            CMD_SERVER_SETTINGS => {
                let m = decode_string_map(&data);
                if let Some(v) = m.get("v") {
                    if let Ok(v) = v.parse::<u8>() {
                        inner.peer_version.store(v, Ordering::Release);
                    }
                }
            }
            _ => { /* unknown */ }
        }
    }
}

type WriteFut = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;
type ShutdownFut = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// A stream multiplexed on an anytls session. Implements `AsyncRead +
/// AsyncWrite + Send + Unpin` so it can substitute for a raw proxy stream.
pub struct AnytlsStream {
    sid: u32,
    session: Arc<SessionInner>,
    rx: mpsc::UnboundedReceiver<Bytes>,
    leftover: Bytes,
    write_closed: bool,
    die_err: Arc<StreamSlot>,
    #[allow(dead_code)]
    die_notify: Arc<Notify>,
    fin_sent: bool,
    pending_write: Option<(usize, WriteFut)>,
    pending_shutdown: Option<ShutdownFut>,
}

impl AnytlsStream {
    fn take_die_err(&self) -> Option<io::Error> {
        self.die_err
            .die_err
            .lock()
            .clone()
            .map(|m| io::Error::new(io::ErrorKind::ConnectionReset, m))
    }
}

impl AsyncRead for AnytlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain leftover first.
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.remaining());
            buf.put_slice(&self.leftover[..n]);
            self.leftover = self.leftover.slice(n..);
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.leftover = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                if let Some(e) = self.take_die_err() {
                    Poll::Ready(Err(e))
                } else {
                    // Clean EOF
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnytlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write.is_none() {
            let sid = this.sid;
            let session = Arc::clone(&this.session);
            let data = buf.to_vec();
            let n = data.len();
            let fut: WriteFut = Box::pin(async move { session.write_data_frame(sid, &data).await });
            this.pending_write = Some((n, fut));
        }
        let (n, fut) = this.pending_write.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(_)) => {
                let n = *n;
                this.pending_write = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                this.pending_write = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        if this.pending_shutdown.is_none() {
            let sid = this.sid;
            let session = Arc::clone(&this.session);
            let fut: ShutdownFut =
                Box::pin(async move { session.write_control_frame(CMD_FIN, sid, &[]).await });
            this.pending_shutdown = Some(fut);
        }
        let fut = this.pending_shutdown.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(r) => {
                this.pending_shutdown = None;
                this.write_closed = true;
                this.fin_sent = true;
                Poll::Ready(r)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for AnytlsStream {
    fn drop(&mut self) {
        let sid = self.sid;
        // Remove from session map (release slot).
        self.session.remove_stream(sid);
        if !self.fin_sent && !self.session.is_closed() {
            let session = Arc::clone(&self.session);
            tokio::spawn(async move {
                let _ = session.write_control_frame(CMD_FIN, sid, &[]).await;
            });
        }
    }
}
