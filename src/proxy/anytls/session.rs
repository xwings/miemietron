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
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex as PlMutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use super::frame::{
    decode_string_map, encode_data_frames, encode_header, encode_string_map, Header, CMD_ALERT,
    CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS,
    CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, HEADER_OVERHEAD,
};
use super::padding::{scheme_md5, update_padding_scheme, SharedPadding, CHECK_MARK};

/// Async reader half of a TLS stream erased to a trait object.
pub type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
/// Async writer half of a TLS stream erased to a trait object.
pub type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

const WRITE_DEADLINE: Duration = Duration::from_secs(5);
/// mihomo compat: session.go OpenStream gives a v2 server this long to answer
/// SYN with SYNACK before the whole session is closed.
const SYNACK_DEADLINE: Duration = Duration::from_secs(3);
/// Frames queued for a stream's reader before the recv loop waits for it.
/// mihomo compat: pipe/io_pipe.go hands each frame straight to the reader, so
/// a stream nobody reads stalls the session's reads and, through TCP, the
/// server — instead of piling the download up in memory.
const STREAM_QUEUE_FRAMES: usize = 8;
const CLIENT_VERSION: &str = "2";

fn session_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "session closed")
}

/// Shared session state. Hosted by [`Session`] and referenced from
/// [`AnytlsStream`] handles and the background recv loop.
pub struct SessionInner {
    writer: TokioMutex<WriterState>,
    streams: PlMutex<HashMap<u32, StreamSlot>>,
    padding: SharedPadding,
    client_metadata: String,
    next_stream_id: AtomicU32,
    /// mihomo `Session.die`: cancelled once, by [`SessionInner::close`].
    die: CancellationToken,
    /// mihomo `Session.synDone`: stops the pending SYNACK watchdog.
    syn_done: PlMutex<Option<AbortHandle>>,
    pub peer_version: AtomicU8,
    pub idle_since: PlMutex<Instant>,
}

struct WriterState {
    writer: BoxedWriter,
    buffering: bool,
    buffer: Vec<u8>,
    send_padding: bool,
    pkt_counter: u32,
}

/// A stream as the recv loop sees it. The slot owns the stream's only
/// long-lived sender: taking it out of the session map ends the stream's
/// reads, once what was already queued has been consumed.
struct StreamSlot {
    tx: mpsc::Sender<Bytes>,
    die: Arc<OnceLock<Die>>,
}

/// Why a stream died (mihomo `Stream.dieErr`). Set once, by whoever closes
/// the stream first (`Stream.dieOnce`).
enum Die {
    /// FIN, from either side.
    Fin,
    /// The session closed under the stream.
    Session,
    /// The server could not open the stream and said why in its SYNACK.
    Remote(String),
}

impl Die {
    fn error(&self) -> io::Error {
        match self {
            // mihomo: net.ErrClosed.
            Die::Fin => io::Error::new(
                io::ErrorKind::BrokenPipe,
                "use of closed network connection",
            ),
            Die::Session => session_closed(),
            Die::Remote(msg) => {
                io::Error::new(io::ErrorKind::ConnectionReset, format!("remote: {msg}"))
            }
        }
    }
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
        self.die.is_cancelled()
    }

    /// mihomo Session.Close: fail blocked I/O and every stream. Idempotent.
    pub fn close(&self) {
        // mihomo compat: `conn.SetDeadline(time.Now())` + `close(s.die)` — the
        // recv loop and any write in flight stop on this token; the recv task
        // then closes the connection.
        self.die.cancel();
        // `register_stream` re-checks `die` under this lock, so no stream can
        // be added behind the drain.
        for (_, slot) in self.streams.lock().drain() {
            // mihomo Stream.closeLocally.
            let _ = slot.die.set(Die::Session);
        }
    }

    /// Write a data frame for `sid`. Returns the number of payload bytes
    /// written (equal to `data.len()` on success).
    ///
    /// mihomo compat: session.go writeDataFrame — a write longer than
    /// [`MAX_FRAME_DATA_LEN`] is split into several PSH frames, since the
    /// header length field is a u16. The whole frame sequence goes out in ONE
    /// `write_conn_framed` call so a single stream write stays contiguous
    /// relative to other streams' data and to control frames.
    pub async fn write_data_frame(self: &Arc<Self>, sid: u32, data: &[u8]) -> io::Result<usize> {
        if self.is_closed() {
            return Err(session_closed());
        }
        if data.is_empty() {
            return Ok(0);
        }
        self.write_conn_framed(&encode_data_frames(sid, data))
            .await?;
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
            return Err(session_closed());
        }
        let frame = self.build_frame(cmd, sid, data);
        let result = tokio::time::timeout(WRITE_DEADLINE, self.write_conn_framed(&frame))
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "control write")));
        if result.is_err() {
            // mihomo compat: session.go writeControlFrame closes the session
            // on any write error, the expired deadline included.
            self.close();
        }
        result
    }

    /// mihomo Session.streamClosed: tell the server a stream was closed on
    /// this side, then forget it.
    async fn stream_closed(self: &Arc<Self>, sid: u32) -> io::Result<()> {
        if self.is_closed() {
            return Err(session_closed());
        }
        let result = self.write_control_frame(CMD_FIN, sid, &[]).await;
        self.remove_stream(sid);
        result
    }

    /// [`Self::write_conn`], given up as soon as the session closes.
    async fn write_conn_framed(self: &Arc<Self>, data: &[u8]) -> io::Result<()> {
        tokio::select! {
            result = self.write_conn(data) => result,
            // mihomo compat: Session.Close sets `conn.SetDeadline(time.Now())`
            // so that a write blocked on the peer cannot outlive the session.
            _ = self.die.cancelled() => Err(session_closed()),
        }
    }

    /// Port of mihomo session.writeConn — handles buffering and padding.
    async fn write_conn(self: &Arc<Self>, data: &[u8]) -> io::Result<()> {
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
                if !payload.is_empty() {
                    ws.writer.write_all(&payload).await?;
                }
                return ws.writer.flush().await;
            } else {
                ws.send_padding = false;
            }
        }

        ws.writer.write_all(&payload).await?;
        // A Go `conn.Write` returns once the bytes are with the kernel. A TLS
        // writer may still be holding some back, and nothing else on an idle
        // stream would push them out.
        ws.writer.flush().await
    }

    fn register_stream(&self, sid: u32, slot: StreamSlot) -> io::Result<()> {
        let mut streams = self.streams.lock();
        // mihomo OpenStream: checked under the stream lock, so that a
        // concurrent `close` either sees the stream or stops it here.
        if self.is_closed() {
            return Err(session_closed());
        }
        streams.insert(sid, slot);
        Ok(())
    }

    fn remove_stream(&self, sid: u32) -> Option<StreamSlot> {
        self.streams.lock().remove(&sid)
    }

    fn take_stream_sender(&self, sid: u32) -> Option<mpsc::Sender<Bytes>> {
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
        padding: SharedPadding,
        client_metadata: String,
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
            padding,
            client_metadata,
            next_stream_id: AtomicU32::new(0),
            die: CancellationToken::new(),
            syn_done: PlMutex::new(None),
            peer_version: AtomicU8::new(0),
            idle_since: PlMutex::new(Instant::now()),
        });
        // Spawn the recv loop.
        let loop_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            tokio::select! {
                result = recv_loop(Arc::clone(&loop_inner), reader) => {
                    if let Err(e) = result {
                        debug!("anytls recv_loop exited: {e}");
                    }
                }
                _ = loop_inner.die.cancelled() => {}
            }
            loop_inner.close();
            // mihomo Session.Close → conn.Close(): TLS says goodbye under its
            // own 5 s write deadline (crypto/tls closeNotify).
            let _ = tokio::time::timeout(WRITE_DEADLINE, async {
                loop_inner.writer.lock().await.writer.shutdown().await
            })
            .await;
        });
        Self { inner }
    }

    /// Send the client settings frame. mihomo's client does this in Run();
    /// we do it once, lazily, before the first stream is opened.
    pub async fn send_initial_settings(&self) -> io::Result<()> {
        let md5 = self.inner.padding.read().md5_hex.clone();
        // mihomo compat: session.go Run — `client` is the `client-metadata`
        // option, and empty unless the user set it.
        let data = encode_string_map(&[
            ("v", CLIENT_VERSION),
            ("client", self.inner.client_metadata.as_str()),
            ("padding-md5", md5.as_str()),
        ]);
        self.inner.write_control_frame(CMD_SETTINGS, 0, &data).await
    }

    /// Open a new stream on this session.
    pub async fn open_stream(&self) -> io::Result<AnytlsStream> {
        if self.inner.is_closed() {
            return Err(session_closed());
        }
        let sid = self.inner.next_stream_id.fetch_add(1, Ordering::AcqRel) + 1;

        let (tx, rx) = mpsc::channel::<Bytes>(STREAM_QUEUE_FRAMES);
        let die = Arc::new(OnceLock::new());
        self.inner.register_stream(
            sid,
            StreamSlot {
                tx,
                die: Arc::clone(&die),
            },
        )?;
        // From here on dropping the stream — this future being cancelled
        // included — reports FIN and forgets the slot.
        let stream = AnytlsStream {
            sid,
            session: Arc::clone(&self.inner),
            rx,
            leftover: Bytes::new(),
            die,
            pending_write: None,
            pending_shutdown: None,
        };

        // mihomo compat: session.go OpenStream — from the second stream on, a
        // v2 server owes a SYNACK. One that does not come within 3 s means
        // the connection is black-holed, and the whole session is closed
        // instead of going back to the pool. Opening another stream restarts
        // the clock; any SYNACK stops it.
        if sid >= 2 && self.inner.peer_version.load(Ordering::Acquire) >= 2 {
            let session = Arc::downgrade(&self.inner);
            let watchdog = tokio::spawn(async move {
                tokio::time::sleep(SYNACK_DEADLINE).await;
                if let Some(session) = session.upgrade() {
                    session.close();
                }
            });
            if let Some(previous) = self.inner.syn_done.lock().replace(watchdog.abort_handle()) {
                previous.abort();
            }
        }

        // Write SYN (still in buffer mode).
        self.inner.write_control_frame(CMD_SYN, sid, &[]).await?;

        // Clear buffering — the next writeDataFrame will flush settings+SYN
        // alongside the first payload chunk.
        {
            let mut ws = self.inner.writer.lock().await;
            ws.buffering = false;
        }

        Ok(stream)
    }
}

impl Drop for Session {
    /// The idle pool and a live stream's wrapper are the only holders. Once
    /// the last one lets go nothing can open a stream here again, so the
    /// connection is closed rather than left to the recv loop
    /// (mihomo session/client.go closes every session it does not pool).
    fn drop(&mut self) {
        self.inner.close();
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
                // mihomo: `if hdr.Length() > 0` — an empty PSH carries nothing
                // and must not read as end of stream.
                if !data.is_empty() {
                    if let Some(tx) = inner.take_stream_sender(hdr.sid) {
                        // Waiting for a reader that is behind is the stream's
                        // flow control (see STREAM_QUEUE_FRAMES).
                        let _ = tx.send(data).await;
                    }
                }
            }
            CMD_SYNACK => {
                if let Some(watchdog) = inner.syn_done.lock().take() {
                    watchdog.abort();
                }
                // Error report on stream creation (only when data is present).
                if !data.is_empty() {
                    let msg = String::from_utf8_lossy(&data).into_owned();
                    if let Some(slot) = inner.remove_stream(hdr.sid) {
                        // mihomo Stream.closeWithError: the close that wins
                        // `dieOnce` releases the reader, then reports FIN.
                        let won = slot.die.set(Die::Remote(msg)).is_ok();
                        drop(slot);
                        if won {
                            let _ = inner.write_control_frame(CMD_FIN, hdr.sid, &[]).await;
                        }
                    }
                }
            }
            CMD_FIN => {
                if let Some(slot) = inner.remove_stream(hdr.sid) {
                    // mihomo Stream.closeLocally. Dropping the slot drops the
                    // sender, which is the reader's end of stream.
                    let _ = slot.die.set(Die::Fin);
                }
            }
            CMD_WASTE => { /* discard */ }
            CMD_SETTINGS => { /* server->client direction not expected */ }
            CMD_ALERT => {
                // mihomo: only an alert that says something ends the session.
                if !data.is_empty() {
                    error!("[Alert from server] {}", String::from_utf8_lossy(&data));
                    return Ok(());
                }
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if !data.is_empty() {
                    let md5 = scheme_md5(&data);
                    if update_padding_scheme(&data, &inner.padding) {
                        debug!("[Update padding succeed] {md5}");
                    } else {
                        warn!("[Update padding failed] {md5}");
                    }
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
///
/// mihomo compat: stream.go — there is no half-close. FIN from either side,
/// a SYNACK error or the session closing ends the stream in both directions.
pub struct AnytlsStream {
    sid: u32,
    session: Arc<SessionInner>,
    rx: mpsc::Receiver<Bytes>,
    leftover: Bytes,
    /// Shared with the recv loop, which is how the server and the session end
    /// the stream.
    die: Arc<OnceLock<Die>>,
    pending_write: Option<(usize, WriteFut)>,
    pending_shutdown: Option<ShutdownFut>,
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
            // The stream died, and everything that arrived before has been
            // read.
            Poll::Ready(None) => match self.die.get() {
                Some(die @ (Die::Session | Die::Remote(_))) => Poll::Ready(Err(die.error())),
                // FIN: a clean end of stream.
                _ => Poll::Ready(Ok(())),
            },
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
            // mihomo Stream.Write: a dead stream takes no more data.
            if let Some(die) = this.die.get() {
                return Poll::Ready(Err(die.error()));
            }
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
        // A write the caller walked away from still has to finish its frame.
        if let Some((_, write)) = this.pending_write.as_mut() {
            let _ = ready!(write.as_mut().poll(cx));
            this.pending_write = None;
        }
        if this.pending_shutdown.is_none() {
            // mihomo Stream.Close → closeWithError: only the close that wins
            // `dieOnce` reports FIN, and the stream is dead from then on.
            if this.die.set(Die::Fin).is_err() {
                return Poll::Ready(Ok(()));
            }
            let sid = this.sid;
            let session = Arc::clone(&this.session);
            let fut: ShutdownFut = Box::pin(async move { session.stream_closed(sid).await });
            this.pending_shutdown = Some(fut);
        }
        let fut = this.pending_shutdown.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(r) => {
                this.pending_shutdown = None;
                Poll::Ready(r)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AnytlsStream {
    /// What closing the stream still owes the wire, if anything; `None` once
    /// taken. Whoever holds the stream last runs it to the end.
    ///
    /// mihomo Stream.Close: FIN is reported by the close that wins `dieOnce`
    /// — not after the server's FIN, nor twice, nor on a dead session.
    pub(super) fn closing(&mut self) -> Option<impl Future<Output = ()> + Send + 'static> {
        let close = self.pending_shutdown.take().or_else(|| {
            self.die.set(Die::Fin).ok()?;
            let sid = self.sid;
            let session = Arc::clone(&self.session);
            let fut: ShutdownFut = Box::pin(async move { session.stream_closed(sid).await });
            Some(fut)
        });
        let write = self.pending_write.take();
        if (close.is_none() && write.is_none()) || self.session.is_closed() {
            return None;
        }
        Some(async move {
            // A frame abandoned halfway would leave the next stream on this
            // session a torn one to follow.
            if let Some((_, write)) = write {
                let _ = write.await;
            }
            if let Some(close) = close {
                let _ = close.await;
            }
        })
    }
}

impl Drop for AnytlsStream {
    fn drop(&mut self) {
        if let Some(closing) = self.closing() {
            tokio::spawn(closing);
        }
    }
}

/// The server end of a session, driven frame by frame.
#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    /// The next frame that is not padding.
    pub async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> (u8, u32, Vec<u8>) {
        loop {
            let mut hdr = [0u8; HEADER_OVERHEAD];
            io.read_exact(&mut hdr).await.unwrap();
            let hdr = Header::parse(&hdr);
            let mut data = vec![0u8; hdr.length as usize];
            io.read_exact(&mut data).await.unwrap();
            if hdr.cmd != CMD_WASTE {
                return (hdr.cmd, hdr.sid, data);
            }
        }
    }

    pub async fn write_frame<W: AsyncWrite + Unpin>(io: &mut W, cmd: u8, sid: u32, data: &[u8]) {
        let mut frame = encode_header(cmd, sid, data.len() as u16).to_vec();
        frame.extend_from_slice(data);
        io.write_all(&frame).await.unwrap();
    }

    /// Fail instead of hanging when the awaited thing never happens.
    pub async fn within<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("timed out")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{read_frame, within, write_frame};
    use super::*;
    use crate::proxy::anytls::padding::PaddingFactory;
    use parking_lot::RwLock;
    use tokio::io::DuplexStream;

    fn default_padding() -> SharedPadding {
        Arc::new(RwLock::new(Arc::new(PaddingFactory::default_scheme())))
    }

    /// A client session over an in-memory pipe, and the server's end of it.
    /// `pipe` has to hold the padding that trails a session's first flush
    /// (under 400 bytes with the default scheme), which no test reads.
    fn pair_with(pipe: usize, padding: SharedPadding, metadata: &str) -> (Session, DuplexStream) {
        let (client, server) = tokio::io::duplex(pipe);
        let (reader, writer) = tokio::io::split(client);
        let session = Session::new_client(
            Box::new(reader),
            Box::new(writer),
            padding,
            metadata.to_string(),
        );
        (session, server)
    }

    fn pair() -> (Session, DuplexStream) {
        pair_with(64 * 1024, default_padding(), "")
    }

    /// Open the first stream of a fresh session the way the outbound does —
    /// settings, SYN and the destination in one flush — and return the
    /// settings the server received. The server announces `version`, if any.
    async fn first_stream(
        session: &Session,
        server: &mut DuplexStream,
        version: Option<&str>,
    ) -> (AnytlsStream, String) {
        session.send_initial_settings().await.unwrap();
        let mut stream = session.open_stream().await.unwrap();
        let (written, settings) = within(async {
            tokio::join!(stream.write_all(b"dst"), async {
                let (cmd, sid, settings) = read_frame(server).await;
                assert_eq!((cmd, sid), (CMD_SETTINGS, 0));
                assert_eq!(read_frame(server).await, (CMD_SYN, 1, vec![]));
                assert_eq!(read_frame(server).await, (CMD_PSH, 1, b"dst".to_vec()));
                String::from_utf8(settings).unwrap()
            })
        })
        .await;
        written.unwrap();
        if let Some(version) = version {
            write_frame(server, CMD_SERVER_SETTINGS, 0, version.as_bytes()).await;
        }
        (stream, settings)
    }

    /// Returns once the client has processed every frame the server wrote
    /// before this call.
    async fn sync(stream: &mut AnytlsStream, sid: u32, server: &mut DuplexStream) {
        write_frame(server, CMD_PSH, sid, b"\x00").await;
        let mut byte = [0xffu8; 1];
        within(stream.read_exact(&mut byte)).await.unwrap();
        assert_eq!(byte, [0]);
    }

    /// session.go Run since b27c659: `"client": s.clientMetadata`, empty
    /// unless `client-metadata` is configured; util/string_map.go ToBytes
    /// joins the lines without a trailing newline.
    #[tokio::test]
    async fn settings_carry_client_metadata_only_when_configured() {
        let md5 = PaddingFactory::default_scheme().md5_hex;
        for (metadata, line) in [("", "client="), ("probe/1.0", "client=probe/1.0")] {
            let (session, mut server) = pair_with(64 * 1024, default_padding(), metadata);
            let (_stream, settings) = first_stream(&session, &mut server, None).await;
            assert_eq!(settings, format!("v=2\n{line}\npadding-md5={md5}"));
        }
    }

    /// session.go `case cmdFIN` → stream.go closeLocally: the server's FIN
    /// ends the stream. What it sent before is still read, writes fail from
    /// then on (`if s.dieErr != nil`), and no FIN goes back (`dieOnce`).
    #[tokio::test]
    async fn remote_fin_is_end_of_stream_after_the_data_before_it() {
        let (session, mut server) = pair();
        let (mut stream, _) = first_stream(&session, &mut server, Some("v=2")).await;
        write_frame(&mut server, CMD_PSH, 1, b"hello ").await;
        write_frame(&mut server, CMD_PSH, 1, b"world").await;
        write_frame(&mut server, CMD_FIN, 1, b"").await;

        let mut received = Vec::new();
        within(stream.read_to_end(&mut received)).await.unwrap();
        assert_eq!(received, b"hello world");
        let error = within(stream.write_all(b"late")).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!session.inner.is_closed());

        drop(stream);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let mut next = session.open_stream().await.unwrap();
        next.write_all(b"dst").await.unwrap();
        assert_eq!(within(read_frame(&mut server)).await, (CMD_SYN, 2, vec![]));
        assert_eq!(
            within(read_frame(&mut server)).await,
            (CMD_PSH, 2, b"dst".to_vec())
        );
    }

    /// session.go `case cmdSYNACK` with a payload → closeWithError(
    /// "remote: <msg>"): both halves report it, and streamClosed sends FIN.
    #[tokio::test]
    async fn synack_error_reaches_the_reader_and_the_writer() {
        let (session, mut server) = pair();
        let (mut stream, _) = first_stream(&session, &mut server, Some("v=2")).await;
        write_frame(&mut server, CMD_SYNACK, 1, b"dial tcp: connection refused").await;

        let error = within(stream.read(&mut [0u8; 16])).await.unwrap_err();
        assert_eq!(error.to_string(), "remote: dial tcp: connection refused");
        let error = within(stream.write_all(b"request")).await.unwrap_err();
        assert_eq!(error.to_string(), "remote: dial tcp: connection refused");
        assert_eq!(within(read_frame(&mut server)).await, (CMD_FIN, 1, vec![]));
        // The session itself is fine and goes on to serve other streams.
        assert!(!session.inner.is_closed());
    }

    /// session.go Close → closeLocally on every stream: when the connection
    /// goes away, no stream is left waiting.
    #[tokio::test]
    async fn session_death_fails_every_stream() {
        let (session, mut server) = pair();
        let (mut first, _) = first_stream(&session, &mut server, Some("v=2")).await;
        let mut second = session.open_stream().await.unwrap();
        second.write_all(b"dst").await.unwrap();
        // One reader is already parked when the connection drops.
        let parked = tokio::spawn(async move {
            let result = first.read(&mut [0u8; 16]).await;
            (first, result)
        });
        tokio::task::yield_now().await;
        drop(server);

        let (mut first, result) = within(parked).await.unwrap();
        assert_eq!(result.unwrap_err().to_string(), "session closed");
        assert!(within(second.read(&mut [0u8; 16])).await.is_err());
        assert!(within(first.write_all(b"x")).await.is_err());
        assert!(within(second.write_all(b"x")).await.is_err());
        assert!(session.inner.is_closed());
        assert!(session.open_stream().await.is_err());
    }

    /// stream.go Close → closeWithError: closing is not half-closing. The
    /// server answers a FIN with nothing (its own close finds `dieOnce`
    /// spent), so the reader must not wait for one.
    #[tokio::test]
    async fn local_shutdown_ends_reads_without_an_answer() {
        let (session, mut server) = pair();
        let (mut stream, _) = first_stream(&session, &mut server, Some("v=2")).await;
        write_frame(&mut server, CMD_PSH, 1, b"tail").await;
        within(stream.read_exact(&mut [0u8; 2])).await.unwrap();

        within(stream.shutdown()).await.unwrap();
        assert_eq!(within(read_frame(&mut server)).await, (CMD_FIN, 1, vec![]));
        let mut rest = Vec::new();
        within(stream.read_to_end(&mut rest)).await.unwrap();
        assert_eq!(rest, b"il");
        assert!(within(stream.write_all(b"late")).await.is_err());
        // FIN went out once: the next frame belongs to the next stream.
        drop(stream);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let mut next = session.open_stream().await.unwrap();
        next.write_all(b"dst").await.unwrap();
        assert_eq!(within(read_frame(&mut server)).await, (CMD_SYN, 2, vec![]));
    }

    /// session.go OpenStream: `if sid >= 2 && s.peerVersion >= 2` arms a 3 s
    /// DeadlineWatcher whose expiry closes the session.
    #[tokio::test(start_paused = true)]
    async fn synack_watchdog_closes_the_session_after_three_seconds() {
        let (session, mut server) = pair();
        let (mut first, _) = first_stream(&session, &mut server, Some("v=2")).await;
        sync(&mut first, 1, &mut server).await;

        let mut second = session.open_stream().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2900)).await;
        assert!(!session.inner.is_closed());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(session.inner.is_closed());
        assert!(within(first.read(&mut [0u8; 1])).await.is_err());
        assert!(within(second.read(&mut [0u8; 1])).await.is_err());
    }

    /// session.go `case cmdSYNACK`: any SYNACK stops the watcher; and
    /// OpenStream replaces a watcher that is still running.
    #[tokio::test(start_paused = true)]
    async fn synack_stops_the_watchdog_and_a_new_stream_restarts_it() {
        let (session, mut server) = pair();
        let (mut first, _) = first_stream(&session, &mut server, Some("v=2")).await;
        sync(&mut first, 1, &mut server).await;

        let _second = session.open_stream().await.unwrap();
        write_frame(&mut server, CMD_SYNACK, 2, b"").await;
        sync(&mut first, 1, &mut server).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!session.inner.is_closed());

        let _third = session.open_stream().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _fourth = session.open_stream().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2900)).await;
        assert!(!session.inner.is_closed());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(session.inner.is_closed());
    }

    /// The watcher's two conditions: not for the first stream (the server's
    /// version is not known yet), and not for a v1 server (no SYNACK exists).
    #[tokio::test(start_paused = true)]
    async fn synack_watchdog_needs_a_second_stream_and_a_v2_server() {
        let (session, mut server) = pair();
        let (mut first, _) = first_stream(&session, &mut server, Some("v=2")).await;
        sync(&mut first, 1, &mut server).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!session.inner.is_closed());

        for version in [None, Some("v=1")] {
            let (session, mut server) = pair();
            let (mut first, _) = first_stream(&session, &mut server, version).await;
            sync(&mut first, 1, &mut server).await;
            let _second = session.open_stream().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            assert!(!session.inner.is_closed(), "server version {version:?}");
        }
    }

    /// client.go keeps one `atomic.Pointer[PaddingFactory]` for the client and
    /// all its sessions: a scheme pushed to one session is what the next one
    /// announces (and authenticates with).
    #[tokio::test]
    async fn padding_update_reaches_sessions_dialed_later() {
        let padding = default_padding();
        let (session, mut server) = pair_with(64 * 1024, padding.clone(), "");
        let (mut stream, settings) = first_stream(&session, &mut server, Some("v=2")).await;
        let default_md5 = PaddingFactory::default_scheme().md5_hex;
        assert!(settings.ends_with(&format!("padding-md5={default_md5}")));

        let scheme = b"stop=3\n0=50-50\n1=100-200\n2=100-200";
        write_frame(&mut server, CMD_UPDATE_PADDING_SCHEME, 0, scheme).await;
        sync(&mut stream, 1, &mut server).await;
        assert_eq!(padding.read().md5_hex, scheme_md5(scheme));

        let (later, mut server) = pair_with(64 * 1024, padding.clone(), "");
        let (_stream, settings) = first_stream(&later, &mut server, None).await;
        assert!(settings.ends_with(&format!("padding-md5={}", scheme_md5(scheme))));

        // A scheme that does not parse changes nothing.
        write_frame(&mut server, CMD_UPDATE_PADDING_SCHEME, 0, b"junk").await;
        write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2").await;
        within(async {
            while later.inner.peer_version.load(Ordering::Acquire) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(padding.read().md5_hex, scheme_md5(scheme));
    }

    /// session/client.go Close closes the sessions it owns. Here the last
    /// handle going away does it: the recv loop stops and the connection is
    /// shut down and released.
    #[tokio::test]
    async fn dropping_the_session_closes_the_connection() {
        let (session, mut server) = pair();
        drop(session);
        assert_eq!(within(server.read(&mut [0u8; 1])).await.unwrap(), 0);
        within(async {
            while server.write_all(&[0]).await.is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    /// session.go recvLoop guards PSH and Alert with `if hdr.Length() > 0`.
    #[tokio::test]
    async fn empty_psh_and_alert_frames_are_ignored() {
        let (session, mut server) = pair();
        let (mut stream, _) = first_stream(&session, &mut server, Some("v=2")).await;
        write_frame(&mut server, CMD_PSH, 1, b"").await;
        write_frame(&mut server, CMD_ALERT, 0, b"").await;
        write_frame(&mut server, CMD_PSH, 1, b"data").await;
        let mut buf = [0u8; 8];
        let n = within(stream.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"data");
        assert!(!session.inner.is_closed());

        write_frame(&mut server, CMD_ALERT, 0, b"go away").await;
        assert!(within(stream.read(&mut buf)).await.is_err());
        assert!(session.inner.is_closed());
    }

    /// pipe/io_pipe.go: a frame is handed to the stream's reader, not stored
    /// without limit, so a download nobody reads holds the server back.
    #[tokio::test(start_paused = true)]
    async fn an_unread_stream_pushes_back_on_the_server() {
        const FRAMES: usize = 200;
        let (session, mut server) = pair_with(4096, default_padding(), "");
        let (mut stream, _) = first_stream(&session, &mut server, Some("v=2")).await;
        let writer = tokio::spawn(async move {
            for i in 0..FRAMES {
                write_frame(&mut server, CMD_PSH, 1, &[i as u8; 1024]).await;
            }
            server
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!writer.is_finished());

        let mut received = vec![0u8; FRAMES * 1024];
        within(stream.read_exact(&mut received)).await.unwrap();
        for (i, frame) in received.chunks(1024).enumerate() {
            assert!(frame.iter().all(|byte| *byte == i as u8), "frame {i}");
        }
        within(writer).await.unwrap();
    }

    /// A write cancelled halfway (the relay task aborted, say) must not leave
    /// half a frame on a session that goes back to the pool.
    #[tokio::test]
    async fn an_abandoned_write_still_finishes_its_frame() {
        let (session, mut server) = pair_with(1024, default_padding(), "");
        let (mut stream, _) = first_stream(&session, &mut server, Some("v=2")).await;
        let payload = vec![7u8; 8000];
        {
            let mut write = Box::pin(stream.write_all(&payload));
            assert!(futures_util::poll!(write.as_mut()).is_pending());
        }
        drop(stream);
        assert_eq!(within(read_frame(&mut server)).await, (CMD_PSH, 1, payload));
        assert_eq!(within(read_frame(&mut server)).await, (CMD_FIN, 1, vec![]));
    }
}
