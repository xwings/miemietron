//! XTLS-Vision support for VLESS.
//!
//! XTLS-Vision optimises TLS-in-TLS by detecting inner TLS records and
//! bypassing the outer encryption layer once the inner handshake completes.
//!
//! This initial implementation maintains protocol compatibility by sending the
//! correct `flow` addon in the VLESS header ("xtls-rprx-vision") while
//! relaying all data through the outer TLS layer normally.  The server-side
//! optimisation still takes effect; client-side direct-copy can be added later.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The flow identifier sent in the VLESS header addon.
#[allow(dead_code)]
pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// State of the Vision stream.
///
/// In a full implementation this would track the inner TLS handshake and
/// switch to direct copy after seeing enough Application Data records.
/// For now, we always stay in `Passthrough` which is protocol-correct:
/// the server sees the flow addon and applies its own optimisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum VisionState {
    /// Still seeing TLS handshake records -- encrypt normally via outer TLS.
    /// `client_hello_seen` tracks whether we have observed the inner
    /// ClientHello from the proxied client.
    Handshaking { client_hello_seen: bool },
    /// Inner TLS handshake appears complete -- could switch to direct copy.
    /// In this implementation we still relay through outer TLS (safe but
    /// without the CPU saving).
    Direct,
}

pin_project! {
    /// A stream wrapper that implements the XTLS-Vision protocol.
    ///
    /// Currently acts as a transparent passthrough while tracking inner TLS
    /// state.  A future optimisation can use `state` to skip outer encryption
    /// once the inner handshake is complete.
    pub struct VisionStream<T> {
        #[pin]
        inner: T,
        state: VisionState,
        app_data_count: usize,
    }
}

/// Number of Application Data records to observe before considering the
/// inner TLS handshake "complete".  The first Application Data record
/// typically carries the client Finished message (encrypted), and we wait
/// for a second one to be sure.
const DIRECT_THRESHOLD: usize = 2;

impl<T> VisionStream<T> {
    /// Create a new Vision stream wrapping an inner transport.
    #[allow(dead_code)]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            state: VisionState::Handshaking {
                client_hello_seen: false,
            },
            app_data_count: 0,
        }
    }

    /// Inspect outbound data and advance the state machine.
    ///
    /// Looks at the first byte of `data` to detect TLS record types:
    /// - 0x16 = Handshake (ClientHello, etc.)
    /// - 0x17 = Application Data
    /// - 0x14 = ChangeCipherSpec
    #[allow(dead_code)]
    fn observe_write(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        match self.state {
            VisionState::Handshaking {
                ref mut client_hello_seen,
            } => {
                match data[0] {
                    0x16 => {
                        // TLS Handshake record
                        *client_hello_seen = true;
                    }
                    0x17 => {
                        // TLS Application Data
                        self.app_data_count += 1;
                        if self.app_data_count >= DIRECT_THRESHOLD {
                            self.state = VisionState::Direct;
                        }
                    }
                    0x14 => {
                        // ChangeCipherSpec -- still handshaking
                    }
                    _ => {
                        // Non-TLS data or unknown -- stay in current state
                    }
                }
            }
            VisionState::Direct => {
                // Already in direct mode, nothing to do.
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for VisionStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Passthrough: in a full implementation, once in Direct state we could
        // read directly from the underlying TCP stream (bypassing outer TLS).
        // For now, always read from the outer (TLS-wrapped) stream.
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for VisionStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        // Observe the data for TLS record detection (state tracking only).
        // In a full implementation, Direct state would bypass outer encryption.
        // For now we always write through the outer stream.

        // We need to call observe_write on the unprojected fields.
        // Since state and app_data_count are not pinned, we can access them.
        if !data.is_empty() {
            match this.state {
                VisionState::Handshaking {
                    ref mut client_hello_seen,
                } => match data[0] {
                    0x16 => {
                        *client_hello_seen = true;
                    }
                    0x17 => {
                        *this.app_data_count += 1;
                        if *this.app_data_count >= DIRECT_THRESHOLD {
                            *this.state = VisionState::Direct;
                        }
                    }
                    _ => {}
                },
                VisionState::Direct => {}
            }
        }

        this.inner.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vision_flow_constant() {
        assert_eq!(VISION_FLOW, "xtls-rprx-vision");
    }

    #[test]
    fn vision_state_transitions() {
        let mut vs = VisionStream {
            inner: (),
            state: VisionState::Handshaking {
                client_hello_seen: false,
            },
            app_data_count: 0,
        };

        // Seeing a handshake record sets client_hello_seen.
        vs.observe_write(&[0x16, 0x03, 0x01]);
        assert!(matches!(
            vs.state,
            VisionState::Handshaking {
                client_hello_seen: true
            }
        ));

        // First Application Data record.
        vs.observe_write(&[0x17, 0x03, 0x03]);
        assert_eq!(vs.app_data_count, 1);
        assert!(matches!(vs.state, VisionState::Handshaking { .. }));

        // Second Application Data record triggers Direct.
        vs.observe_write(&[0x17, 0x03, 0x03]);
        assert_eq!(vs.app_data_count, 2);
        assert_eq!(vs.state, VisionState::Direct);

        // Further data stays in Direct.
        vs.observe_write(&[0x17, 0x03, 0x03]);
        assert_eq!(vs.state, VisionState::Direct);
    }

    #[test]
    fn vision_state_change_cipher_spec() {
        let mut vs = VisionStream {
            inner: (),
            state: VisionState::Handshaking {
                client_hello_seen: false,
            },
            app_data_count: 0,
        };

        // ChangeCipherSpec should not change state.
        vs.observe_write(&[0x14]);
        assert!(matches!(
            vs.state,
            VisionState::Handshaking {
                client_hello_seen: false
            }
        ));
    }

    #[test]
    fn vision_empty_data() {
        let mut vs = VisionStream {
            inner: (),
            state: VisionState::Handshaking {
                client_hello_seen: false,
            },
            app_data_count: 0,
        };

        // Empty data should not panic or change state.
        vs.observe_write(&[]);
        assert!(matches!(
            vs.state,
            VisionState::Handshaking {
                client_hello_seen: false
            }
        ));
    }
}
