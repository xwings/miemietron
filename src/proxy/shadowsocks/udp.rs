/// UDP relay for Shadowsocks (stub).
///
/// Full UDP relay implementation is planned for a future phase.
/// This module provides the type so that the rest of the codebase can
/// reference it without feature-gating.
use super::aead::AeadCipher;

/// Placeholder struct for Shadowsocks UDP relay.
pub struct SsUdpRelay {
    server: String,
    port: u16,
    cipher: AeadCipher,
    master_key: Vec<u8>,
}

impl SsUdpRelay {
    /// Create a new UDP relay instance.
    pub fn new(server: String, port: u16, cipher: AeadCipher, master_key: Vec<u8>) -> Self {
        Self {
            server,
            port,
            cipher,
            master_key,
        }
    }

    /// Server address.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Server port.
    pub fn port(&self) -> u16 {
        self.port
    }
}
