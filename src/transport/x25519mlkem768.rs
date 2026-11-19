//! Client side of the X25519MLKEM768 hybrid key exchange.
//!
//! Wire format (draft-ietf-tls-ecdhe-mlkem), the same one Go's `crypto/tls`
//! speaks — which is what mihomo's uTLS and the REALITY server are built on:
//!
//! * client share: ML-KEM-768 encapsulation key (1184) ‖ X25519 public key (32)
//! * server share: ML-KEM-768 ciphertext (1088) ‖ X25519 public key (32)
//! * shared secret: ML-KEM shared secret (32) ‖ X25519 shared secret (32)
//!
//! Built from the pure-Rust `ml-kem` and `x25519-dalek` crates so the static
//! musl targets need no C toolchain.

use ml_kem::{Decapsulate, DecapsulationKey768, KeyExport, Seed};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const X25519_KEY_LEN: usize = 32;

/// The peer sent a key share this exchange cannot be completed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKeyShare;

/// X25519 between `secret` and `peer_public`.
///
/// mihomo compat: Go's `ecdh` rejects a low-order peer point (all-zero
/// output), so a server cannot force a known shared secret.
pub fn x25519(secret: &StaticSecret, peer_public: &[u8]) -> Result<[u8; 32], InvalidKeyShare> {
    let peer_public: [u8; X25519_KEY_LEN] = peer_public.try_into().map_err(|_| InvalidKeyShare)?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer_public));
    if !shared.was_contributory() {
        return Err(InvalidKeyShare);
    }
    Ok(shared.to_bytes())
}

/// One client key share: an ML-KEM-768 decapsulation key plus an X25519 secret.
pub struct HybridKeyShare {
    mlkem: DecapsulationKey768,
    x25519: StaticSecret,
}

impl HybridKeyShare {
    pub fn generate() -> Self {
        let mut seed = [0u8; 64];
        OsRng.fill_bytes(&mut seed);
        Self {
            mlkem: DecapsulationKey768::from_seed(Seed::from(seed)),
            x25519: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// The ML-KEM-768 encapsulation key.
    pub fn encapsulation_key(&self) -> Vec<u8> {
        self.mlkem.encapsulation_key().to_bytes().to_vec()
    }

    /// The X25519 half's secret: REALITY authenticates with it when the hello
    /// carries no separate X25519 share, and Firefox reuses it for that share.
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519
    }

    pub fn x25519_public(&self) -> [u8; X25519_KEY_LEN] {
        PublicKey::from(&self.x25519).to_bytes()
    }

    /// Finish the exchange against a server share, returning the 64-byte
    /// combined secret.
    pub fn complete(&self, server_share: &[u8]) -> Result<[u8; 64], InvalidKeyShare> {
        if server_share.len() != MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN {
            return Err(InvalidKeyShare);
        }
        let (ciphertext, x25519_public) = server_share.split_at(MLKEM768_CIPHERTEXT_LEN);
        let ciphertext = ciphertext.try_into().map_err(|_| InvalidKeyShare)?;

        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&self.mlkem.decapsulate(ciphertext));
        secret[32..].copy_from_slice(&x25519(&self.x25519, x25519_public)?);
        Ok(secret)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ml_kem::EncapsulationKey768;

    /// What a TLS server does with a client share: encapsulate to the ML-KEM
    /// key and run X25519 against the trailing public key. Returns the server
    /// share and the secret the server ends up with.
    pub(crate) fn server_side(
        encapsulation_key: &[u8],
        client_x25519: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let encapsulation_key =
            EncapsulationKey768::new(encapsulation_key.try_into().unwrap()).unwrap();
        let (ciphertext, mlkem_secret) =
            encapsulation_key.encapsulate_deterministic(&[7u8; 32].into());

        let server_x25519 = StaticSecret::from([9u8; 32]);
        let client_x25519: [u8; 32] = client_x25519.try_into().unwrap();
        let x25519_secret = server_x25519.diffie_hellman(&PublicKey::from(client_x25519));

        let mut share = ciphertext.to_vec();
        share.extend_from_slice(PublicKey::from(&server_x25519).as_bytes());
        let mut secret = mlkem_secret.to_vec();
        secret.extend_from_slice(x25519_secret.as_bytes());
        (share, secret)
    }

    #[test]
    fn share_halves_have_the_wire_sizes() {
        let share = HybridKeyShare::generate();
        assert_eq!(share.encapsulation_key().len(), 1184);
        assert_eq!(
            share.x25519_public(),
            PublicKey::from(share.x25519_secret()).to_bytes()
        );
    }

    #[test]
    fn completes_against_a_server_share() {
        let share = HybridKeyShare::generate();
        let (server_share, server_secret) =
            server_side(&share.encapsulation_key(), &share.x25519_public());
        assert_eq!(server_share.len(), 1088 + 32);
        assert_eq!(
            share.complete(&server_share).unwrap().as_slice(),
            server_secret
        );
    }

    #[test]
    fn rejects_malformed_server_shares() {
        let share = HybridKeyShare::generate();
        let (server_share, _) = server_side(&share.encapsulation_key(), &share.x25519_public());

        // Truncated, and a bare X25519 key where the hybrid share belongs.
        assert!(share
            .complete(&server_share[..server_share.len() - 1])
            .is_err());
        assert!(share.complete(&[9u8; 32]).is_err());
        // A low-order X25519 point must not yield an all-zero secret.
        assert!(x25519(share.x25519_secret(), &[0u8; 32]).is_err());
        let mut low_order = server_share.clone();
        low_order[MLKEM768_CIPHERTEXT_LEN..].fill(0);
        assert!(share.complete(&low_order).is_err());
    }
}
