//! Client side of the X25519MLKEM768 hybrid key exchange, as a rustls
//! [`ActiveKeyExchange`].
//!
//! Wire format (draft-ietf-tls-ecdhe-mlkem), the same one Go's `crypto/tls`
//! speaks — which is what mihomo's uTLS and the REALITY server are built on:
//!
//! * client share: ML-KEM-768 encapsulation key (1184) ‖ X25519 public key (32)
//! * server share: ML-KEM-768 ciphertext (1088) ‖ X25519 public key (32)
//! * shared secret: ML-KEM shared secret (32) ‖ X25519 shared secret (32)
//!
//! rustls only ships this group with its aws-lc-rs provider. This build uses
//! ring so the static musl targets need no C toolchain, hence the group is
//! assembled here from the pure-Rust `ml-kem` and `x25519-dalek` crates.

use ml_kem::{Decapsulate, DecapsulationKey768, KeyExport, Seed};
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::crypto::{ActiveKeyExchange, SharedSecret};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use x25519_dalek::{PublicKey, StaticSecret};

const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const X25519_KEY_LEN: usize = 32;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// One client key share: an ML-KEM-768 decapsulation key plus an X25519 secret.
///
/// `Clone` because REALITY has rustls build the same ClientHello twice (see
/// `transport/reality.rs`).
#[derive(Clone)]
pub struct HybridKeyShare {
    mlkem: DecapsulationKey768,
    x25519: StaticSecret,
    /// The encoded client share.
    public: Vec<u8>,
}

impl HybridKeyShare {
    pub fn generate() -> Self {
        let mut seed = [0u8; 64];
        OsRng.fill_bytes(&mut seed);
        let mlkem = DecapsulationKey768::from_seed(Seed::from(seed));
        let x25519 = StaticSecret::random_from_rng(OsRng);

        let mut public = Vec::with_capacity(MLKEM768_ENCAPSULATION_KEY_LEN + X25519_KEY_LEN);
        public.extend_from_slice(&mlkem.encapsulation_key().to_bytes());
        public.extend_from_slice(PublicKey::from(&x25519).as_bytes());

        Self {
            mlkem,
            x25519,
            public,
        }
    }

    /// X25519 between this share's secret and `peer_public`.
    ///
    /// Besides completing the TLS exchange, REALITY runs this against the
    /// server's static key to derive its auth key.
    pub fn x25519(&self, peer_public: &[u8]) -> Result<x25519_dalek::SharedSecret, Error> {
        let peer_public: [u8; X25519_KEY_LEN] =
            peer_public.try_into().map_err(|_| INVALID_KEY_SHARE)?;
        let shared = self.x25519.diffie_hellman(&PublicKey::from(peer_public));
        // mihomo compat: Go's `ecdh` rejects a low-order peer point (all-zero
        // output), as does the ring X25519 group this stands in for.
        if !shared.was_contributory() {
            return Err(INVALID_KEY_SHARE);
        }
        Ok(shared)
    }
}

impl ActiveKeyExchange for HybridKeyShare {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ciphertext, x25519_public) = peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);
        let ciphertext = ciphertext.try_into().map_err(|_| INVALID_KEY_SHARE)?;

        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&self.mlkem.decapsulate(ciphertext));
        secret.extend_from_slice(self.x25519(x25519_public)?.as_bytes());
        Ok(SharedSecret::from(secret))
    }

    /// The X25519 half doubles as a plain X25519 share, which rustls sends
    /// right after the hybrid one — the layout REALITY servers look for.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((
            NamedGroup::X25519,
            &self.public[MLKEM768_ENCAPSULATION_KEY_LEN..],
        ))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(
            self.x25519(peer_pub_key)?.as_bytes().as_slice(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::EncapsulationKey768;

    /// What a TLS server does with a client share: encapsulate to the ML-KEM
    /// key and run X25519 against the trailing public key. Returns the server
    /// share and the secret the server ends up with.
    fn server_side(client_share: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (encapsulation_key, client_x25519) =
            client_share.split_at(MLKEM768_ENCAPSULATION_KEY_LEN);
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
    fn client_share_is_mlkem_key_then_x25519_key() {
        let share = HybridKeyShare::generate();
        assert_eq!(share.group(), NamedGroup::X25519MLKEM768);
        assert_eq!(share.pub_key().len(), 1184 + 32);

        let (group, x25519_public) = share.hybrid_component().unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(x25519_public, &share.pub_key()[1184..]);
    }

    #[test]
    fn completes_against_a_server_share() {
        let share = HybridKeyShare::generate();
        let (server_share, server_secret) = server_side(share.pub_key());
        assert_eq!(server_share.len(), 1088 + 32);

        let secret = Box::new(share).complete(&server_share).unwrap();
        assert_eq!(secret.secret_bytes(), server_secret);
    }

    #[test]
    fn x25519_half_completes_alone_when_the_server_picks_x25519() {
        let share = HybridKeyShare::generate();
        let (_, x25519_public) = share.hybrid_component().unwrap();
        let client_public: [u8; 32] = x25519_public.try_into().unwrap();

        let server = StaticSecret::from([9u8; 32]);
        let expected = server.diffie_hellman(&PublicKey::from(client_public));

        let secret = Box::new(share)
            .complete_hybrid_component(PublicKey::from(&server).as_bytes())
            .unwrap();
        assert_eq!(secret.secret_bytes(), expected.as_bytes());
    }

    #[test]
    fn rejects_malformed_server_shares() {
        let share = HybridKeyShare::generate();
        let (server_share, _) = server_side(share.pub_key());

        // Truncated, and a bare X25519 key where the hybrid share belongs.
        assert!(Box::new(share.clone())
            .complete(&server_share[..server_share.len() - 1])
            .is_err());
        assert!(Box::new(share.clone()).complete(&[9u8; 32]).is_err());
        // A low-order X25519 point must not yield an all-zero secret.
        assert!(share.x25519(&[0u8; 32]).is_err());
        assert!(Box::new(share)
            .complete_hybrid_component(&[0u8; 32])
            .is_err());
    }
}
