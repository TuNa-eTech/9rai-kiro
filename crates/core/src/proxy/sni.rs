//! Serves a per-SNI leaf certificate during the TLS handshake.
//!
//! `resolve` is a synchronous trait method called on the tokio worker thread. That is only
//! acceptable because leaves are ECDSA P-256 (tens of µs to sign) and, after the first hit,
//! served straight from [`CertStore`]'s cache — the whole reason the port does not use RSA.

use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::cert::CertStore;
use crate::config::Tool;

#[derive(Debug)]
pub struct SniResolver {
    store: Arc<CertStore>,
}

impl SniResolver {
    pub fn new(store: Arc<CertStore>) -> Self {
        Self { store }
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // A client that sends no SNI cannot be one of the hosts we hijack, so drop it.
        let name = client_hello.server_name()?;
        // Only mint for hosts we actually hijack. Minting for arbitrary SNI would let any
        // local process grow the cache unboundedly and fingerprint the proxy.
        if !Tool::Kiro.hosts().contains(&name) {
            tracing::info!(sni = name, "SNI outside the hijack set; refusing handshake");
            return None;
        }
        match self.store.certified_key(name) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::warn!(domain = name, error = %e, "failed to mint leaf certificate");
                None
            }
        }
    }
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}
