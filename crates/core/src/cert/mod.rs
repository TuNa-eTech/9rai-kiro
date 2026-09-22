//! Root CA lifecycle and per-domain leaf minting.
//!
//! The store owns the root PEM, hands out a rustls [`CertifiedKey`] for any SNI name, and caches
//! each leaf for the process lifetime (only three hosts are ever hijacked). Leaves are signed
//! lazily; the cache hit is the hot path, so rebuilding the issuer on the rare miss is fine.

pub mod gen;
pub mod trust;

use std::sync::Arc;

use dashmap::DashMap;
use rustls::sign::CertifiedKey;
use rustls_pki_types::CertificateDer;

use crate::paths;
use crate::{Error, Result};

/// Regenerate the root once it is within this window of expiring.
const ROTATE_BEFORE_EXPIRY: time::Duration = time::Duration::days(30);

pub struct CertStore {
    root_cert_pem: String,
    root_key_pem: String,
    root_der: Vec<u8>,
    fingerprint: String,
    cache: DashMap<String, Arc<CertifiedKey>>,
}

impl CertStore {
    /// Load the root from disk, generating and persisting a fresh one if missing or near expiry.
    pub fn load_or_create() -> Result<Self> {
        let cert_path = paths::root_ca_cert()?;
        let key_path = paths::root_ca_key()?;

        let existing = match (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(c), Ok(k)) if !needs_rotation(&c) => Some((c, k)),
            _ => None,
        };

        let (root_cert_pem, root_key_pem) = match existing {
            Some(pair) => pair,
            None => {
                let root = gen::generate_root()?;
                paths::ensure_dir(&paths::cert_dir()?)?;
                paths::write_private(&key_path, root.key_pem.as_bytes())?;
                std::fs::write(&cert_path, &root.cert_pem).map_err(|e| Error::io(&cert_path, e))?;
                paths::chown_to_real_user(&cert_path);
                (root.cert_pem, root.key_pem)
            }
        };

        let root_der = pem_to_der(&root_cert_pem)?;
        let fingerprint = gen::sha1_fingerprint(&root_der);

        Ok(Self {
            root_cert_pem,
            root_key_pem,
            root_der,
            fingerprint,
            cache: DashMap::new(),
        })
    }

    /// An in-memory root that is never written to disk. Used by tests and reproducible
    /// benchmarks that must not touch the user's real trust material.
    pub fn ephemeral() -> Result<Self> {
        let root = gen::generate_root()?;
        let root_der = pem_to_der(&root.cert_pem)?;
        Ok(Self {
            fingerprint: gen::sha1_fingerprint(&root_der),
            root_der,
            root_cert_pem: root.cert_pem,
            root_key_pem: root.key_pem,
            cache: DashMap::new(),
        })
    }

    pub fn root_cert_pem(&self) -> &str {
        &self.root_cert_pem
    }

    pub fn root_cert_path(&self) -> Result<std::path::PathBuf> {
        paths::root_ca_cert()
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// A rustls signing key + chain for `domain`, minting and caching on first use.
    pub fn certified_key(&self, domain: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.cache.get(domain) {
            return Ok(hit.clone());
        }

        let issuer = gen::load_issuer(&self.root_cert_pem, &self.root_key_pem)?;
        let leaf = gen::generate_leaf(domain, &issuer)?;

        let leaf_der = pem_to_der(&leaf.cert_pem)?;
        // Serve leaf + root so a client that only pins the root still builds a chain.
        let chain = vec![
            CertificateDer::from(leaf_der),
            CertificateDer::from(self.root_der.clone()),
        ];

        let key_der = rustls_pemfile::private_key(&mut leaf.key_pem.as_bytes())
            .map_err(|e| Error::Cert(format!("leaf key parse: {e}")))?
            .ok_or_else(|| Error::Cert("leaf key PEM contained no private key".into()))?;
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key_der)
            .map_err(|e| Error::Cert(format!("leaf signing key: {e}")))?;

        let certified = Arc::new(CertifiedKey::new(chain, signing_key));
        self.cache.insert(domain.to_string(), certified.clone());
        Ok(certified)
    }
}

fn needs_rotation(cert_pem: &str) -> bool {
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()) else {
        return true;
    };
    let Ok(cert) = pem.parse_x509() else {
        return true;
    };
    let not_after = cert.validity().not_after.timestamp();
    let threshold = (time::OffsetDateTime::now_utc() + ROTATE_BEFORE_EXPIRY).unix_timestamp();
    not_after < threshold
}

fn pem_to_der(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| Error::Cert(format!("root PEM parse: {e}")))?;
    Ok(pem.contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freshly_generated_root_is_not_due_for_rotation() {
        let root = gen::generate_root().unwrap();
        assert!(!needs_rotation(&root.cert_pem));
    }

    #[test]
    fn garbage_pem_is_treated_as_needing_rotation() {
        assert!(needs_rotation("not a certificate"));
    }

    #[test]
    fn minting_produces_a_usable_chain_and_caches_it() {
        let root = gen::generate_root().unwrap();
        let root_der = pem_to_der(&root.cert_pem).unwrap();
        let store = CertStore {
            fingerprint: gen::sha1_fingerprint(&root_der),
            root_der,
            root_cert_pem: root.cert_pem,
            root_key_pem: root.key_pem,
            cache: DashMap::new(),
        };

        let first = store.certified_key("runtime.us-east-1.kiro.dev").unwrap();
        assert_eq!(first.cert.len(), 2, "chain must be leaf + root");
        let second = store.certified_key("runtime.us-east-1.kiro.dev").unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "second call must hit the cache"
        );
    }
}
