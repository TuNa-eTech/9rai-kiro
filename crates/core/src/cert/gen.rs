//! X.509 generation via rcgen.
//!
//! Keys are ECDSA P-256, not the reference's RSA-2048. The parity contract is the extension
//! set, not the key algorithm, and P-256 matters operationally: a leaf is minted inside the
//! synchronous TLS SNI callback, where P-256 keygen (~tens of µs) is acceptable but RSA-2048 in
//! pure Rust (hundreds of ms) is not. Both macOS and Windows trust P-256 roots.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

use crate::{Error, Result};

pub const ROOT_CN: &str = "9rai MITM Root CA";
const ROOT_ORG: &str = "9rai";
const ROOT_COUNTRY: &str = "US";

fn map_err(e: rcgen::Error) -> Error {
    Error::Cert(e.to_string())
}

/// A freshly generated root CA: the self-signed cert plus its key, both as PEM.
pub struct GeneratedRoot {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_root() -> Result<GeneratedRoot> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(map_err)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ROOT_CN);
    dn.push(DnType::OrganizationName, ROOT_ORG);
    dn.push(DnType::CountryName, ROOT_COUNTRY);
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1); // tolerate minor clock skew
    params.not_after = now + Duration::days(3650);
    params.serial_number = Some(SerialNumber::from(1u64));

    let cert = params.self_signed(&key).map_err(map_err)?;
    Ok(GeneratedRoot {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Rebuild the signing issuer from stored root PEM.
pub fn load_issuer(cert_pem: &str, key_pem: &str) -> Result<Issuer<'static, KeyPair>> {
    let key = KeyPair::from_pem(key_pem).map_err(map_err)?;
    Issuer::from_ca_cert_pem(cert_pem, key).map_err(map_err)
}

/// A minted leaf: cert plus its own key, both PEM. Valid for exactly one domain.
pub struct GeneratedLeaf {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_leaf(domain: &str, issuer: &Issuer<'_, KeyPair>) -> Result<GeneratedLeaf> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(map_err)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    // Exactly the host and its direct wildcard — never widened, so HTTP/2 coalescing cannot
    // route one hijacked host's traffic onto another's connection.
    params.subject_alt_names = vec![
        SanType::DnsName(domain.try_into().map_err(map_err)?),
        SanType::DnsName(format!("*.{domain}").try_into().map_err(map_err)?),
    ];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(365);

    let cert: Certificate = params.signed_by(&key, issuer).map_err(map_err)?;
    Ok(GeneratedLeaf {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Uppercase, colon-free SHA-1 of the certificate DER — the fingerprint form both
/// `security` and `certutil` accept for lookup and deletion.
pub fn sha1_fingerprint(cert_der: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(cert_der);
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_a_ca_valid_for_a_decade() {
        let root = generate_root().unwrap();
        assert!(root.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(root.key_pem.contains("PRIVATE KEY"));

        let (_, parsed) = x509_parser::pem::parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
        let cert = parsed.parse_x509().unwrap();
        assert!(cert.tbs_certificate.is_ca());
        let days = (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp())
            / 86400;
        assert!(days >= 3649, "expected ~10 years, got {days} days");
    }

    #[test]
    fn leaf_carries_both_the_host_and_its_wildcard_san() {
        let root = generate_root().unwrap();
        let issuer = load_issuer(&root.cert_pem, &root.key_pem).unwrap();
        let leaf = generate_leaf("runtime.us-east-1.kiro.dev", &issuer).unwrap();

        let (_, parsed) = x509_parser::pem::parse_x509_pem(leaf.cert_pem.as_bytes()).unwrap();
        let cert = parsed.parse_x509().unwrap();
        assert!(!cert.tbs_certificate.is_ca());

        let sans: Vec<String> = cert
            .tbs_certificate
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .map(|g| g.to_string())
            .collect();
        assert!(sans
            .iter()
            .any(|s| s.contains("runtime.us-east-1.kiro.dev")));
        assert!(sans
            .iter()
            .any(|s| s.contains("*.runtime.us-east-1.kiro.dev")));
    }

    #[test]
    fn fingerprint_is_the_uppercase_hex_sha1_digest() {
        // SHA-1 of "abc" is a published test vector.
        let fp = sha1_fingerprint(b"abc");
        assert_eq!(fp, "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(fp.len(), 40);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()));
    }
}
