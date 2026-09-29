//! Kiro account pool: credentials and the symmetric folder import/export.
//!
//! The folder format is shared with the `kiro-account-switcher` reference so an account
//! "shared" from another machine round-trips unchanged:
//!
//! ```text
//! <folder>/
//! ├── kiro-auth-token.json    # { accessToken, refreshToken, clientIdHash, region, authMethod, expiresAt }
//! └── <clientIdHash>.json     # { clientId, clientSecret }
//! ```
//!
//! Two auth shapes exist and must never be conflated:
//! - [`CredentialKind::Sso`] — OAuth/IdC/social. Has a refresh token + client registration,
//!   so it round-trips through the folder format.
//! - [`CredentialKind::ApiKey`] — a long-lived `ksk_` bearer key. No refresh token, no client
//!   registration, so it cannot be exported as a folder (there is no `<hash>.json` to write).
//!
//! [`export_to_folder`] on an `ApiKey` credential is an error, not a silent no-op.

mod export;
mod import;
mod pool;
mod resolve;
mod store;

pub use export::export_to_folder;
pub use import::{import_from_folder, ImportError};
pub use pool::{
    find_active_label, now_iso, select_best_account, sso_cache_dir, switch_to_account, token_file,
    write_sso_cache,
};
pub use resolve::{KiroApi, RefreshResult, ResolvedAccount, UsageInfo};
pub use store::AccountStore;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

/// The credential payload behind an account. Which fields are meaningful depends on
/// [`CredentialKind`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroCredential {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default = "default_region")]
    pub region: String,
    /// Kiro's own `authMethod` token-file value (`"IdC"`, `"Social"`, `"api_key"`, …). Kept
    /// as a verbatim string: Kiro recomputes nothing here, and switch must write back exactly
    /// what it read or the IDE stops recognizing the token.
    #[serde(default)]
    pub auth_method: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// Filename of the client registration (`<hash>.json`), or empty for `ApiKey`.
    #[serde(default)]
    pub client_id_hash: String,
    #[serde(default)]
    pub profile_arn: String,
    #[serde(default)]
    pub start_url: String,
}

impl KiroCredential {
    /// Which shape this credential is. `ApiKey` iff the auth method names a headless key;
    /// everything else is an SSO-shaped credential that can round-trip through the folder.
    pub fn kind(&self) -> CredentialKind {
        let m = self.auth_method.to_ascii_lowercase();
        if m == "api_key" || m == "apikey" || m == "headless" {
            CredentialKind::ApiKey
        } else {
            CredentialKind::Sso
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// OAuth/IdC/social: refreshable, carries client registration, folder-exportable.
    Sso,
    /// Headless `ksk_` key: not refreshable, no client registration, not folder-exportable.
    ApiKey,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountStatus {
    #[default]
    Active,
    Exhausted,
    Suspended,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Suspended => "suspended",
        }
    }
}

/// One Kiro account in the pool: metadata plus its credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroAccount {
    pub id: String,
    pub label: String,
    pub email: String,
    #[serde(default)]
    pub status: AccountStatus,
    #[serde(default)]
    pub credit_total: f64,
    #[serde(default)]
    pub credit_used: f64,
    /// ISO-8601 credit reset time, for the "use it or lose it" urgency term in selection.
    #[serde(default)]
    pub cycle_reset_at: Option<String>,
    /// ISO-8601 time this account was last switched to, for the spread-load recency penalty.
    #[serde(default)]
    pub last_used_at: Option<String>,
    pub credential: KiroCredential,
}

impl KiroAccount {
    pub fn credit_available(&self) -> f64 {
        (self.credit_total - self.credit_used).max(0.0)
    }
}

fn default_region() -> String {
    "us-east-1".to_string()
}

/// Name an account: an explicit label wins, then the email local-part, then a short hash of the
/// client-id hash.
///
/// Lives here rather than in either caller so the GUI and `9rai account import-file` land the
/// same folder under the same label — two copies of this drifted once already (one trimmed the
/// label, the other did not), and a label is the key every lookup uses.
pub fn derive_label(label: Option<String>, email: &str, client_id_hash: &str) -> String {
    if let Some(label) = label {
        let label = label.trim();
        if !label.is_empty() {
            return label.to_string();
        }
    }
    let local = email.split('@').next().unwrap_or("").trim();
    if !local.is_empty() {
        return local.to_string();
    }
    let hint: String = client_id_hash.chars().take(8).collect();
    format!("kiro-{hint}")
}

/// SHA-1 of `{"startUrl":"<start_url>"}` (no trailing slash) — the name Kiro gives its client
/// registration file. Kiro recomputes this itself, so an import must derive it from the
/// resolved start URL rather than trusting the `clientIdHash` field in the token file.
pub fn client_id_hash(start_url: &str) -> String {
    let clean = start_url.trim_end_matches('/');
    let input = format!("{{\"startUrl\":\"{clean}\"}}");
    let digest = Sha1::digest(input.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_hash_matches_reference_implementation() {
        // Verified against the kiro-account-switcher `ks` tool for the default start URL.
        assert_eq!(
            client_id_hash("https://view.awsapps.com/start"),
            "e909a0580879b06ece1202964fbe9dda95ea4ce3"
        );
        // A trailing slash must not change the hash.
        assert_eq!(
            client_id_hash("https://view.awsapps.com/start/"),
            "e909a0580879b06ece1202964fbe9dda95ea4ce3"
        );
    }

    #[test]
    fn derived_labels_prefer_the_explicit_name_then_the_email_then_a_hash() {
        // An explicit label wins, trimmed — it is the key every lookup uses.
        assert_eq!(
            derive_label(Some(" mine ".into()), "a@b.com", "abcdef1234"),
            "mine"
        );
        // A blank label is the same as no label.
        assert_eq!(
            derive_label(Some("   ".into()), "alice@b.com", "abcdef1234"),
            "alice"
        );
        // Then the email local-part.
        assert_eq!(derive_label(None, "alice@b.com", "abcdef1234"), "alice");
        // A blank email must not produce a blank label; fall through to the hash.
        assert_eq!(
            derive_label(None, "   ", "abcdef1234567890"),
            "kiro-abcdef12"
        );
        assert_eq!(derive_label(None, "", "abcdef1234567890"), "kiro-abcdef12");
    }

    #[test]
    fn kind_detects_api_key_case_insensitively() {
        fn cred(m: &str) -> KiroCredential {
            KiroCredential {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: String::new(),
                region: "us-east-1".into(),
                auth_method: m.into(),
                provider: String::new(),
                client_id: String::new(),
                client_secret: String::new(),
                client_id_hash: String::new(),
                profile_arn: String::new(),
                start_url: String::new(),
            }
        }
        assert_eq!(cred("api_key").kind(), CredentialKind::ApiKey);
        assert_eq!(cred("API_KEY").kind(), CredentialKind::ApiKey);
        assert_eq!(cred("apikey").kind(), CredentialKind::ApiKey);
        assert_eq!(cred("IdC").kind(), CredentialKind::Sso);
        assert_eq!(cred("Social").kind(), CredentialKind::Sso);
        assert_eq!(cred("").kind(), CredentialKind::Sso);
    }
}
