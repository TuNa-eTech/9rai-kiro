//! Import a Kiro account from a shared folder of SSO cache files.
//!
//! The folder must contain:
//! - `kiro-auth-token.json` — `{ accessToken, refreshToken, region, authMethod, … }`
//! - a client-registration JSON — `{ clientId, clientSecret }`, named `<hash>.json` by Kiro but
//!   matched here by content, not by filename.
//!
//! Import is **offline** by design: it parses the two files and reconstructs the credential
//! without making any network call. Refreshing the token / resolving `profileArn` and `email`
//! is the caller's job (the switcher and MITM paths want different things there).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{client_id_hash, KiroCredential};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("folder not found: {0}")]
    MissingFolder(PathBuf),
    #[error("kiro-auth-token.json not found in {0}")]
    MissingTokenFile(PathBuf),
    #[error("invalid JSON in kiro-auth-token.json: {0}")]
    BadTokenJson(serde_json::Error),
    #[error("token file is missing accessToken")]
    MissingAccessToken,
    #[error("token file is missing refreshToken")]
    MissingRefreshToken,
    #[error("client registration not found — need a JSON with clientId + clientSecret")]
    MissingClientRegistration,
    #[error("client registration has no valid clientSecret (start URL unrecoverable)")]
    MissingStartUrl,
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// The token-file fields we read; everything else Kiro writes is ignored.
#[derive(Deserialize)]
struct TokenFile {
    #[serde(default)]
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(default)]
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    #[serde(rename = "authMethod")]
    auth_method: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(default)]
    #[serde(rename = "profileArn")]
    profile_arn: String,
    /// Kiro's own registration filename (`<hash>.json`). Newer Kiro builds no longer derive
    /// this as `SHA1({"startUrl":...})` (custom start URLs, `SHA1(clientId)` for the CLI,
    /// opaque ids for the IDE), so it must be preserved verbatim — recomputing it breaks
    /// `find_active_label` matching and writes cache files Kiro never reads.
    #[serde(default)]
    #[serde(rename = "clientIdHash")]
    client_id_hash: String,
}

/// A client registration file. Only the two fields we need to refresh a token and compute the
/// hash are read; `scopes`/`expiresAt` are preserved on export, not consumed on import.
#[derive(Deserialize)]
struct ClientRegistration {
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "clientSecret")]
    client_secret: String,
}

/// Parse a folder of Kiro SSO cache files into a [`KiroCredential`].
pub fn import_from_folder(folder: &Path) -> Result<KiroCredential, ImportError> {
    if !folder.is_dir() {
        return Err(ImportError::MissingFolder(folder.to_path_buf()));
    }

    let token_file = folder.join("kiro-auth-token.json");
    let raw = std::fs::read_to_string(&token_file).map_err(|e| ImportError::Io {
        path: token_file.clone(),
        source: e,
    })?;
    let token: TokenFile = serde_json::from_str(&raw).map_err(ImportError::BadTokenJson)?;

    if token.access_token.trim().is_empty() {
        return Err(ImportError::MissingAccessToken);
    }
    if token.refresh_token.trim().is_empty() {
        return Err(ImportError::MissingRefreshToken);
    }

    // Prefer the registration Kiro itself paired with this token (`<clientIdHash>.json`):
    // the live `~/.aws/sso/cache` holds several accounts at once, so a blind content scan can
    // pick another account's registration. Fall back to the content scan for shared folders
    // whose registration was renamed in transit.
    let (client_id, client_secret) = find_client_registration(folder, &token.client_id_hash)?;
    let start_url = extract_start_url(&client_secret).ok_or(ImportError::MissingStartUrl)?;

    let region = if token.region.trim().is_empty() {
        "us-east-1".to_string()
    } else {
        token.region
    };

    // Preserve Kiro's own hash when the token carries one; only derive it for old shared
    // folders that predate the field. Recomputing unconditionally breaks active-account
    // matching (and later cache writes) for every account whose hash is not
    // `SHA1({"startUrl":...})` — which is all of them on current Kiro builds.
    let client_id_hash = if token.client_id_hash.trim().is_empty() {
        client_id_hash(&start_url)
    } else {
        token.client_id_hash.trim().to_string()
    };

    Ok(KiroCredential {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at: token.expires_at,
        region,
        auth_method: token.auth_method,
        provider: token.provider,
        client_id,
        client_secret: client_secret.clone(),
        client_id_hash,
        profile_arn: token.profile_arn,
        start_url,
    })
}

/// Scan the folder for the client registration. When the token names its hash, that exact
/// file wins; otherwise (or when it is missing/unparseable) fall back to the first JSON
/// carrying `clientId` + `clientSecret`, skipping every `kiro-auth-token*.json` token file.
fn find_client_registration(
    folder: &Path,
    client_id_hash: &str,
) -> Result<(String, String), ImportError> {
    // Fast path: the file Kiro paired with this token.
    let hash = client_id_hash.trim();
    if !hash.is_empty() && !hash.contains('/') && !hash.contains('\\') && !hash.contains("..") {
        let named = folder.join(format!("{hash}.json"));
        if named.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&named) {
                if let Ok(reg) = serde_json::from_str::<ClientRegistration>(&raw) {
                    if !reg.client_id.trim().is_empty() && !reg.client_secret.trim().is_empty() {
                        return Ok((reg.client_id, reg.client_secret));
                    }
                }
            }
        }
    }

    let entries = std::fs::read_dir(folder).map_err(|e| ImportError::Io {
        path: folder.to_path_buf(),
        source: e,
    })?;

    for entry in entries {
        let path = match entry {
            Ok(e) => e.path(),
            Err(_) => continue,
        };
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("kiro-auth-token"))
        {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(reg) = serde_json::from_str::<ClientRegistration>(&raw) {
            if !reg.client_id.trim().is_empty() && !reg.client_secret.trim().is_empty() {
                return Ok((reg.client_id, reg.client_secret));
            }
        }
    }

    Err(ImportError::MissingClientRegistration)
}

/// Recover the SSO start URL from a client secret JWT: the second segment is JSON whose
/// `serialized` field (itself JSON) carries `initiateLoginUri`. Mirrors the reference tool.
fn extract_start_url(client_secret: &str) -> Option<String> {
    let parts: Vec<&str> = client_secret.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload_b64 = parts[1];
    let padded = payload_b64.as_bytes();
    let mut owned = Vec::with_capacity(padded.len() + 4);
    owned.extend_from_slice(padded);
    while owned.len() % 4 != 0 {
        owned.push(b'=');
    }
    use base64::Engine;
    // `URL_SAFE` (not `NO_PAD`): the padding above is required input for it, and rejected
    // by `NO_PAD` — which is why every current (long, `len % 4 == 3`) client secret failed
    // to decode while the old short ones (`len % 4 == 0`, no padding added) worked.
    let engine = base64::engine::general_purpose::URL_SAFE;
    let decoded = engine.decode(&owned).ok()?;
    let outer: BTreeMap<String, serde_json::Value> = serde_json::from_slice(&decoded).ok()?;
    let serialized = outer.get("serialized")?.as_str()?;
    let inner: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(serialized).ok()?;
    inner
        .get("initiateLoginUri")?
        .as_str()
        .map(|s| s.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("9rai-account-import-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The exact JWT shape the reference tool emits for the default start URL.
    const DEFAULT_START_JWT: &str = "eyJhbGciOiJub25lIn0.eyJzZXJpYWxpemVkIjogIntcImluaXRpYXRlTG9naW5VcmlcIjpcImh0dHBzOi8vdmlldy5hd3NhcHBzLmNvbS9zdGFydFwifSJ9.sig";

    fn write_minimal_folder(dir: &Path) {
        fs::write(
            dir.join("kiro-auth-token.json"),
            r#"{"accessToken":"at-1","refreshToken":"rt-1","region":"us-east-1","authMethod":"idc","provider":"Enterprise"}"#,
        )
        .unwrap();
        fs::write(
            dir.join("e909a0580879b06ece1202964fbe9dda95ea4ce3.json"),
            format!(
                r#"{{"clientId":"cid","clientSecret":"{DEFAULT_START_JWT}","scopes":["codewhisperer:completions"]}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn imports_a_minimal_folder() {
        let dir = tmpdir("minimal");
        write_minimal_folder(&dir);

        let cred = import_from_folder(&dir).unwrap();
        assert_eq!(cred.access_token, "at-1");
        assert_eq!(cred.refresh_token, "rt-1");
        assert_eq!(cred.auth_method, "idc");
        assert_eq!(cred.start_url, "https://view.awsapps.com/start");
        assert_eq!(cred.client_id_hash, "e909a0580879b06ece1202964fbe9dda95ea4ce3");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn registration_is_found_by_content_not_filename() {
        let dir = tmpdir("renamed");
        fs::write(
            dir.join("kiro-auth-token.json"),
            r#"{"accessToken":"at","refreshToken":"rt"}"#,
        )
        .unwrap();
        // A renamed registration file must still be picked up.
        fs::write(
            dir.join("whatever.json"),
            format!(r#"{{"clientId":"cid","clientSecret":"{DEFAULT_START_JWT}"}}"#),
        )
        .unwrap();

        let cred = import_from_folder(&dir).unwrap();
        assert_eq!(cred.client_id_hash, "e909a0580879b06ece1202964fbe9dda95ea4ce3");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_registration_is_an_error() {
        let dir = tmpdir("no-reg");
        fs::write(
            dir.join("kiro-auth-token.json"),
            r#"{"accessToken":"at","refreshToken":"rt"}"#,
        )
        .unwrap();

        assert!(matches!(
            import_from_folder(&dir),
            Err(ImportError::MissingClientRegistration)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_refresh_token_is_an_error() {
        let dir = tmpdir("no-refresh");
        fs::write(
            dir.join("kiro-auth-token.json"),
            r#"{"accessToken":"at"}"#,
        )
        .unwrap();

        assert!(matches!(
            import_from_folder(&dir),
            Err(ImportError::MissingRefreshToken)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    /// Regression: current Kiro client secrets are ~5 KB JWTs whose payload base64 length is
    /// `3 mod 4`, so one `=` of padding is added before decoding. The old `URL_SAFE_NO_PAD`
    /// engine rejected that padding and every such import failed with `MissingStartUrl`,
    /// which is why the app could never load the account Kiro is actually using.
    #[test]
    fn decodes_a_long_client_secret_needing_base64_padding() {
        use base64::Engine;
        // Build a payload whose unpadded base64url length is 3 mod 4, like the real secret.
        let mut pad_len = 0;
        let payload_b64;
        loop {
            let inner = format!(
                "{{\"initiateLoginUri\":\"https://d-90660cc21e.awsapps.com/start/\",\"pad\":\"{}\"}}",
                "x".repeat(pad_len)
            );
            let outer = serde_json::json!({ "serialized": inner }).to_string();
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(outer.as_bytes());
            if b64.len() % 4 == 3 {
                payload_b64 = b64;
                break;
            }
            pad_len += 1;
            assert!(pad_len < 16, "should find a 3-mod-4 payload quickly");
        }
        let secret = format!("header.{payload_b64}.sig");
        assert_eq!(payload_b64.len() % 4, 3);
        assert_eq!(
            extract_start_url(&secret).as_deref(),
            Some("https://d-90660cc21e.awsapps.com/start")
        );
    }

    /// Regression: current Kiro hashes are opaque (custom start URLs, `SHA1(clientId)` for
    /// the CLI) — not `SHA1({"startUrl":...})`. The token's own `clientIdHash` must be
    /// preserved, and the `<hash>.json` file it names must win over a content scan when the
    /// folder holds several accounts (the live `~/.aws/sso/cache` always does).
    #[test]
    fn preserves_kiro_client_id_hash_and_prefers_the_hash_named_registration() {
        let dir = tmpdir("hash-named");
        fs::write(
            dir.join("kiro-auth-token.json"),
            r#"{"accessToken":"at","refreshToken":"rt","clientIdHash":"aee64dc2c64212757368d860468ea9a44161d7d5"}"#,
        )
        .unwrap();
        // Decoy: another account's registration that a blind content scan could pick first.
        fs::write(
            dir.join("d21df2ca836ca8b7a6834d0fb019db749e49d5c0.json"),
            format!(r#"{{"clientId":"decoy-id","clientSecret":"{DEFAULT_START_JWT}"}}"#),
        )
        .unwrap();
        // The registration Kiro paired with this token.
        fs::write(
            dir.join("aee64dc2c64212757368d860468ea9a44161d7d5.json"),
            format!(r#"{{"clientId":"live-id","clientSecret":"{DEFAULT_START_JWT}"}}"#),
        )
        .unwrap();

        let cred = import_from_folder(&dir).unwrap();
        assert_eq!(cred.client_id, "live-id");
        assert_eq!(
            cred.client_id_hash,
            "aee64dc2c64212757368d860468ea9a44161d7d5"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
