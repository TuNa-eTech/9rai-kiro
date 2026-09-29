//! Export a Kiro account to a shareable folder, the inverse of [`crate::account::import_from_folder`].
//!
//! The emitted folder has exactly the two-file shape the reference tool reads back, so
//! `export_to_folder(import_from_folder(dir))` reproduces the same content (round-trip).

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{CredentialKind, KiroCredential};

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("cannot export an api_key credential as a folder (no client registration exists)")]
    ApiKeyNotExportable,
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Serialize)]
struct TokenFile<'a> {
    #[serde(rename = "accessToken")]
    access_token: &'a str,
    #[serde(rename = "refreshToken")]
    refresh_token: &'a str,
    #[serde(rename = "expiresAt")]
    expires_at: &'a str,
    #[serde(rename = "clientIdHash")]
    client_id_hash: &'a str,
    #[serde(rename = "authMethod")]
    auth_method: &'a str,
    provider: &'a str,
    region: &'a str,
    #[serde(rename = "profileArn")]
    profile_arn: &'a str,
}

#[derive(Serialize)]
struct ClientRegistration<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
    #[serde(rename = "expiresAt")]
    expires_at: &'a str,
    scopes: &'static [&'static str],
}

/// Scopes Kiro writes into its live client registration. Kept identical to the reference so a
/// switched account keeps refreshing inside Kiro IDE.
const SCOPES: &[&str] = &[
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
    "codewhisperer:transformations",
    "codewhisperer:taskassist",
];

/// Serialize a credential to a folder of two files. Refuses `ApiKey` credentials — they have
/// no client registration, so a folder export would be silently unimportable on the other end.
pub fn export_to_folder(cred: &KiroCredential, out_dir: &Path) -> Result<(), ExportError> {
    if cred.kind() == CredentialKind::ApiKey {
        return Err(ExportError::ApiKeyNotExportable);
    }

    std::fs::create_dir_all(out_dir).map_err(|e| ExportError::Io {
        path: out_dir.to_path_buf(),
        source: e,
    })?;

    // Preserve Kiro's own hash when the credential carries one; only derive it for old
    // credentials that predate the field. Deriving unconditionally renames the registration
    // and retokens the hash, so Kiro (and `find_active_label`) no longer recognises the pair.
    let hash = if cred.client_id_hash.trim().is_empty() {
        super::client_id_hash(&cred.start_url)
    } else {
        cred.client_id_hash.trim().to_string()
    };
    let reg_path = out_dir.join(format!("{hash}.json"));
    let reg = ClientRegistration {
        client_id: &cred.client_id,
        client_secret: &cred.client_secret,
        expires_at: "",
        scopes: SCOPES,
    };
    let reg_json = serde_json::to_vec_pretty(&reg).map_err(ExportError::from_json)?;
    std::fs::write(&reg_path, reg_json).map_err(|e| ExportError::Io {
        path: reg_path,
        source: e,
    })?;

    let token = TokenFile {
        access_token: &cred.access_token,
        refresh_token: &cred.refresh_token,
        expires_at: &cred.expires_at,
        client_id_hash: &hash,
        auth_method: &cred.auth_method,
        provider: &cred.provider,
        region: &cred.region,
        profile_arn: &cred.profile_arn,
    };
    let token_path = out_dir.join("kiro-auth-token.json");
    let token_json = serde_json::to_vec_pretty(&token).map_err(ExportError::from_json)?;
    std::fs::write(&token_path, token_json).map_err(|e| ExportError::Io {
        path: token_path,
        source: e,
    })?;

    Ok(())
}

impl ExportError {
    fn from_json(e: serde_json::Error) -> Self {
        // Serialization of borrowed strings cannot fail; still keep the error path explicit
        // rather than panicking on an impossible-but-typed path.
        unreachable!("serializing borrowed string fields: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::import_from_folder;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("9rai-account-export-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sso_credential() -> KiroCredential {
        KiroCredential {
            access_token: "at-1".into(),
            refresh_token: "rt-1".into(),
            expires_at: "2026-06-01T00:00:00Z".into(),
            region: "us-east-1".into(),
            auth_method: "IdC".into(),
            provider: "Enterprise".into(),
            client_id: "cid".into(),
            client_secret: "eyJhbGciOiJub25lIn0.eyJzZXJpYWxpemVkIjogIntcImluaXRpYXRlTG9naW5VcmlcIjpcImh0dHBzOi8vdmlldy5hd3NhcHBzLmNvbS9zdGFydFwifSJ9.sig".into(),
            client_id_hash: "".into(), // must be derived, not trusted
            profile_arn: "arn:aws:codewhisperer:us-east-1:111122223333:profile/test".into(),
            start_url: "https://view.awsapps.com/start".into(),
        }
    }

    #[test]
    fn round_trip_import_export_is_identity() {
        let dir = tmpdir("roundtrip");
        let cred = sso_credential();

        export_to_folder(&cred, &dir).unwrap();

        // Two files, exactly.
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "kiro-auth-token.json"));
        assert!(names
            .iter()
            .any(|n| n == "e909a0580879b06ece1202964fbe9dda95ea4ce3.json"));
        assert_eq!(names.len(), 2);

        let back = import_from_folder(&dir).unwrap();
        assert_eq!(back.access_token, cred.access_token);
        assert_eq!(back.refresh_token, cred.refresh_token);
        assert_eq!(back.client_id, cred.client_id);
        assert_eq!(back.client_secret, cred.client_secret);
        assert_eq!(back.profile_arn, cred.profile_arn);
        assert_eq!(back.start_url, cred.start_url);
        assert_eq!(
            back.client_id_hash,
            "e909a0580879b06ece1202964fbe9dda95ea4ce3"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn api_key_credential_is_not_exportable() {
        let dir = tmpdir("apikey");
        let cred = KiroCredential {
            access_token: "ksk_123".into(),
            refresh_token: "".into(),
            expires_at: "".into(),
            region: "us-east-1".into(),
            auth_method: "api_key".into(),
            provider: "API Key".into(),
            client_id: "".into(),
            client_secret: "".into(),
            client_id_hash: "".into(),
            profile_arn: "".into(),
            start_url: "".into(),
        };

        assert!(matches!(
            export_to_folder(&cred, &dir),
            Err(ExportError::ApiKeyNotExportable)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn preserves_kiro_opaque_hash_instead_of_rederiving_it() {
        let dir = tmpdir("opaque-hash");
        let cred = KiroCredential {
            access_token: "at-1".into(),
            refresh_token: "rt-1".into(),
            expires_at: "2026-06-01T00:00:00Z".into(),
            region: "us-east-1".into(),
            auth_method: "IdC".into(),
            provider: "Enterprise".into(),
            client_id: "live-id".into(),
            client_secret: "eyJhbGciOiJub25lIn0.eyJzZXJpYWxpemVkIjogIntcImluaXRpYXRlTG9naW5VcmlcIjpcImh0dHBzOi8vdmlldy5hd3NhcHBzLmNvbS9zdGFydFwifSJ9.sig".into(),
            // Kiro's real, opaque hash — must survive the round trip, not be rederived.
            client_id_hash: "aee64dc2c64212757368d860468ea9a44161d7d5".into(),
            profile_arn: "".into(),
            start_url: "https://view.awsapps.com/start".into(),
        };

        export_to_folder(&cred, &dir).unwrap();
        assert!(dir
            .join("aee64dc2c64212757368d860468ea9a44161d7d5.json")
            .is_file());

        let back = import_from_folder(&dir).unwrap();
        assert_eq!(
            back.client_id_hash,
            "aee64dc2c64212757368d860468ea9a44161d7d5"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
