//! Account pool orchestration: pick the best account, switch Kiro to it, mark exhausted.
//!
//! This is the "switcher" half of the account feature — the part that actually moves Kiro IDE
//! onto a different account by rewriting its live SSO cache (`~/.aws/sso/cache`). It never
//! touches the MITM pipeline; it operates on the same [`AccountStore`] the import/export pair
//! fills.
//!
//! Switch is deliberately ordered the same way as the reference (`pool_manager.py`):
//! refresh first (a stale access token makes the IDE show "Invalid token"), then recompute the
//! client-id hash from the start URL, then atomically write the client registration and the
//! token file.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{client_id_hash, KiroAccount, KiroCredential};
use crate::account::KiroApi;
use crate::{Error, Result};

/// `~/.aws/sso/cache` — where Kiro IDE reads its live credential from.
pub fn sso_cache_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aws")
        .join("sso")
        .join("cache")
}

/// The token file Kiro IDE watches for a credential change.
pub fn token_file() -> PathBuf {
    sso_cache_dir().join("kiro-auth-token.json")
}

/// The label of the account Kiro IDE is currently using, if we can tell.
///
/// Kiro records the account it holds in its live SSO cache; matching that file's
/// `clientIdHash` against the pool is what makes "which one is live right now?" answerable
/// without shelling out to the IDE. `None` covers the three normal unknowns: Kiro has never
/// run, the cache is unreadable/not JSON, or it names an account this pool does not hold.
pub fn find_active_label(store: &super::store::AccountStore) -> Option<String> {
    let raw = std::fs::read_to_string(token_file()).ok()?;
    let token: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let hash = token.get("clientIdHash")?.as_str()?;
    if hash.is_empty() {
        return None;
    }
    store
        .accounts
        .iter()
        .find(|a| a.credential.client_id_hash.eq_ignore_ascii_case(hash))
        .map(|a| a.label.clone())
}

/// Choose the account with the most available credit, preferring accounts close to their reset
/// time (use it or lose it) and penalizing accounts used in the last hour (spread load).
/// Returns the index into `accounts`, or `None` when no active account has credit left.
pub fn select_best_account(accounts: &[KiroAccount]) -> Option<usize> {
    let mut best: Option<(usize, f64)> = None;
    for (i, acc) in accounts.iter().enumerate() {
        if acc.status != super::AccountStatus::Active {
            continue;
        }
        if acc.credit_available() <= 0.0 {
            continue;
        }
        let score = account_score(acc);
        if best.is_none_or(|(_, s)| score > s) {
            best = Some((i, score));
        }
    }
    best.map(|(i, _)| i)
}

/// Score an account for selection. Higher is better; mirrors the reference's heuristic:
/// available credit + urgency (near reset) × 100 − recency (used in the last hour) × 10.
fn account_score(acc: &KiroAccount) -> f64 {
    let available = acc.credit_available();

    // Closer to reset = higher urgency ("use it or lose it"). `available / seconds_to_reset`.
    let urgency = acc
        .cycle_reset_at
        .as_deref()
        .and_then(parse_iso)
        .and_then(|reset| {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let seconds_to_reset = reset - now;
            (seconds_to_reset > 0).then_some(available / seconds_to_reset as f64)
        })
        .unwrap_or(0.0);

    // Recency penalty: an account switched to within the last hour is less attractive, so
    // load spreads instead of hammering one account until it trips multi-device detection.
    let recency = acc
        .last_used_at
        .as_deref()
        .and_then(parse_iso)
        .and_then(|used| {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let seconds_since = now - used;
            (0..3600).contains(&seconds_since)
                .then_some(1.0 - seconds_since as f64 / 3600.0)
        })
        .unwrap_or(0.0);

    available + urgency * 100.0 - recency * 10.0
}

/// Parse a Kiro `expiresAt` (ISO-8601) into unix seconds, if well-formed.
fn parse_iso(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// Switch Kiro IDE onto `account`: refresh its token, then rewrite the live SSO cache.
///
/// Returns the freshly-refreshed credential so the caller can persist it back to the store.
pub async fn switch_to_account(
    account: &KiroAccount,
    api: &KiroApi,
) -> Result<KiroCredential> {
    let mut cred = account.credential.clone();

    // 1. Refresh — always, so the written access token is fresh. A stale token surfaces as
    //    "Invalid token" in the IDE and no amount of cache rewriting fixes it.
    let refreshed = api
        .refresh_token(
            &cred.refresh_token,
            &cred.client_id,
            &cred.client_secret,
            &cred.region,
        )
        .await?;
    cred.access_token = refreshed.access_token;
    if !refreshed.refresh_token.is_empty() {
        cred.refresh_token = refreshed.refresh_token;
    }
    if refreshed.expires_in > 0 {
        cred.expires_at = iso_from_now(refreshed.expires_in);
    }
    if !refreshed.profile_arn.is_empty() {
        cred.profile_arn = refreshed.profile_arn;
    }

    // Keep Kiro's own registration hash: current builds no longer derive it as
    // `SHA1({"startUrl":...})`, so recomputing writes a registration filename + token hash
    // Kiro never reads (and breaks `find_active_label` matching). Only derive it when the
    // credential predates the field entirely.
    if cred.client_id_hash.trim().is_empty() && !cred.start_url.is_empty() {
        cred.client_id_hash = client_id_hash(&cred.start_url);
    }

    // 3. Write the live cache.
    write_sso_cache(&cred)?;

    Ok(cred)
}

/// Rewrite Kiro's live SSO cache: the `<hash>.json` client registration and the token file.
/// Both writes are atomic (temp + rename) so the IDE's file watcher never sees a half-written
/// file. The prior token is backed up to `.bak`.
pub fn write_sso_cache(cred: &KiroCredential) -> Result<()> {
    let dir = sso_cache_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(dir.clone(), e))?;

    // Client registration — named by the SHA-1 hash, exactly like Kiro's own files.
    let reg_path = dir.join(format!("{}.json", cred.client_id_hash));
    let reg_expiry = iso_from_now(90 * 24 * 60 * 60);
    let reg = ClientRegistration {
        client_id: &cred.client_id,
        client_secret: &cred.client_secret,
        expires_at: &reg_expiry,
        scopes: SCOPES,
    };
    atomic_write(&reg_path, serde_json::to_vec_pretty(&reg)?)?;

    // Token file. Cap the expiry at now+1h: Kiro refreshes off this field, and a far-future
    // value would make the IDE believe an expired token is still valid.
    let token_expiry = iso_from_now(60 * 60);
    let token = TokenFile {
        access_token: &cred.access_token,
        refresh_token: &cred.refresh_token,
        expires_at: &token_expiry,
        client_id_hash: &cred.client_id_hash,
        auth_method: &cred.auth_method,
        provider: &cred.provider,
        region: &cred.region,
        profile_arn: &cred.profile_arn,
    };
    let token_path = token_file();
    if token_path.exists() {
        let backup = token_path.with_extension("json.bak");
        std::fs::copy(&token_path, &backup).map_err(|e| Error::io(token_path.clone(), e))?;
    }
    atomic_write(&token_path, serde_json::to_vec_pretty(&token)?)?;

    Ok(())
}

/// Write `path` atomically: write to a sibling temp file, then rename over the target.
fn atomic_write(path: &Path, bytes: Vec<u8>) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| Error::io(tmp.clone(), e))?;
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path.to_path_buf(), e))?;
    Ok(())
}

/// ISO-8601 timestamp `seconds` from now, in the format Kiro writes (`…T…Z`).
fn iso_from_now(seconds: u64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds.max(1) as i64);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Current time as an ISO-8601 string, for stamping `last_used_at` on a successful switch.
pub fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

const SCOPES: &[&str] = &[
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
    "codewhisperer:transformations",
    "codewhisperer:taskassist",
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientRegistration<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    expires_at: &'a str,
    scopes: &'static [&'static str],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenFile<'a> {
    access_token: &'a str,
    refresh_token: &'a str,
    expires_at: &'a str,
    client_id_hash: &'a str,
    auth_method: &'a str,
    provider: &'a str,
    region: &'a str,
    profile_arn: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountStatus, KiroCredential};

    fn account(label: &str, total: f64, used: f64, status: AccountStatus) -> KiroAccount {
        KiroAccount {
            id: format!("id-{label}"),
            label: label.into(),
            email: format!("{label}@example.com"),
            status,
            credit_total: total,
            credit_used: used,
            cycle_reset_at: None,
            last_used_at: None,
            credential: KiroCredential {
                access_token: "at".into(),
                refresh_token: "rt".into(),
                expires_at: "".into(),
                region: "us-east-1".into(),
                auth_method: "IdC".into(),
                provider: "Enterprise".into(),
                client_id: "cid".into(),
                client_secret: "cs".into(),
                client_id_hash: "".into(),
                profile_arn: "".into(),
                start_url: "".into(),
            },
        }
    }

    #[test]
    fn selects_the_account_with_most_available_credit() {
        let accounts = vec![
            account("low", 100.0, 90.0, AccountStatus::Active),
            account("high", 1000.0, 100.0, AccountStatus::Active),
        ];
        assert_eq!(select_best_account(&accounts), Some(1));
    }

    #[test]
    fn skips_exhausted_and_suspended_accounts() {
        let accounts = vec![
            account("exhausted", 100.0, 100.0, AccountStatus::Exhausted),
            account("suspended", 1000.0, 0.0, AccountStatus::Suspended),
        ];
        assert_eq!(select_best_account(&accounts), None);
    }

    #[test]
    fn skips_active_accounts_with_no_credit() {
        let accounts = vec![account("empty", 0.0, 0.0, AccountStatus::Active)];
        assert_eq!(select_best_account(&accounts), None);
    }

    #[test]
    fn a_recently_used_account_loses_to_an_untouched_one() {
        // Both have 1000 available credit, but "recent" was switched to a moment ago — the
        // recency penalty must tip selection to "fresh".
        let mut recent = account("recent", 1000.0, 0.0, AccountStatus::Active);
        recent.last_used_at = Some(now_iso());
        let fresh = account("fresh", 1000.0, 0.0, AccountStatus::Active);

        let accounts = vec![recent, fresh];
        assert_eq!(select_best_account(&accounts), Some(1));
    }

    #[test]
    fn a_near_reset_account_beats_equal_credit_that_resets_later() {
        // Same credit, but "soon" resets in an hour (urgency term boosts it) while "later"
        // resets in a month. The 100× urgency weight is enough to tip equal-credit selection.
        let mut soon = account("soon", 100.0, 0.0, AccountStatus::Active);
        soon.cycle_reset_at = Some(iso_from_now(3600));
        let mut later = account("later", 100.0, 0.0, AccountStatus::Active);
        later.cycle_reset_at = Some(iso_from_now(30 * 24 * 3600));

        let accounts = vec![later, soon];
        assert_eq!(select_best_account(&accounts), Some(1));
    }

    /// Point `$HOME` at a scratch directory for the duration of a test: `sso_cache_dir()` (and
    /// `paths::data_dir()` behind the store) both resolve from it, so the developer's real
    /// `~/.aws/sso/cache` is never read or written. `$HOME` is process-wide, hence the lock.
    struct ScratchHome {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<std::ffi::OsString>,
    }

    impl ScratchHome {
        fn new(tag: &str) -> (Self, PathBuf) {
            static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let lock = HOME_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let dir = std::env::temp_dir().join(format!("9rai-pool-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let previous = std::env::var_os("HOME");
            std::env::set_var("HOME", &dir);
            (
                Self {
                    _lock: lock,
                    previous,
                },
                dir,
            )
        }
    }

    impl Drop for ScratchHome {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn finds_the_account_kiro_is_currently_using() {
        use crate::account::AccountStore;

        let (_home, dir) = ScratchHome::new("active");

        let mut store = AccountStore::default();
        let mut live = account("live", 100.0, 0.0, AccountStatus::Active);
        live.credential.client_id_hash = "abc123".into();
        store.upsert(live);

        // No Kiro cache at all — "we cannot tell", not an error.
        assert_eq!(find_active_label(&store), None);

        // Kiro's own token file names the live account by hash (case-insensitively).
        let cache = dir.join(".aws").join("sso").join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let token = cache.join("kiro-auth-token.json");
        std::fs::write(&token, r#"{"accessToken":"at","clientIdHash":"ABC123"}"#).unwrap();
        assert_eq!(find_active_label(&store).as_deref(), Some("live"));

        // A cache naming an account this pool does not hold matches nothing.
        std::fs::write(&token, r#"{"accessToken":"at","clientIdHash":"deadbeef"}"#).unwrap();
        assert_eq!(find_active_label(&store), None);

        // A malformed cache is tolerated too.
        std::fs::write(&token, "not json").unwrap();
        assert_eq!(find_active_label(&store), None);
    }
}
