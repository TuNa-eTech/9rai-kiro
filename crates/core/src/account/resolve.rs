//! Kiro API client: token refresh, profile ARN resolution, and credit usage.
//!
//! Ports the network primitives from the `kiro-account-switcher` reference (`kiro_api.py`),
//! scoped to what an account pool needs. These are the *only* calls that leave the machine:
//! refresh against the regional OIDC endpoint, and profile/usage against the CodeWhisperer
//! REST surface. Import and switch both depend on these, so they live here rather than in
//! either caller.
//!
//! Headers mirror what Kiro IDE sends — including the machine-id that Kiro derives from the
//! platform UUID (macOS) or `/etc/machine-id` (Linux). Without a plausible machine-id the
//! upstream treats every account as a multi-device login.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Kiro's REST surface. API keys and OAuth tokens both authenticate here, but the request
/// shape differs — see [`crate::account::CredentialKind`].
pub const CODEWHISPERER_BASE: &str = "https://codewhisperer.us-east-1.amazonaws.com";

const DEFAULT_KIRO_VERSION: &str = "0.11.107";
const DEFAULT_NODE_VERSION: &str = "22.22.0";

/// What a token refresh produced.
#[derive(Debug, Clone, Default)]
pub struct RefreshResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub profile_arn: String,
}

/// Credit/identity snapshot returned by `getUsageLimits`.
#[derive(Debug, Clone, Default)]
pub struct UsageInfo {
    pub total_limit: f64,
    pub total_used: f64,
    pub email: String,
    pub is_banned: bool,
    pub ban_reason: String,
    pub is_auth_error: bool,
    /// ISO-8601 timestamp the credit window resets, from `nextDateReset`/`resetDate`.
    pub reset_at: Option<String>,
}

impl UsageInfo {
    pub fn available(&self) -> f64 {
        (self.total_limit - self.total_used).max(0.0)
    }
}

/// What a full account resolution produces: a fresh token pair plus the identity and credit
/// state that import (and later switch) need before touching the pool.
#[derive(Debug, Clone, Default)]
pub struct ResolvedAccount {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub profile_arn: String,
    pub email: String,
    pub credit_total: f64,
    pub credit_used: f64,
    /// ISO-8601 credit reset time, when the usage response reports one.
    pub reset_at: Option<String>,
}

/// A client for Kiro's OIDC + CodeWhisperer endpoints, optionally proxied.
#[derive(Clone)]
pub struct KiroApi {
    http: reqwest::Client,
    machine_id: String,
}

impl KiroApi {
    pub fn new(proxy_url: Option<&str>) -> Result<Self> {
        let builder = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(20))
            .timeout(std::time::Duration::from_secs(60));
        let http = match proxy_url {
            Some(url) if !url.is_empty() => builder.proxy(reqwest::Proxy::all(url)?).build()?,
            _ => builder.build()?,
        };
        Ok(Self {
            http,
            machine_id: machine_id_hash(),
        })
    }

    /// Refresh an SSO token via the regional OIDC endpoint.
    ///
    /// `refresh_token` is the rolled-forward token when the response carries one; the caller
    /// must persist it or the next refresh uses a stale token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
        region: &str,
    ) -> Result<RefreshResult> {
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(Error::Account(
                "refresh requires clientId and clientSecret".into(),
            ));
        }
        let region = if region.is_empty() {
            "us-east-1"
        } else {
            region
        };

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            client_id: &'a str,
            client_secret: &'a str,
            refresh_token: &'a str,
            grant_type: &'a str,
        }
        use serde::Serialize;

        let url = format!("https://oidc.{region}.amazonaws.com/token");
        let body = Body {
            client_id,
            client_secret,
            refresh_token,
            grant_type: "refresh_token",
        };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            let detail = String::from_utf8_lossy(&bytes);
            return Err(Error::Account(format!(
                "token refresh failed: HTTP {status}: {detail}"
            )));
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Tokens {
            #[serde(default)]
            access_token: String,
            #[serde(default)]
            refresh_token: String,
            #[serde(default)]
            expires_in: u64,
            #[serde(default)]
            profile_arn: String,
        }
        let tokens: Tokens = serde_json::from_slice(&bytes)?;

        Ok(RefreshResult {
            access_token: tokens.access_token,
            refresh_token: if tokens.refresh_token.is_empty() {
                refresh_token.to_string()
            } else {
                tokens.refresh_token
            },
            expires_in: tokens.expires_in,
            profile_arn: tokens.profile_arn,
        })
    }

    /// Resolve the profile ARN for a token: `ListAvailableProfiles`, falling back to a refresh
    /// when the access token alone yields nothing (the reference does the same).
    pub async fn resolve_profile_arn(
        &self,
        access_token: &str,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
        region: &str,
    ) -> Result<String> {
        if let Some(arn) = self.list_available_profiles(access_token).await? {
            return Ok(arn);
        }
        if !refresh_token.is_empty() && !client_id.is_empty() && !client_secret.is_empty() {
            let refreshed = self
                .refresh_token(refresh_token, client_id, client_secret, region)
                .await?;
            if !refreshed.profile_arn.is_empty() {
                return Ok(refreshed.profile_arn);
            }
        }
        Ok(String::new())
    }

    /// The first profile ARN the account exposes, if any.
    async fn list_available_profiles(&self, access_token: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct Profiles {
            #[serde(default)]
            profiles: Vec<Profile>,
        }
        #[derive(Deserialize)]
        struct Profile {
            #[serde(default)]
            arn: String,
        }

        let url = format!("{CODEWHISPERER_BASE}/ListAvailableProfiles");
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "maxResults": 10 }))
            .headers(self.headers(access_token))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(None);
        }
        let data: Profiles = resp.json().await?;
        Ok(data.profiles.into_iter().find_map(|p| {
            let arn = p.arn.trim().to_string();
            (!arn.is_empty()).then_some(arn)
        }))
    }

    /// Credit + identity from `getUsageLimits`. Returns `None` on a non-2xx that is neither a
    /// ban nor an auth error, mirroring the reference (which swallows those into `None`).
    pub async fn check_usage(
        &self,
        access_token: &str,
        profile_arn: &str,
    ) -> Result<Option<UsageInfo>> {
        let url = format!("{CODEWHISPERER_BASE}/getUsageLimits");
        let mut query: Vec<(&str, &str)> = vec![
            ("isEmailRequired", "true"),
            ("origin", "AI_EDITOR"),
            ("resourceType", "AGENTIC_REQUEST"),
        ];
        let arn_owned;
        if !profile_arn.is_empty() {
            arn_owned = profile_arn.to_string();
            query.push(("profileArn", arn_owned.as_str()));
        }

        let resp = self
            .http
            .get(&url)
            .query(&query)
            .headers(self.headers(access_token))
            .send()
            .await?;

        let status = resp.status();
        let bytes = resp.bytes().await?;

        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            if body.contains("TEMPORARILY_SUSPENDED") {
                return Ok(Some(UsageInfo {
                    is_banned: true,
                    ban_reason: "TEMPORARILY_SUSPENDED".into(),
                    ..Default::default()
                }));
            }
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return Ok(Some(UsageInfo {
                    is_auth_error: true,
                    ..Default::default()
                }));
            }
            return Ok(None);
        }

        Ok(Some(parse_usage(&bytes)?))
    }

    /// Resolve an account end-to-end: refresh the token, then pull identity + credit from
    /// CodeWhisperer. This is the single entry point import (and later switch) share.
    pub async fn resolve_account(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
        region: &str,
    ) -> Result<ResolvedAccount> {
        let refreshed = self
            .refresh_token(refresh_token, client_id, client_secret, region)
            .await?;

        let profile_arn = self
            .resolve_profile_arn(
                &refreshed.access_token,
                &refreshed.refresh_token,
                client_id,
                client_secret,
                region,
            )
            .await?;

        let mut resolved = ResolvedAccount {
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            expires_at: expires_at_from(refreshed.expires_in),
            profile_arn,
            ..Default::default()
        };

        if let Some(usage) = self
            .check_usage(&resolved.access_token, &resolved.profile_arn)
            .await?
        {
            resolved.email = usage.email;
            resolved.credit_total = usage.total_limit;
            resolved.credit_used = usage.total_used;
            resolved.reset_at = usage.reset_at;
        }
        Ok(resolved)
    }

    fn headers(&self, access_token: &str) -> reqwest::header::HeaderMap {
        use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        if !access_token.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {access_token}")) {
                headers.insert(AUTHORIZATION, v);
            }
        }
        if let Ok(v) = HeaderValue::from_str(&user_agent(&self.machine_id)) {
            headers.insert(USER_AGENT, v);
        }
        if let Ok(v) = HeaderValue::from_str(&amz_user_agent(&self.machine_id)) {
            headers.insert("x-amz-user-agent", v);
        }
        // No manual `Host`: reqwest derives it from the request URL. The previous code sent
        // the full base URL (`https://codewhisperer.…`) as the Host value, and AWS answers
        // every such call with `400 Bad Request` — so profile resolution silently got `None`
        // and usage silently got `None`, leaving every account at 0/0 credits with no email.
        headers
    }
}

/// ISO-8601 timestamp `expires_in` seconds from now, for the `expiresAt` field Kiro reads.
fn expires_at_from(expires_in: u64) -> String {
    use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(expires_in.max(1) as i64);
    expiry.format(&Rfc3339).unwrap_or_default()
}

/// Rebuild the user-agent Kiro IDE sends, with the machine-id suffix.
fn user_agent(machine_id: &str) -> String {
    let os = os_version();
    let base = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{os} lang/js md/nodejs#{DEFAULT_NODE_VERSION} \
         api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{DEFAULT_KIRO_VERSION}"
    );
    if machine_id.is_empty() {
        base
    } else {
        format!("{base}-{machine_id}")
    }
}

fn amz_user_agent(machine_id: &str) -> String {
    let base = format!("aws-sdk-js/1.0.0 KiroIDE-{DEFAULT_KIRO_VERSION}");
    if machine_id.is_empty() {
        base
    } else {
        format!("{base}-{machine_id}")
    }
}

fn os_version() -> String {
    let os = std::env::consts::OS; // "macos" | "linux" | "windows"
    format!("{os}#{}", std::env::consts::ARCH)
}

/// SHA-256 machine-id, matching Kiro IDE: the platform UUID on macOS, `/etc/machine-id` on
/// Linux, the hostname everywhere else / as a fallback.
fn machine_id_hash() -> String {
    let id = machine_id_source();
    let digest = Sha256::digest(id.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn machine_id_source() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some((_, value)) = line.split_once('=') {
                        let v = value.trim().trim_matches('"');
                        if !v.is_empty() {
                            return v.to_string();
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let id = id.trim();
            if !id.is_empty() {
                return id.to_string();
            }
        }
    }
    hostname()
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".into())
}

/// Parse the `getUsageLimits` response into [`UsageInfo`]. Mirrors the reference's field
/// fallbacks (`usageLimitWithPrecision` → `usageLimit`, free-trial rollup).
fn parse_usage(bytes: &[u8]) -> Result<UsageInfo> {
    let data: serde_json::Value = serde_json::from_slice(bytes)?;

    let mut info = UsageInfo::default();
    let sub = data.get("subscriptionInfo").and_then(|v| v.as_object());
    let _ = sub; // subscription type/title are not surfaced by the pool yet

    if let Some(user) = data.get("userInfo").and_then(|v| v.as_object()) {
        info.email = user
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
    }

    // Credit reset time: the top-level `nextDateReset`/`resetDate`, normalized to ISO-8601.
    // Kiro reports either a date string or a unix timestamp (seconds or millis).
    info.reset_at = data
        .get("nextDateReset")
        .or_else(|| data.get("resetDate"))
        .and_then(parse_reset_time);

    if let Some(list) = data.get("usageBreakdownList").and_then(|v| v.as_array()) {
        for bd in list {
            let Some(bd) = bd.as_object() else { continue };
            if bd.get("resourceType").and_then(|v| v.as_str()) != Some("CREDIT") {
                continue;
            }
            info.total_limit = num_or_zero(bd, "usageLimitWithPrecision")
                .or_else(|| num_or_zero(bd, "usageLimit"))
                .unwrap_or(0.0);
            info.total_used = num_or_zero(bd, "currentUsageWithPrecision")
                .or_else(|| num_or_zero(bd, "currentUsage"))
                .unwrap_or(0.0);

            if let Some(ft) = bd.get("freeTrialInfo").and_then(|v| v.as_object()) {
                if ft.get("freeTrialStatus").and_then(|v| v.as_str()) == Some("ACTIVE") {
                    info.total_limit += num_or_zero(ft, "usageLimitWithPrecision")
                        .or_else(|| num_or_zero(ft, "usageLimit"))
                        .unwrap_or(0.0);
                    info.total_used += num_or_zero(ft, "currentUsageWithPrecision")
                        .or_else(|| num_or_zero(ft, "currentUsage"))
                        .unwrap_or(0.0);
                }
            }
            break;
        }
    }

    Ok(info)
}

fn num_or_zero(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<f64> {
    obj.get(key).and_then(|v| v.as_f64())
}

/// Normalize Kiro's reset-time value to an ISO-8601 string. Handles an ISO string, a unix
/// timestamp in seconds, or in milliseconds (the reference treats `1e12` as the boundary).
fn parse_reset_time(v: &serde_json::Value) -> Option<String> {
    // Already a date string → pass through.
    if let Some(s) = v.as_str() {
        if !s.is_empty() {
            return Some(s.to_string());
        }
        return None;
    }
    // Unix timestamp, seconds or milliseconds.
    let raw = v.as_f64()?;
    if raw <= 0.0 {
        return None;
    }
    let seconds = if raw < 1e12 { raw } else { raw / 1000.0 };
    let nanos = (seconds * 1e9) as i128;
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    t.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_credit_breakdown_and_email() {
        let body = r#"{
            "subscriptionInfo": { "type": "PRO" },
            "userInfo": { "email": "user@fpt.com", "userId": "u-1" },
            "usageBreakdownList": [
                { "resourceType": "CREDIT",
                  "usageLimitWithPrecision": 1000.5,
                  "currentUsageWithPrecision": 123.25 }
            ]
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        assert_eq!(info.email, "user@fpt.com");
        assert!((info.total_limit - 1000.5).abs() < 1e-9);
        assert!((info.total_used - 123.25).abs() < 1e-9);
        assert!((info.available() - 877.25).abs() < 1e-9);
    }

    #[test]
    fn rolls_up_active_free_trial() {
        let body = r#"{
            "userInfo": {},
            "usageBreakdownList": [
                { "resourceType": "CREDIT",
                  "usageLimit": 500.0,
                  "currentUsage": 400.0,
                  "freeTrialInfo": {
                      "freeTrialStatus": "ACTIVE",
                      "usageLimit": 50.0,
                      "currentUsage": 10.0
                  } }
            ]
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        assert_eq!(info.total_limit, 550.0);
        assert_eq!(info.total_used, 410.0);
    }

    #[test]
    fn ignores_non_credit_breakdown_entries() {
        let body = r#"{
            "userInfo": {},
            "usageBreakdownList": [
                { "resourceType": "AGENTIC_REQUEST", "usageLimit": 9999.0 }
            ]
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        assert_eq!(info.total_limit, 0.0);
    }

    #[test]
    fn machine_id_hash_is_64_hex_chars() {
        let hash = machine_id_hash();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parses_reset_time_from_next_date_reset() {
        let body = r#"{
            "userInfo": {},
            "nextDateReset": "2026-09-25T00:00:00Z",
            "usageBreakdownList": [
                { "resourceType": "CREDIT", "usageLimit": 100.0, "currentUsage": 10.0 }
            ]
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        assert_eq!(info.reset_at.as_deref(), Some("2026-09-25T00:00:00Z"));
    }

    #[test]
    fn normalizes_millisecond_unix_timestamp_reset() {
        let body = r#"{
            "userInfo": {},
            "resetDate": 1756051200000,
            "usageBreakdownList": []
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        // 1756051200 = 2025-08-24T16:00:00Z.
        assert_eq!(info.reset_at.as_deref(), Some("2025-08-24T16:00:00Z"));
    }

    #[test]
    fn normalizes_second_unix_timestamp_reset() {
        let body = r#"{
            "userInfo": {},
            "nextDateReset": 1756051200,
            "usageBreakdownList": []
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        assert_eq!(info.reset_at.as_deref(), Some("2025-08-24T16:00:00Z"));
    }

    /// The exact shape CodeWhisperer returns for a KIRO PRO account (sanitized): float
    /// `nextDateReset` in scientific notation, full CREDIT breakdown, email under `userInfo`.
    #[test]
    fn parses_the_live_kiro_pro_response_shape() {
        let body = r#"{
            "daysUntilReset": 0,
            "limits": [],
            "nextDateReset": 1.7908128E9,
            "subscriptionInfo": {"type": "Q_DEVELOPER_STANDALONE_PRO", "subscriptionTitle": "KIRO PRO"},
            "usageBreakdownList": [
                { "resourceType": "CREDIT",
                  "currency": "USD",
                  "currentUsage": 672,
                  "currentUsageWithPrecision": 672.95,
                  "displayName": "Credit",
                  "freeTrialInfo": null,
                  "nextDateReset": 1.7908128E9,
                  "resourceType": "CREDIT",
                  "unit": "INVOCATIONS",
                  "usageLimit": 1000,
                  "usageLimitWithPrecision": 1000.0 }
            ],
            "userInfo": {"email": "user@fpt.com", "userId": "d-90660cc21e.abc"}
        }"#;
        let info = parse_usage(body.as_bytes()).unwrap();
        assert_eq!(info.email, "user@fpt.com");
        assert!((info.total_limit - 1000.0).abs() < 1e-9);
        assert!((info.total_used - 672.95).abs() < 1e-9);
        assert!((info.available() - 327.05).abs() < 1e-6);
        // 1790812800 = 2026-10-01T00:00:00Z.
        assert_eq!(info.reset_at.as_deref(), Some("2026-10-01T00:00:00Z"));
    }

    /// reqwest must send the Host derived from the URL — a manual `Host` header carrying the
    /// full base URL (`https://…`) makes AWS answer `400 Bad Request`, which used to sink
    /// every usage/profile call into silent `None` (0/0 credits, no email).
    #[test]
    fn headers_carry_no_manual_host() {
        use reqwest::header::HOST;
        crate::proxy::init_crypto();
        let api = KiroApi {
            http: reqwest::Client::builder().build().unwrap(),
            machine_id: "test-machine".into(),
        };
        let headers = api.headers("token-123");
        assert!(headers.get(HOST).is_none());
        assert!(headers.get(reqwest::header::AUTHORIZATION).is_some());
    }
}
