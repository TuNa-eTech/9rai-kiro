//! The GUI's command surface.
//!
//! Every command here is a thin shell over the same `nine-rai-core` code the CLI drives, so
//! the window and `9rai` can never disagree about where config lives or what it means.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use nine_rai_core::account::{
    export_to_folder, find_active_label, import_from_folder, now_iso, select_best_account,
    switch_to_account, AccountStatus, AccountStore, KiroAccount, KiroApi,
};
use nine_rai_core::appconfig::AppConfig;
use nine_rai_core::cert::{trust, CertStore};
use nine_rai_core::config::KIRO_MODEL_SLOTS;
use nine_rai_core::{hosts, paths, session};
use std::path::Path;

use crate::daemon::{self, DaemonStatus, Supervisor};

pub struct AppState {
    pub supervisor: Mutex<Supervisor>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            supervisor: Mutex::new(Supervisor::load()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModelEntry {
    pub kiro: String,
    pub provider: String,
}

/// One known Kiro-side model id, so the window can offer the picker slots without
/// hard-coding a second copy of the protocol's model list.
#[derive(Debug, Serialize)]
pub struct ModelSlot {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct ConfigView {
    pub base_url: String,
    /// The key itself is never sent to the webview; only whether one is stored.
    pub api_key_set: bool,
    pub models: Vec<ModelEntry>,
    pub default_model: Option<String>,
    pub slots: Vec<ModelSlot>,
    pub config_path: String,
}

#[derive(Debug, Serialize)]
pub struct CaStatus {
    pub initialized: bool,
    pub fingerprint: Option<String>,
    pub trusted: bool,
    pub cert_path: String,
}

fn view(config: &AppConfig) -> ConfigView {
    let mut models: Vec<ModelEntry> = config
        .mappings
        .models
        .iter()
        .map(|(kiro, provider)| ModelEntry {
            kiro: kiro.clone(),
            provider: provider.clone(),
        })
        .collect();
    models.sort_by(|a, b| a.kiro.cmp(&b.kiro));
    ConfigView {
        base_url: config.provider.base_url.clone(),
        api_key_set: !config.provider.api_key.is_empty(),
        models,
        default_model: config.mappings.default.clone(),
        slots: KIRO_MODEL_SLOTS
            .iter()
            .map(|(id, name)| ModelSlot {
                id: id.to_string(),
                name: name.to_string(),
            })
            .collect(),
        config_path: AppConfig::path()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }
}

fn ca_view() -> Result<CaStatus, String> {
    let cert_path = paths::root_ca_cert().map_err(|e| e.to_string())?;
    let key_path = paths::root_ca_key().map_err(|e| e.to_string())?;
    let initialized = cert_path.is_file() && key_path.is_file();
    if !initialized {
        return Ok(CaStatus {
            initialized: false,
            fingerprint: None,
            trusted: false,
            cert_path: cert_path.display().to_string(),
        });
    }
    let store = CertStore::load_or_create().map_err(|e| e.to_string())?;
    let fingerprint = store.fingerprint().to_string();
    Ok(CaStatus {
        initialized: true,
        trusted: trust::is_installed(&fingerprint),
        fingerprint: Some(fingerprint),
        cert_path: cert_path.display().to_string(),
    })
}

#[tauri::command]
pub fn get_config() -> Result<ConfigView, String> {
    let config = AppConfig::load().map_err(|e| e.to_string())?;
    let view = view(&config);
    log::info!("desktop window connected; config at {}", view.config_path);
    Ok(view)
}

/// Save the provider endpoint. An empty/absent `api_key` keeps the stored one, so the UI can
/// change the URL without the key ever round-tripping through the webview.
#[tauri::command]
pub fn set_provider_config(
    base_url: String,
    api_key: Option<String>,
) -> Result<ConfigView, String> {
    let base_url = base_url.trim().to_string();
    if base_url.is_empty() {
        return Err("the provider base URL cannot be empty".into());
    }
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        return Err("the provider base URL must start with http:// or https://".into());
    }

    let mut config = AppConfig::load().map_err(|e| e.to_string())?;
    config.provider.base_url = base_url;
    if let Some(key) = api_key {
        let key = key.trim();
        if !key.is_empty() {
            config.provider.api_key = key.to_string();
        }
    }
    if config.provider.api_key.is_empty() {
        return Err("no API key stored yet — enter one to configure the provider".into());
    }
    config.save().map_err(|e| e.to_string())?;
    log::info!("provider configuration saved");
    Ok(view(&config))
}

/// Replace the whole model map with the rows the window submitted. The fallback
/// (`default_model`) is untouched; a row whose provider field is empty is simply not part of
/// the set, which is how the UI "removes" a mapping.
#[tauri::command]
pub fn set_model_mappings(models: Vec<ModelEntry>) -> Result<ConfigView, String> {
    let mut config = AppConfig::load().map_err(|e| e.to_string())?;
    let mut next = std::collections::HashMap::with_capacity(models.len());
    for entry in models {
        let kiro = entry.kiro.trim().to_string();
        let provider = entry.provider.trim().to_string();
        if kiro.is_empty() || provider.is_empty() {
            return Err(format!(
                "each row needs both a Kiro model id and a provider model (got `{kiro}` → `{provider}`)"
            ));
        }
        if next.insert(kiro.clone(), provider).is_some() {
            return Err(format!("duplicate Kiro model id `{kiro}`"));
        }
    }
    config.mappings.models = next;
    config.save().map_err(|e| e.to_string())?;
    log::info!("saved {} model mapping(s)", config.mappings.models.len());
    Ok(view(&config))
}

/// Set or clear (`None`) the fallback model used for unmapped Kiro models.
#[tauri::command]
pub fn set_default_model(provider_model: Option<String>) -> Result<ConfigView, String> {
    let mut config = AppConfig::load().map_err(|e| e.to_string())?;
    config.mappings.default = provider_model
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty());
    config.save().map_err(|e| e.to_string())?;
    Ok(view(&config))
}

/// Atomically save the provider configuration, model mappings, and fallback model in one step.
#[tauri::command]
pub fn save_all_settings(
    base_url: String,
    api_key: Option<String>,
    models: Vec<ModelEntry>,
    default_model: Option<String>,
) -> Result<ConfigView, String> {
    let base_url = base_url.trim().to_string();
    if base_url.is_empty() {
        return Err("The provider base URL cannot be empty".into());
    }
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        return Err("The provider base URL must start with http:// or https://".into());
    }

    let mut config = AppConfig::load().map_err(|e| e.to_string())?;
    config.provider.base_url = base_url;
    if let Some(key) = api_key {
        let key = key.trim();
        if !key.is_empty() {
            config.provider.api_key = key.to_string();
        }
    }
    if config.provider.api_key.is_empty() {
        return Err("No API key stored yet — please enter one to configure the provider".into());
    }

    let mut next = std::collections::HashMap::with_capacity(models.len());
    for entry in models {
        let kiro = entry.kiro.trim().to_string();
        let provider = entry.provider.trim().to_string();
        if !kiro.is_empty() && !provider.is_empty() && next.insert(kiro.clone(), provider).is_some()
        {
            return Err(format!("Duplicate Kiro model id `{kiro}`"));
        }
    }
    config.mappings.models = next;

    config.mappings.default = default_model
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty());

    config.save().map_err(|e| e.to_string())?;
    log::info!("all settings saved successfully");
    Ok(view(&config))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    pub ok: bool,
    pub status: u16,
    pub message: String,
    pub latency_ms: u64,
    pub models: Vec<String>,
}

#[tauri::command]
pub async fn test_provider_connection(
    base_url: String,
    api_key: Option<String>,
) -> Result<ConnectionTestResult, String> {
    let base_url = base_url.trim().trim_end_matches('/').to_string();
    if base_url.is_empty() {
        return Err("Base URL không được để trống".into());
    }
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        return Err("Base URL phải bắt đầu bằng http:// hoặc https://".into());
    }

    let effective_key = match api_key.filter(|k| !k.trim().is_empty()) {
        Some(k) => k,
        None => {
            let config = AppConfig::load().map_err(|e| e.to_string())?;
            config.provider.api_key
        }
    };

    let start = std::time::Instant::now();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("Lỗi tạo HTTP client: {e}"))?;

    let models_url = format!("{base_url}/models");
    let mut req = client.get(&models_url);
    if !effective_key.is_empty() {
        req = req.bearer_auth(&effective_key);
    }

    match req.send().await {
        Ok(resp) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status = resp.status().as_u16();
            if resp.status().is_success() {
                let mut models = Vec::new();
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        for item in data {
                            if let Some(id) = item.get("id").and_then(|s| s.as_str()) {
                                models.push(id.to_string());
                            }
                        }
                    }
                }
                models.sort();
                Ok(ConnectionTestResult {
                    ok: true,
                    status,
                    message: format!("Kết nối thành công (HTTP {status})"),
                    latency_ms,
                    models,
                })
            } else {
                let err_text = resp.text().await.unwrap_or_default();
                let summary = if err_text.len() > 150 {
                    format!("{}...", &err_text[..150])
                } else if err_text.is_empty() {
                    format!("Máy chủ trả về mã HTTP {status}")
                } else {
                    err_text
                };
                Ok(ConnectionTestResult {
                    ok: false,
                    status,
                    message: format!("Lỗi kết nối (HTTP {status}): {summary}"),
                    latency_ms,
                    models: vec![],
                })
            }
        }
        Err(err) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            Ok(ConnectionTestResult {
                ok: false,
                status: 0,
                message: format!("Không thể kết nối đến máy chủ: {err}"),
                latency_ms,
                models: vec![],
            })
        }
    }
}

#[tauri::command]
pub fn ca_status() -> Result<CaStatus, String> {
    ca_view()
}

/// The one-click "auto setup": mint the root CA if missing and install it into the system
/// trust store, elevating exactly once. Safe to run while the proxy is up or down, and a
/// no-op (no prompt) when trust is already in place.
#[tauri::command]
pub async fn install_ca() -> Result<CaStatus, String> {
    let store = CertStore::load_or_create().map_err(|e| e.to_string())?;
    if trust::is_installed(store.fingerprint()) {
        log::info!("root CA already trusted; no elevation needed");
        return ca_view();
    }

    let log = daemon::log_path().map_err(|e| e.to_string())?;
    if let Some(dir) = log.parent() {
        paths::ensure_dir(dir).map_err(|e| e.to_string())?;
        if !log.exists() {
            paths::write_private(&log, b"").map_err(|e| e.to_string())?;
        }
    }

    // One path, shared with the daemon launch: trust for this user, prompted by macOS itself.
    daemon::ensure_ca_trusted(&store, &log).await;

    let view = ca_view().map_err(|e| e.to_string())?;
    if !view.trusted {
        return Err(format!(
            "macOS still does not trust the root CA. Run this in a terminal, then try again:\n{}",
            trust::manual_trust_command(
                &store
                    .root_cert_path()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
            )
        ));
    }
    log::info!("root CA minted and trusted");
    Ok(view)
}

#[tauri::command]
pub async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatus, String> {
    let mut supervisor = state.supervisor.lock().await;
    Ok(supervisor.status().await)
}

#[tauri::command]
pub async fn start_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DaemonStatus, String> {
    let mut supervisor = state.supervisor.lock().await;
    // A start that fails before anything is launched (no provider, no mappings, no CLI on
    // disk) never reaches the daemon log on its own — it would exist only as a toast that is
    // gone in twelve seconds. Record it next to the daemon's own output.
    let status = match supervisor.start().await {
        Ok(status) => status,
        Err(e) => {
            log::error!("start failed: {e}");
            if let Ok(log) = daemon::log_path() {
                daemon::note(&log, &[format!("start failed before launching: {e}")]);
            }
            return Err(e.to_string());
        }
    };
    drop(supervisor);
    let _ = app.emit("proxy-status-changed", &status);
    Ok(status)
}

#[tauri::command]
pub async fn stop_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DaemonStatus, String> {
    let mut supervisor = state.supervisor.lock().await;
    let status = supervisor.stop().await.map_err(|e| e.to_string())?;
    drop(supervisor);
    let _ = app.emit("proxy-status-changed", &status);
    Ok(status)
}

/// Recent daemon output — the daemon's own stderr, captured by the launcher's redirection.
#[tauri::command]
pub fn daemon_log(lines: Option<usize>) -> Result<Vec<String>, String> {
    let path = daemon::log_path().map_err(|e| e.to_string())?;
    Ok(daemon::log_tail(&path, lines.unwrap_or(200).min(2000)))
}

/// Check if the system hosts file currently contains 9rai's interception block.
#[tauri::command]
pub fn check_hosts_stranded() -> Result<bool, String> {
    let hosts_path = paths::hosts_file();
    let content = std::fs::read_to_string(hosts_path).unwrap_or_default();
    Ok(hosts::is_applied(&content))
}

/// Remove 9rai's block from the system hosts file using elevated operations.
#[tauri::command]
pub async fn restore_hosts() -> Result<bool, String> {
    let cli = daemon::locate_cli().map_err(|e| e.to_string())?;
    let log = daemon::log_path().map_err(|e| e.to_string())?;
    let ops = session::disable_ops().map_err(|e| e.to_string())?;
    daemon::run_elevated_ops(&cli, &ops, &log)
        .await
        .map_err(|e| e.to_string())?;
    log::info!("hosts file cleanly restored");
    Ok(true)
}

/// One row of the Accounts table. Deliberately carries no credential fields: the refresh
/// token, client secret and API key live in `accounts.json` (0600) and must never reach the
/// webview, which is why the view is a projection rather than a serialization of `KiroAccount`.
#[derive(Debug, Serialize)]
pub struct AccountRow {
    pub label: String,
    pub email: String,
    pub region: String,
    pub auth_method: String,
    pub status: String,
    pub credit_total: f64,
    pub credit_used: f64,
    pub credit_available: f64,
    pub cycle_reset_at: Option<String>,
    pub last_used_at: Option<String>,
    /// Whether Kiro IDE's live SSO cache currently names this account.
    pub is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct AccountsView {
    pub accounts: Vec<AccountRow>,
    pub total: usize,
}

/// Project the pool for the window, best account first.
fn accounts_view(store: &AccountStore) -> AccountsView {
    let active = find_active_label(store);
    let mut accounts: Vec<AccountRow> = store
        .accounts
        .iter()
        .map(|acc| AccountRow {
            label: acc.label.clone(),
            email: acc.email.clone(),
            region: acc.credential.region.clone(),
            auth_method: acc.credential.auth_method.clone(),
            status: acc.status.as_str().to_string(),
            credit_total: acc.credit_total,
            credit_used: acc.credit_used,
            credit_available: acc.credit_available(),
            cycle_reset_at: acc.cycle_reset_at.clone(),
            last_used_at: acc.last_used_at.clone(),
            is_active: active.as_deref() == Some(acc.label.as_str()),
        })
        .collect();
    // Most credit first, so the account worth switching to reads at the top. `total_cmp` keeps
    // this a total order even if a credit value is degenerate.
    accounts.sort_by(|a, b| b.credit_available.total_cmp(&a.credit_available));
    AccountsView {
        total: accounts.len(),
        accounts,
    }
}

/// Import a folder from another machine: parse it offline, then resolve identity + credit
/// online. A dead refresh token fails here rather than entering the pool silently broken.
#[tauri::command]
pub async fn import_account(path: String, label: Option<String>) -> Result<AccountsView, String> {
    let folder = Path::new(&path);
    let cred = import_from_folder(folder).map_err(|e| e.to_string())?;

    let api = KiroApi::new(None).map_err(|e| e.to_string())?;
    let resolved = api
        .resolve_account(
            &cred.refresh_token,
            &cred.client_id,
            &cred.client_secret,
            &cred.region,
        )
        .await
        .map_err(|e| e.to_string())?;

    let label = nine_rai_core::account::derive_label(label, &resolved.email, &cred.client_id_hash);
    let id = format!("{}-{}", cred.client_id_hash, std::process::id());

    let mut account = KiroAccount {
        id,
        label: label.clone(),
        email: resolved.email.clone(),
        status: Default::default(),
        credit_total: resolved.credit_total,
        credit_used: resolved.credit_used,
        cycle_reset_at: resolved.reset_at.clone(),
        last_used_at: None,
        credential: cred,
    };
    // The resolved token pair is fresher than the folder's; keep the rolled-forward refresh
    // token or the next refresh uses a stale one.
    account.credential.access_token = resolved.access_token;
    account.credential.refresh_token = resolved.refresh_token;
    account.credential.expires_at = resolved.expires_at;
    account.credential.profile_arn = resolved.profile_arn;

    let mut store = AccountStore::load().map_err(|e| e.to_string())?;
    store.upsert(account);
    store.save().map_err(|e| e.to_string())?;
    log::info!("imported account '{label}'");
    Ok(accounts_view(&store))
}

/// One-click import for Kiro IDE's currently active SSO session from ~/.aws/sso/cache.
#[tauri::command]
pub async fn import_current_kiro_account() -> Result<AccountsView, String> {
    let cache_dir = nine_rai_core::account::sso_cache_dir();
    if !cache_dir.is_dir() {
        return Err("Kiro SSO cache directory not found (~/.aws/sso/cache). Please log in to Kiro IDE first.".into());
    }
    let token_file = nine_rai_core::account::token_file();
    if !token_file.is_file() {
        return Err("No active Kiro login session found in ~/.aws/sso/cache/kiro-auth-token.json. Please open Kiro IDE and log in.".into());
    }
    import_account(cache_dir.to_string_lossy().to_string(), None).await
}

#[tauri::command]
pub fn get_accounts() -> Result<AccountsView, String> {
    let store = AccountStore::load().map_err(|e| e.to_string())?;
    Ok(accounts_view(&store))
}

/// Write one account back out as the two-file folder the reference tool (and this app's own
/// import) reads. Returns the directory written, for the confirmation toast.
#[tauri::command]
pub fn export_account(label: String, out_dir: String) -> Result<String, String> {
    let store = AccountStore::load().map_err(|e| e.to_string())?;
    let account = store
        .get_by_label(&label)
        .ok_or_else(|| format!("no account with label '{label}'"))?;
    export_to_folder(&account.credential, Path::new(&out_dir)).map_err(|e| e.to_string())?;
    log::info!("exported account '{label}'");
    Ok(out_dir)
}

/// Switch Kiro IDE onto `label`: refresh its token, rewrite the live SSO cache, and persist
/// the refreshed credential back to the pool.
#[tauri::command]
pub async fn switch_account(label: String) -> Result<AccountsView, String> {
    let mut store = AccountStore::load().map_err(|e| e.to_string())?;
    let account = store
        .get_by_label(&label)
        .ok_or_else(|| format!("no account with label '{label}'"))?
        .clone();

    let api = KiroApi::new(None).map_err(|e| e.to_string())?;
    let refreshed = switch_to_account(&account, &api)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(slot) = store.accounts.iter_mut().find(|a| a.label == label) {
        slot.credential = refreshed;
        slot.last_used_at = Some(now_iso());
    }
    store.save().map_err(|e| e.to_string())?;
    log::info!("switched Kiro to '{label}'");
    Ok(accounts_view(&store))
}

/// Mark `label` exhausted and move Kiro to the next best account.
///
/// The mark is committed before the switch is attempted, so a failed switch returns `Ok` with
/// an explanatory message instead of an error — rolling the mark back would resurrect an
/// account the user just told us is out of credit.
#[tauri::command]
pub async fn mark_exhausted(label: String) -> Result<(AccountsView, Option<String>), String> {
    let mut store = AccountStore::load().map_err(|e| e.to_string())?;
    let status = store
        .get_by_label(&label)
        .ok_or_else(|| format!("no account with label '{label}'"))?
        .status;
    if status != AccountStatus::Active {
        return Err(format!("account '{label}' is already {}", status.as_str()));
    }

    if let Some(slot) = store.accounts.iter_mut().find(|a| a.label == label) {
        slot.status = AccountStatus::Exhausted;
    }
    store.save().map_err(|e| e.to_string())?;

    // Pick the successor from the *updated* pool, so the account just marked cannot be chosen.
    let Some(idx) = select_best_account(&store.accounts) else {
        log::info!("marked '{label}' exhausted; no other account has credit left");
        return Ok((
            accounts_view(&store),
            Some("marked exhausted — no other account has credit left".into()),
        ));
    };
    let next = store.accounts[idx].clone();

    let api = KiroApi::new(None).map_err(|e| e.to_string())?;
    let message = match switch_to_account(&next, &api).await {
        Ok(refreshed) => {
            if let Some(slot) = store.accounts.iter_mut().find(|a| a.label == next.label) {
                slot.credential = refreshed;
                slot.last_used_at = Some(now_iso());
            }
            store.save().map_err(|e| e.to_string())?;
            log::info!("marked '{label}' exhausted; switched to '{}'", next.label);
            format!("marked exhausted — switched to '{}'", next.label)
        }
        Err(e) => {
            // The mark stands; only the follow-up switch failed.
            log::error!(
                "marked '{label}' exhausted but switching to '{}' failed: {e}",
                next.label
            );
            format!("marked exhausted but auto-switch failed: {e}")
        }
    };
    Ok((accounts_view(&store), Some(message)))
}

#[tauri::command]
pub fn remove_account(label: String) -> Result<AccountsView, String> {
    let mut store = AccountStore::load().map_err(|e| e.to_string())?;
    if !store.remove_by_label(&label) {
        return Err(format!("no account with label '{label}'"));
    }
    store.save().map_err(|e| e.to_string())?;
    log::info!("removed account '{label}'");
    Ok(accounts_view(&store))
}

/// Switch to whichever account the selection heuristic prefers. Returns the label it moved to.
#[tauri::command]
pub async fn auto_switch_account() -> Result<(AccountsView, Option<String>), String> {
    let mut store = AccountStore::load().map_err(|e| e.to_string())?;
    let idx = select_best_account(&store.accounts)
        .ok_or_else(|| "no active account with credit left".to_string())?;
    let next = store.accounts[idx].clone();

    let api = KiroApi::new(None).map_err(|e| e.to_string())?;
    let refreshed = switch_to_account(&next, &api)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(slot) = store.accounts.iter_mut().find(|a| a.label == next.label) {
        slot.credential = refreshed;
        slot.last_used_at = Some(now_iso());
    }
    store.save().map_err(|e| e.to_string())?;
    log::info!("auto-switched Kiro to '{}'", next.label);
    Ok((accounts_view(&store), Some(next.label)))
}

/// Re-read every account's credit from CodeWhisperer. One unreachable account must not fail
/// the whole refresh, so failures come back as notes for the window to report alongside the
/// rows that did update.
#[tauri::command]
pub async fn refresh_accounts_usage() -> Result<(AccountsView, Vec<String>), String> {
    let mut store = AccountStore::load().map_err(|e| e.to_string())?;
    let api = KiroApi::new(None).map_err(|e| e.to_string())?;
    let mut notes = Vec::new();

    for account in &mut store.accounts {
        match api
            .check_usage(
                &account.credential.access_token,
                &account.credential.profile_arn,
            )
            .await
        {
            Ok(Some(usage)) if usage.is_banned => {
                account.status = AccountStatus::Suspended;
                notes.push(format!("'{}' is suspended by AWS", account.label));
            }
            Ok(Some(usage)) if usage.is_auth_error => {
                notes.push(format!(
                    "'{}' rejected its token — switch to it to refresh",
                    account.label
                ));
            }
            Ok(Some(usage)) => {
                // A 2xx without a CREDIT breakdown parses to all-zero; applying that would
                // silently zero a working account's credit and drop it from selection. Only
                // adopt numbers the response actually carried.
                if usage.total_limit > 0.0 || usage.total_used > 0.0 {
                    account.credit_total = usage.total_limit;
                    account.credit_used = usage.total_used;
                    account.cycle_reset_at = usage.reset_at;
                } else {
                    notes.push(format!("'{}' reported no credit breakdown", account.label));
                }
            }
            Ok(None) => notes.push(format!("'{}' usage unavailable", account.label)),
            Err(e) => notes.push(format!("'{}' usage failed: {e}", account.label)),
        }
    }

    store.save().map_err(|e| e.to_string())?;
    log::info!("refreshed usage for {} account(s)", store.accounts.len());
    Ok((accounts_view(&store), notes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_home::ScratchHome;
    use std::future::Future;

    #[test]
    fn config_commands_round_trip_through_the_real_config_file() {
        let (_home, dir) = ScratchHome::new("cmd");

        // A fresh install: no key, no mappings.
        let fresh = get_config().unwrap();
        assert!(!fresh.api_key_set);
        assert!(fresh.models.is_empty());
        assert_eq!(fresh.default_model, None);

        // The provider cannot be saved without a key, and the URL must be usable.
        assert!(set_provider_config("https://api.example.com/v1".into(), None).is_err());
        assert!(
            set_provider_config("ftp://api.example.com/v1".into(), Some("sk-1".into())).is_err()
        );

        // The key goes in once and never comes back out to the window.
        let saved = set_provider_config("https://api.example.com/v1".into(), Some(" sk-1 ".into()))
            .unwrap();
        assert!(saved.api_key_set);
        assert_eq!(saved.base_url, "https://api.example.com/v1");

        // Editing the URL alone keeps the stored key.
        let edited = set_provider_config("https://api.example.com/v2".into(), None).unwrap();
        assert!(edited.api_key_set);
        assert_eq!(edited.base_url, "https://api.example.com/v2");

        // Mappings: replace-whole-map semantics, validation, and the fallback path.
        let mapped = set_model_mappings(vec![
            ModelEntry {
                kiro: "auto".into(),
                provider: " gpt-4o ".into(),
            },
            ModelEntry {
                kiro: "simple-task".into(),
                provider: "deepseek-chat".into(),
            },
        ])
        .unwrap();
        assert_eq!(mapped.models.len(), 2);
        assert_eq!(mapped.models[0].kiro, "auto"); // sorted by id
        assert_eq!(mapped.models[0].provider, "gpt-4o");
        assert_eq!(mapped.models[1].kiro, "simple-task");

        // A later set replaces the map — nothing survives that was not resubmitted.
        let replaced = set_model_mappings(vec![ModelEntry {
            kiro: "auto".into(),
            provider: "gpt-4o-mini".into(),
        }])
        .unwrap();
        assert_eq!(replaced.models.len(), 1);
        assert_eq!(replaced.models[0].provider, "gpt-4o-mini");

        // Validation: blank rows and duplicate ids are rejected before anything is written.
        assert!(set_model_mappings(vec![ModelEntry {
            kiro: "auto".into(),
            provider: "".into()
        }])
        .is_err());
        assert!(set_model_mappings(vec![
            ModelEntry {
                kiro: "auto".into(),
                provider: "a".into()
            },
            ModelEntry {
                kiro: "auto".into(),
                provider: "b".into()
            },
        ])
        .is_err());

        // Clearing is the empty set.
        let cleared = set_model_mappings(vec![]).unwrap();
        assert!(cleared.models.is_empty());

        // The fallback is a separate field and survives map replacement.
        assert_eq!(
            set_default_model(Some("gpt-4o-mini".into()))
                .unwrap()
                .default_model
                .as_deref(),
            Some("gpt-4o-mini")
        );
        assert_eq!(
            set_default_model(Some("  ".into())).unwrap().default_model,
            None
        );

        // The known Kiro slots ride along on every view so the UI never needs its own copy.
        let with_slots = set_model_mappings(vec![ModelEntry {
            kiro: "auto".into(),
            provider: "gpt-4o".into(),
        }])
        .unwrap();
        assert!(with_slots
            .slots
            .iter()
            .any(|s| s.id == "auto" && !s.name.is_empty()));
        assert!(with_slots.slots.iter().any(|s| s.id == "simple-task"));

        // What the CLI reads back is exactly what the GUI wrote.
        let on_disk = AppConfig::load().unwrap();
        assert_eq!(on_disk.provider.base_url, "https://api.example.com/v2");
        assert_eq!(on_disk.provider.api_key, "sk-1");

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_all_settings_saves_provider_mappings_and_fallback_together() {
        let (_home, dir) = ScratchHome::new("save_all");

        let saved = save_all_settings(
            "https://api.deepseek.com/v1".into(),
            Some("sk-deepseek-test".into()),
            vec![
                ModelEntry {
                    kiro: "auto".into(),
                    provider: "deepseek-chat".into(),
                },
                ModelEntry {
                    kiro: "claude-sonnet-4".into(),
                    provider: "deepseek-reasoner".into(),
                },
            ],
            Some("deepseek-chat".into()),
        )
        .unwrap();

        assert!(saved.api_key_set);
        assert_eq!(saved.base_url, "https://api.deepseek.com/v1");
        assert_eq!(saved.models.len(), 2);
        assert_eq!(saved.default_model.as_deref(), Some("deepseek-chat"));

        // What the on-disk config has is updated
        let on_disk = AppConfig::load().unwrap();
        assert_eq!(on_disk.provider.base_url, "https://api.deepseek.com/v1");
        assert_eq!(on_disk.provider.api_key, "sk-deepseek-test");
        assert_eq!(
            on_disk.mappings.models.get("auto").unwrap(),
            "deepseek-chat"
        );
        assert_eq!(on_disk.mappings.default.as_deref(), Some("deepseek-chat"));

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_status_reports_uninitialized_and_minting_is_the_unprivileged_half() {
        let (_home, dir) = ScratchHome::new("ca");

        let status = ca_status().unwrap();
        assert!(!status.initialized);
        assert_eq!(status.fingerprint, None);
        assert!(!status.trusted);
        // Reporting status must not mint a CA behind the user's back.
        assert!(!nine_rai_core::paths::root_ca_cert().unwrap().exists());

        // Minting (the unprivileged half of the auto-setup command) creates the pair on disk;
        // without elevation the store is still untrusted.
        let store = CertStore::load_or_create().unwrap();
        assert!(nine_rai_core::paths::root_ca_cert().unwrap().is_file());
        let after = ca_status().unwrap();
        assert!(after.initialized);
        assert_eq!(after.fingerprint.as_deref(), Some(store.fingerprint()));
        assert!(!after.trusted);

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── accounts ─────────────────────────────────────────────────────────────

    /// A pool entry with a valid SSO shape (the folder-exportable kind).
    fn seed_account(label: &str, email: &str, total: f64, used: f64) -> KiroAccount {
        KiroAccount {
            id: format!("id-{label}"),
            label: label.into(),
            email: email.into(),
            status: AccountStatus::Active,
            credit_total: total,
            credit_used: used,
            cycle_reset_at: None,
            last_used_at: None,
            credential: nine_rai_core::account::KiroCredential {
                access_token: "at-secret".into(),
                refresh_token: "rt-secret".into(),
                expires_at: "2026-06-01T00:00:00Z".into(),
                region: "us-east-1".into(),
                auth_method: "IdC".into(),
                provider: "Enterprise".into(),
                client_id: "cid".into(),
                client_secret: "eyJhbGciOiJub25lIn0.eyJzZXJpYWxpemVkIjogIntcImluaXRpYXRlTG9naW5VcmlcIjpcImh0dHBzOi8vdmlldy5hd3NhcHBzLmNvbS9zdGFydFwifSJ9.sig".into(),
                client_id_hash: "e909a0580879b06ece1202964fbe9dda95ea4ce3".into(),
                profile_arn: "arn:aws:codewhisperer:us-east-1:111122223333:profile/test".into(),
                start_url: "https://view.awsapps.com/start".into(),
            },
        }
    }

    /// Persist a pool into the scratch home, the same way the app would.
    fn seed_store(accounts: Vec<KiroAccount>) {
        let mut store = AccountStore::load().unwrap();
        for account in accounts {
            store.upsert(account);
        }
        store.save().unwrap();
    }

    #[test]
    fn accounts_view_reports_the_pool_best_first_and_never_leaks_credentials() {
        let (_home, dir) = ScratchHome::new("acct-view");

        // An empty pool is a valid answer, not an error.
        let empty = get_accounts().unwrap();
        assert!(empty.accounts.is_empty());
        assert_eq!(empty.total, 0);

        seed_store(vec![
            seed_account("spent", "spent@example.com", 100.0, 90.0),
            seed_account("rich", "rich@example.com", 1000.0, 10.0),
        ]);

        let view = get_accounts().unwrap();
        assert_eq!(view.total, 2);
        // Most available credit reads first.
        assert_eq!(view.accounts[0].label, "rich");
        assert_eq!(view.accounts[1].label, "spent");
        assert_eq!(view.accounts[0].credit_available, 990.0);
        assert_eq!(view.accounts[0].status, "active");
        assert_eq!(view.accounts[0].region, "us-east-1");
        // No Kiro SSO cache exists in the scratch home, so nothing is "live".
        assert!(view.accounts.iter().all(|a| !a.is_active));

        // The projection is the security boundary: the webview must never receive a token.
        let json = serde_json::to_string(&view).unwrap();
        for secret in [
            "at-secret",
            "rt-secret",
            "refresh_token",
            "client_secret",
            "access_token",
        ] {
            assert!(
                !json.contains(secret),
                "accounts view leaked `{secret}`: {json}"
            );
        }

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accounts_view_marks_the_account_kiro_is_currently_using() {
        let (_home, dir) = ScratchHome::new("acct-active");
        seed_store(vec![
            seed_account("live", "live@example.com", 100.0, 0.0),
            seed_account("other", "other@example.com", 100.0, 0.0),
        ]);

        // Kiro's cache names the account by hash — the row must be flagged, the other not.
        let cache = dir.join(".aws").join("sso").join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(
            cache.join("kiro-auth-token.json"),
            r#"{"accessToken":"at","clientIdHash":"e909a0580879b06ece1202964fbe9dda95ea4ce3"}"#,
        )
        .unwrap();

        let view = get_accounts().unwrap();
        let live = view.accounts.iter().find(|a| a.label == "live").unwrap();
        let other = view.accounts.iter().find(|a| a.label == "other").unwrap();
        assert!(live.is_active);
        assert!(!other.is_active);

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_account_reports_a_missing_folder_before_touching_the_network() {
        let (_home, dir) = ScratchHome::new("acct-import");

        let missing = dir.join("nope");
        let err = block_on(import_account(missing.display().to_string(), None)).unwrap_err();
        assert!(
            err.contains("folder not found"),
            "expected a missing-folder error, got: {err}"
        );

        // A folder that exists but holds no Kiro files is also rejected, still offline.
        std::fs::create_dir_all(&missing).unwrap();
        let err = block_on(import_account(missing.display().to_string(), None)).unwrap_err();
        assert!(
            err.contains("kiro-auth-token.json"),
            "expected a missing-token-file error, got: {err}"
        );

        // Nothing was written into the pool.
        assert_eq!(get_accounts().unwrap().total, 0);

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_account_writes_a_folder_this_app_can_import_back() {
        let (_home, dir) = ScratchHome::new("acct-export");
        seed_store(vec![seed_account(
            "share-me",
            "share@example.com",
            100.0,
            0.0,
        )]);

        let out = dir.join("shared-out");
        let written = export_account("share-me".into(), out.display().to_string()).unwrap();
        assert_eq!(written, out.display().to_string());

        // The two-file folder shape, with the hash derived from the start URL.
        assert!(out.join("kiro-auth-token.json").is_file());
        assert!(out
            .join("e909a0580879b06ece1202964fbe9dda95ea4ce3.json")
            .is_file());

        // Round-trip: the same offline parser the import command uses reads it back intact.
        let cred = import_from_folder(&out).unwrap();
        assert_eq!(cred.refresh_token, "rt-secret");
        assert_eq!(cred.client_id, "cid");
        assert_eq!(cred.start_url, "https://view.awsapps.com/start");

        // An unknown label is an error, not a silently empty export.
        assert!(export_account("ghost".into(), out.display().to_string()).is_err());

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_account_drops_the_row_and_rejects_an_unknown_label() {
        let (_home, dir) = ScratchHome::new("acct-remove");
        seed_store(vec![
            seed_account("keep", "keep@example.com", 100.0, 0.0),
            seed_account("drop", "drop@example.com", 100.0, 0.0),
        ]);

        let view = remove_account("drop".into()).unwrap();
        assert_eq!(view.total, 1);
        assert_eq!(view.accounts[0].label, "keep");
        // Gone from disk too, not just from the returned view.
        assert_eq!(get_accounts().unwrap().total, 1);

        assert!(remove_account("drop".into()).is_err());

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_exhausted_marks_the_account_and_reports_when_there_is_no_successor() {
        let (_home, dir) = ScratchHome::new("acct-exhausted");
        seed_store(vec![seed_account("only", "only@example.com", 100.0, 0.0)]);

        // The only account is exhausted, so there is nobody to switch to. That is a successful
        // mark with an explanatory message — not an error, and not a rolled-back status.
        let (view, message) = block_on(mark_exhausted("only".into())).unwrap();
        assert_eq!(view.total, 1);
        assert_eq!(view.accounts[0].status, "exhausted");
        let message = message.expect("a message explaining the outcome");
        assert!(
            message.contains("no other account"),
            "unexpected message: {message}"
        );
        // The status survives a reload.
        assert_eq!(get_accounts().unwrap().accounts[0].status, "exhausted");

        // Marking an already-exhausted account is refused.
        assert!(block_on(mark_exhausted("only".into())).is_err());
        // As is an unknown label.
        assert!(block_on(mark_exhausted("ghost".into())).is_err());

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_switch_needs_an_account_with_credit() {
        let (_home, dir) = ScratchHome::new("acct-auto");

        // Empty pool.
        assert!(block_on(auto_switch_account()).is_err());

        // A pool whose only account is spent has nothing to switch to, and must not attempt a
        // network call to find out.
        let mut spent = seed_account("spent", "spent@example.com", 100.0, 100.0);
        spent.status = AccountStatus::Exhausted;
        seed_store(vec![spent]);
        assert!(block_on(auto_switch_account()).is_err());

        drop(_home);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Run a future to completion on a throwaway current-thread runtime. The commands are
    /// `async` only because the network calls inside them are; their offline paths (which is
    /// all a test can exercise) resolve without ever yielding.
    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a test runtime")
            .block_on(future)
    }
}
