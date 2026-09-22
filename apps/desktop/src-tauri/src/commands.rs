//! The GUI's command surface.
//!
//! Every command here is a thin shell over the same `nine-rai-core` code the CLI drives, so
//! the window and `9rai` can never disagree about where config lives or what it means.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use nine_rai_core::appconfig::AppConfig;
use nine_rai_core::cert::{trust, CertStore};
use nine_rai_core::config::KIRO_MODEL_SLOTS;
use nine_rai_core::paths;

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
                &store.root_cert_path().map_err(|e| e.to_string())?.to_string_lossy()
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
pub async fn stop_proxy(app: AppHandle, state: State<'_, AppState>) -> Result<DaemonStatus, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_home::ScratchHome;

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
        assert!(set_provider_config("ftp://api.example.com/v1".into(), Some("sk-1".into())).is_err());

        // The key goes in once and never comes back out to the window.
        let saved =
            set_provider_config("https://api.example.com/v1".into(), Some(" sk-1 ".into())).unwrap();
        assert!(saved.api_key_set);
        assert_eq!(saved.base_url, "https://api.example.com/v1");

        // Editing the URL alone keeps the stored key.
        let edited = set_provider_config("https://api.example.com/v2".into(), None).unwrap();
        assert!(edited.api_key_set);
        assert_eq!(edited.base_url, "https://api.example.com/v2");

        // Mappings: replace-whole-map semantics, validation, and the fallback path.
        let mapped = set_model_mappings(vec![
            ModelEntry { kiro: "auto".into(), provider: " gpt-4o ".into() },
            ModelEntry { kiro: "simple-task".into(), provider: "deepseek-chat".into() },
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
        assert!(set_model_mappings(vec![ModelEntry { kiro: "auto".into(), provider: "".into() }]).is_err());
        assert!(set_model_mappings(vec![
            ModelEntry { kiro: "auto".into(), provider: "a".into() },
            ModelEntry { kiro: "auto".into(), provider: "b".into() },
        ])
        .is_err());

        // Clearing is the empty set.
        let cleared = set_model_mappings(vec![]).unwrap();
        assert!(cleared.models.is_empty());

        // The fallback is a separate field and survives map replacement.
        assert_eq!(
            set_default_model(Some("gpt-4o-mini".into())).unwrap().default_model.as_deref(),
            Some("gpt-4o-mini")
        );
        assert_eq!(set_default_model(Some("  ".into())).unwrap().default_model, None);

        // The known Kiro slots ride along on every view so the UI never needs its own copy.
        let with_slots = set_model_mappings(vec![ModelEntry {
            kiro: "auto".into(),
            provider: "gpt-4o".into(),
        }])
        .unwrap();
        assert!(with_slots.slots.iter().any(|s| s.id == "auto" && !s.name.is_empty()));
        assert!(with_slots.slots.iter().any(|s| s.id == "simple-task"));

        // What the CLI reads back is exactly what the GUI wrote.
        let on_disk = AppConfig::load().unwrap();
        assert_eq!(on_disk.provider.base_url, "https://api.example.com/v2");
        assert_eq!(on_disk.provider.api_key, "sk-1");

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
}
