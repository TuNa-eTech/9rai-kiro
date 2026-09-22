//! 9rai desktop — the Tauri shell around the headless engine.
//!
//! The window is a control panel, not a second implementation: configuration and the root CA
//! are read and written through `nine-rai-core` (the same code `9rai config` / `9rai ca` run),
//! and the privileged work is delegated to the `9rai daemon` process — see `daemon.rs`.

mod commands;
mod daemon;

#[cfg(test)]
mod test_home;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // reqwest is built with `rustls-no-provider`, so the ring provider must be installed
    // before the first TLS connection anywhere in this process.
    nine_rai_core::proxy::init_crypto();

    tauri::Builder::default()
        .plugin(
            // The window's log (`~/Library/Logs/<identifier>/9rai.log` on macOS) is a support
            // artefact: when a start fails, the user is asked for it. At the plugin's default
            // Trace level our own handful of lines sit under thousands of reqwest/tao frames,
            // so everything below is pinned down to warnings and the app's own modules up.
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .level_for("app_lib", log::LevelFilter::Debug)
                .level_for("nine_rai_core", log::LevelFilter::Debug)
                .level_for("reqwest", log::LevelFilter::Warn)
                .level_for("hyper", log::LevelFilter::Warn)
                .level_for("hyper_util", log::LevelFilter::Warn)
                .level_for("rustls", log::LevelFilter::Warn)
                .level_for("tao", log::LevelFilter::Warn)
                .level_for("wry", log::LevelFilter::Warn)
                .level_for("tracing", log::LevelFilter::Warn)
                .build(),
        )
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_config,
            commands::set_provider_config,
            commands::set_model_mappings,
            commands::set_default_model,
            commands::ca_status,
            commands::install_ca,
            commands::daemon_status,
            commands::start_proxy,
            commands::stop_proxy,
            commands::daemon_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
