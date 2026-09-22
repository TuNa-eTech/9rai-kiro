//! Trust-store commands, one module per concern.
//!
//! These return [`Argv`] lists rather than running anything, so [`crate::privilege`] can batch a
//! whole install into a single elevation and tests can assert the exact commands. The macOS and
//! Windows forms mirror the reference implementation's `security` / `certutil` usage.

use std::process::Command;

use crate::cert::gen::ROOT_CN;
use crate::privilege::Argv;

const MAC_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

// ── macOS / Unix ─────────────────────────────────────────────────────────────

/// `security add-trusted-cert` into the system keychain. A stale copy is deleted first so
/// re-installs after a rotation do not accumulate — best-effort, since on a first install
/// there is nothing to delete and `security` reports that as an error.
pub fn unix_install(cert_path: &str) -> Vec<Argv> {
    vec![
        Argv::optional([
            "security",
            "delete-certificate",
            "-c",
            ROOT_CN,
            MAC_KEYCHAIN,
        ]),
        Argv::new([
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            MAC_KEYCHAIN,
            cert_path,
        ]),
    ]
}

/// Trust the root for the logged-in user, with no elevation at all.
///
/// The admin domain (`-d`) needs an authorization only an interactive session can satisfy, and
/// the GUI elevates through AppleScript's privileged trampoline, which has no session to prompt
/// in — hence "the authorization was denied since no user interaction was possible", every
/// time, however many times it is retried. This form runs as the user in their own session, so
/// macOS raises its own dialog and takes the answer directly. The settings land in the user
/// trust domain, which Security.framework honours for that user's applications — which is every
/// client we care about, the IDE included.
pub fn unix_install_user(cert_path: &str) -> Vec<Argv> {
    vec![Argv::new([
        "security",
        "add-trusted-cert",
        "-r",
        "trustRoot",
        cert_path,
    ])]
}

pub fn unix_remove(fingerprint: &str) -> Vec<Argv> {
    vec![Argv::optional([
        "security",
        "delete-certificate",
        "-Z",
        fingerprint,
        MAC_KEYCHAIN,
    ])]
}

pub fn unix_flush_dns() -> Vec<Argv> {
    #[cfg(target_os = "linux")]
    {
        return vec![Argv::new(["resolvectl", "flush-caches"])];
    }
    #[cfg(not(target_os = "linux"))]
    vec![
        Argv::new(["dscacheutil", "-flushcache"]),
        Argv::new(["killall", "-HUP", "mDNSResponder"]),
    ]
}

const NODE_CA_VAR: &str = "NODE_EXTRA_CA_CERTS";

/// What to tell a user whose trust store we could not write.
///
/// Worth spelling out rather than saying "trust failed": the same command run from a terminal
/// has the interactive authorization that an elevated-but-headless shell does not.
#[cfg(target_os = "macos")]
pub fn manual_trust_command(cert_path: &str) -> String {
    // No `sudo`: run from a terminal it prompts through macOS's own dialog, which is exactly
    // what the app's elevation path cannot do.
    format!("security add-trusted-cert -r trustRoot \"{cert_path}\"")
}

#[cfg(not(target_os = "macos"))]
pub fn manual_trust_command(cert_path: &str) -> String {
    format!("install {cert_path} into the system trust store manually")
}

/// Point Node-based clients at our root CA.
///
/// Trusting the root in the system keychain is not enough for Kiro: its agent runs in an
/// Electron *utility* process (`node.mojom.NodeService`), and Node ships its own compiled-in CA
/// list that ignores the macOS keychain entirely. Without this the TLS handshake is refused by
/// the client, so there is no request to log and the IDE reports only its own "Internal error".
/// `launchctl setenv` reaches the user's GUI session; from a root daemon that needs an `asuser`
/// hop into their domain. Processes pick the variable up when they start, so the IDE has to be
/// restarted once after enabling.
pub fn unix_set_node_ca(cert_path: &str) -> Vec<Argv> {
    launchctl(["setenv", NODE_CA_VAR, cert_path])
}

pub fn unix_unset_node_ca() -> Vec<Argv> {
    launchctl(["unsetenv", NODE_CA_VAR])
}

fn launchctl<const N: usize>(args: [&str; N]) -> Vec<Argv> {
    #[cfg(not(target_os = "macos"))]
    {
        // `launchctl` is macOS-only; elsewhere the variable is the user's own business.
        let _ = args;
        Vec::new()
    }
    #[cfg(target_os = "macos")]
    {
        let mut argv: Vec<String> = match crate::paths::gui_user_uid() {
            Some(uid) => vec![
                "launchctl".into(),
                "asuser".into(),
                uid.to_string(),
                "launchctl".into(),
            ],
            None => vec!["launchctl".into()],
        };
        argv.extend(args.iter().map(|a| a.to_string()));
        // Best-effort: a machine without a GUI session still proxies fine for anything that
        // uses the system trust store.
        vec![Argv(argv, true)]
    }
}

/// The Windows equivalent: a user-level environment variable for the same Node clients.
pub fn windows_set_node_ca(cert_path: &str) -> Vec<Argv> {
    vec![Argv::optional(["setx", NODE_CA_VAR, cert_path])]
}

pub fn windows_unset_node_ca() -> Vec<Argv> {
    vec![Argv::optional([
        "reg",
        "delete",
        "HKCU\\Environment",
        "/F",
        "/V",
        NODE_CA_VAR,
    ])]
}

/// Make the system resolver re-read the hosts file.
///
/// macOS is why this exists. `killall -HUP mDNSResponder` purges the DNS cache — its log says
/// exactly that, "SIGHUP: Purge cache" — but it does **not** re-read `/etc/hosts`; that only
/// happens when mDNSResponder's own file watcher fires, and it misses the change when the file
/// is replaced twice within a few seconds, which is precisely what a stop-then-start does. The
/// hijack then looks applied everywhere except in `getaddrinfo`, which keeps handing out the
/// real addresses, and the proxy sits there with nothing connecting to it. Terminating the
/// daemon makes launchd restart it, and it reads the hosts file on startup.
///
/// Best-effort: if the process is not running, launchd is about to start a fresh one anyway.
pub fn unix_reload_resolver() -> Vec<Argv> {
    #[cfg(target_os = "linux")]
    {
        // glibc consults /etc/hosts per lookup; there is nothing to reload.
        return vec![Argv::new(["resolvectl", "flush-caches"])];
    }
    #[cfg(not(target_os = "linux"))]
    vec![Argv::optional(["killall", "mDNSResponder"])]
}

/// Is the root installed *and trusted*? Runs unprivileged.
///
/// Both halves are needed, and the second is the one that bites. `security add-trusted-cert`
/// imports the certificate and then writes trust settings; the write needs an authorization
/// that can prompt, and a session which cannot show one — `osascript ... with administrator
/// privileges`, for instance — is refused with "the authorization was denied since no user
/// interaction was possible". The import already happened, so a presence check calls that
/// machine trusted while macOS itself answers `CSSMERR_TP_NOT_TRUSTED` and every
/// Security-framework client (Chromium, and with it an IDE's non-Node traffic) keeps rejecting
/// our leaves. The reference implementation checks both for the same reason
/// (9router `src/mitm/cert/install.js`).
#[cfg(not(windows))]
pub fn unix_is_installed(expected_fingerprint: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        // Asking macOS to evaluate the exact certificate we hold answers both halves at once:
        // a root that is absent, superseded by a rotation, or present-but-untrusted all fail
        // here. Requiring it in *System.keychain* specifically would additionally reject a
        // perfectly good user-domain install, which is the one we can actually perform.
        let _ = expected_fingerprint;
        unix_trust_is_effective()
    }
    #[cfg(not(target_os = "macos"))]
    {
        unix_cert_is_present(expected_fingerprint)
    }
}

/// Does the system actually evaluate our root as a trusted SSL anchor?
///
/// macOS only — it is the one platform that splits "imported" from "trusted"; elsewhere
/// presence is the answer, and `unix_cert_is_present` already covers that.
#[cfg(target_os = "macos")]
fn unix_trust_is_effective() -> bool {
    let Ok(cert) = crate::paths::root_ca_cert() else {
        return false;
    };
    Command::new("security")
        .args([
            "verify-cert",
            "-c",
            &cert.to_string_lossy(),
            "-p",
            "ssl",
            "-k",
            MAC_KEYCHAIN,
        ])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// The certificate bytes we expect, sitting in the system keychain.
#[cfg(all(not(windows), not(target_os = "macos")))]
fn unix_cert_is_present(expected_fingerprint: &str) -> bool {
    let output = Command::new("security")
        .args(["find-certificate", "-a", "-c", ROOT_CN, "-Z", MAC_KEYCHAIN])
        .output();
    let Ok(output) = output else {
        return false;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    // macOS has printed this line as both "SHA-1 hash:" and "SHA-1 Hash:" across releases;
    // match loosely and compare hex digits only.
    text.lines().any(|line| {
        let line = line.trim();
        if !line.to_ascii_lowercase().starts_with("sha-1") {
            return false;
        }
        let Some((_, hash)) = line.split_once(':') else {
            return false;
        };
        let hex: String = hash.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        hex.eq_ignore_ascii_case(expected_fingerprint)
    })
}

// ── Windows ──────────────────────────────────────────────────────────────────

/// `certutil -addstore Root` into the machine store, stale copy removed first (best-effort —
/// absent on a first install, and `certutil` reports that as a failure).
pub fn windows_install(cert_path: &str) -> Vec<Argv> {
    vec![
        Argv::optional(["certutil", "-delstore", "Root", ROOT_CN]),
        Argv::new(["certutil", "-addstore", "Root", cert_path]),
    ]
}

pub fn windows_remove(cn: &str) -> Vec<Argv> {
    vec![Argv::optional(["certutil", "-delstore", "Root", cn])]
}

pub fn windows_flush_dns() -> Vec<Argv> {
    vec![Argv::new(["ipconfig", "/flushdns"])]
}

/// Is the root already in the machine Root store? `certutil -store` returns exit 0 on a hit.
#[cfg(windows)]
pub fn windows_is_installed(expected_fingerprint: &str) -> bool {
    Command::new("certutil")
        .args(["-store", "Root", expected_fingerprint])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Platform-dispatched trust check.
pub fn is_installed(expected_fingerprint: &str) -> bool {
    #[cfg(windows)]
    {
        windows_is_installed(expected_fingerprint)
    }
    #[cfg(not(windows))]
    {
        unix_is_installed(expected_fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_install_deletes_then_adds_with_trustroot() {
        let cmds = unix_install("/path/rootCA.crt");
        assert_eq!(cmds[0].0[1], "delete-certificate");
        assert!(
            cmds[0].1,
            "the stale-delete must tolerate 'not found' on a first install"
        );
        assert!(!cmds[1].1, "the add itself is mandatory");
        assert!(cmds[1].0.contains(&"trustRoot".to_string()));
        assert!(cmds[1].0.contains(&"/path/rootCA.crt".to_string()));
        assert!(cmds[1].0.contains(&MAC_KEYCHAIN.to_string()));
    }

    #[test]
    fn windows_install_targets_the_root_store() {
        let cmds = windows_install("C:\\rootCA.crt");
        assert_eq!(
            cmds[1].0,
            ["certutil", "-addstore", "Root", "C:\\rootCA.crt"]
        );
    }

    #[test]
    fn removal_uses_the_common_name_on_windows_and_fingerprint_on_mac() {
        assert!(windows_remove(ROOT_CN)[0].0.contains(&ROOT_CN.to_string()));
        assert_eq!(unix_remove("AABB")[0].0[2], "-Z");
    }
}
