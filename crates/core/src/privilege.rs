//! Privileged operations and how they are rendered to OS commands.
//!
//! Two ideas keep this testable and safe. First, every privileged action is a [`PrivOp`] value,
//! rendered to concrete argv by pure functions ([`render_unix`] / [`render_windows`]) that unit
//! tests can assert on without touching the machine. Second, a whole batch is elevated **once** —
//! one `osascript` auth dialog on macOS, one UAC prompt on Windows — rather than prompting per
//! action. We never capture, store, or transport the user's password (the reference persists an
//! AES-encrypted sudo password; this design deliberately does not).

use std::path::PathBuf;

use crate::cert::trust;
use crate::{Error, Result};

/// One privileged step. File contents are staged to a temp path by the unprivileged caller, so
/// the privileged batch only ever copies a prepared file into place — never edits in place.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PrivOp {
    /// Replace the hosts file with the already-rendered contents at `staged`.
    InstallHosts { staged: PathBuf, target: PathBuf },
    /// Trust the root CA whose PEM is at `cert`.
    InstallCa { cert: PathBuf },
    /// Untrust the root CA identified by common name and SHA-1 fingerprint.
    RemoveCa { cn: String, fingerprint: String },
    /// Drop the OS DNS cache so the hosts change takes effect immediately.
    FlushDns,
    /// Force the system resolver to re-read the hosts file. Stronger (and more disruptive)
    /// than [`PrivOp::FlushDns`]; used only when a flush demonstrably was not enough.
    ReloadResolver,
    /// Publish `NODE_EXTRA_CA_CERTS` into the desktop session so Node-based clients (Kiro's
    /// agent among them) trust our root; they ignore the OS trust store.
    SetNodeCaEnv { cert: PathBuf },
    /// Withdraw it again, so nothing keeps trusting a root we have stopped using.
    UnsetNodeCaEnv,
}

/// A single command to run: `.0` is the argv, `.1` says whether a non-zero exit is tolerated.
///
/// Tolerated failures exist for the "delete stale copy" steps: on a first install there is
/// nothing to delete, and `security` / `certutil` report that as an error — which must not
/// abort the batch that is about to install the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argv(pub Vec<String>, pub bool);

impl Argv {
    pub(crate) fn new<I, S>(parts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Argv(parts.into_iter().map(Into::into).collect(), false)
    }

    /// A command whose failure is not a failure of the batch.
    pub(crate) fn optional<I, S>(parts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Argv(parts.into_iter().map(Into::into).collect(), true)
    }

    pub fn program(&self) -> &str {
        self.0.first().map(String::as_str).unwrap_or_default()
    }

    pub fn args(&self) -> &[String] {
        self.0.get(1..).unwrap_or(&[])
    }

    /// The command as a user would type it, for logs and error messages. A part containing a
    /// space is quoted, so `.../Application Support/...` reads as one argument rather than two.
    pub fn display(&self) -> String {
        self.0
            .iter()
            .map(|part| {
                if part.contains(' ') {
                    format!("\"{part}\"")
                } else {
                    part.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What a bare non-zero exit most likely means. `security` and `certutil` report a refused
/// write as an exit code and nothing else, so without this a log line reads only
/// "exited with 1" and every diagnosis starts from scratch.
fn failure_hint() -> &'static str {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        return " — this process is not root, so the trust store and /etc/hosts are read-only \
to it; run the batch under `sudo` or through the GUI's authorization prompt";
    }
    ""
}

/// Render one op to the macOS/Unix commands that carry it out.
pub fn render_unix(op: &PrivOp) -> Vec<Argv> {
    match op {
        PrivOp::InstallHosts { staged, target } => vec![
            Argv::new(["cp", &staged.to_string_lossy(), &target.to_string_lossy()]),
            Argv::new(["chmod", "644", &target.to_string_lossy()]),
        ],
        PrivOp::InstallCa { cert } => trust::unix_install(&cert.to_string_lossy()),
        PrivOp::RemoveCa { fingerprint, .. } => trust::unix_remove(fingerprint),
        PrivOp::FlushDns => trust::unix_flush_dns(),
        PrivOp::ReloadResolver => trust::unix_reload_resolver(),
        PrivOp::SetNodeCaEnv { cert } => trust::unix_set_node_ca(&cert.to_string_lossy()),
        PrivOp::UnsetNodeCaEnv => trust::unix_unset_node_ca(),
    }
}

/// Render one op to the Windows commands that carry it out.
pub fn render_windows(op: &PrivOp) -> Vec<Argv> {
    match op {
        PrivOp::InstallHosts { staged, target } => vec![Argv::new([
            "cmd",
            "/C",
            "copy",
            "/Y",
            &staged.to_string_lossy(),
            &target.to_string_lossy(),
        ])],
        PrivOp::InstallCa { cert } => trust::windows_install(&cert.to_string_lossy()),
        PrivOp::RemoveCa { cn, .. } => trust::windows_remove(cn),
        PrivOp::FlushDns => trust::windows_flush_dns(),
        // Windows reads the hosts file per lookup; a cache flush is the whole story.
        PrivOp::ReloadResolver => trust::windows_flush_dns(),
        PrivOp::SetNodeCaEnv { cert } => trust::windows_set_node_ca(&cert.to_string_lossy()),
        PrivOp::UnsetNodeCaEnv => trust::windows_unset_node_ca(),
    }
}

/// Render a whole batch to the argv list for the current platform.
pub fn render(ops: &[PrivOp]) -> Vec<Argv> {
    ops.iter()
        .flat_map(|op| {
            if cfg!(windows) {
                render_windows(op)
            } else {
                render_unix(op)
            }
        })
        .collect()
}

/// Reject anything that is not exactly the batch shape this app produces. The hidden
/// `9rai elevated` entry point runs with Administrator rights and takes its ops from the
/// command line — without this check, any local process that can talk a user into approving
/// a UAC/osascript prompt could use us to overwrite arbitrary files or install a foreign CA.
pub fn validate(ops: &[PrivOp]) -> Result<()> {
    for op in ops {
        match op {
            PrivOp::InstallHosts { staged, target } => {
                if target.as_path() != crate::paths::hosts_file() {
                    return Err(Error::Elevation(format!(
                        "refusing to write non-hosts target {}",
                        target.display()
                    )));
                }
                let data = crate::paths::data_dir()?;
                if !staged.starts_with(&data) {
                    return Err(Error::Elevation(format!(
                        "refusing staged file {} outside {}",
                        staged.display(),
                        data.display()
                    )));
                }
            }
            PrivOp::InstallCa { cert } => {
                if *cert != crate::paths::root_ca_cert()? {
                    return Err(Error::Elevation(
                        "refusing to install a CA that is not our own root".into(),
                    ));
                }
            }
            PrivOp::RemoveCa { cn, .. } => {
                if cn != crate::cert::gen::ROOT_CN {
                    return Err(Error::Elevation(format!(
                        "refusing to remove foreign CA {cn:?}"
                    )));
                }
            }
            // Publishing an environment variable that points every Node client at a
            // certificate is as sensitive as installing that certificate — same check.
            PrivOp::SetNodeCaEnv { cert } => {
                if *cert != crate::paths::root_ca_cert()? {
                    return Err(Error::Elevation(
                        "refusing to advertise a CA that is not our own root".into(),
                    ));
                }
            }
            PrivOp::FlushDns | PrivOp::ReloadResolver | PrivOp::UnsetNodeCaEnv => {}
        }
    }
    Ok(())
}

/// Executes a batch of privileged ops.
pub trait Privileged {
    fn run(&self, ops: &[PrivOp]) -> Result<()>;
}

/// Runs each command directly, assuming the process is already privileged. This is what the
/// hidden `9rai elevated` subcommand uses after the OS has elevated it.
pub struct DirectExecutor;

impl Privileged for DirectExecutor {
    fn run(&self, ops: &[PrivOp]) -> Result<()> {
        // Trust-store automation is only implemented for macOS and Windows. On Linux the
        // rendered commands would be macOS keychain invocations; fail loudly instead.
        #[cfg(all(unix, not(target_os = "macos")))]
        if ops
            .iter()
            .any(|op| matches!(op, PrivOp::InstallCa { .. } | PrivOp::RemoveCa { .. }))
        {
            return Err(Error::NotImplemented(
                "trust-store automation on Linux (install the root CA manually)",
            ));
        }
        for argv in render(ops) {
            // Log before running, at info: when a step fails, this is the only record of what
            // the OS was actually asked to do — the commands carry no secrets.
            tracing::info!(command = %argv.display(), "privileged step");
            let status = std::process::Command::new(argv.program())
                .args(argv.args())
                .status()
                .map_err(|e| {
                    Error::Elevation(format!("spawning `{}` failed: {e}", argv.display()))
                })?;
            if !status.success() {
                if argv.1 {
                    // Best-effort step (e.g. deleting a stale cert that is not there yet).
                    // Logged at info, not debug: it explains stderr noise like `security`'s
                    // "Unable to delete certificate matching ..." that is *not* the failure.
                    tracing::info!(
                        command = %argv.display(),
                        %status,
                        "best-effort step failed; continuing"
                    );
                    continue;
                }
                tracing::error!(command = %argv.display(), %status, "privileged step failed");
                return Err(Error::Elevation(format!(
                    "`{}` exited with {status}{}",
                    argv.display(),
                    failure_hint()
                )));
            }
        }
        Ok(())
    }
}

/// Records ops instead of running them — for tests and dry runs.
#[derive(Debug, Default)]
pub struct RecordingExecutor {
    pub ops: std::sync::Mutex<Vec<PrivOp>>,
}

impl Privileged for RecordingExecutor {
    fn run(&self, ops: &[PrivOp]) -> Result<()> {
        self.ops.lock().unwrap().extend_from_slice(ops);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_install_stages_a_copy_rather_than_editing_in_place() {
        let op = PrivOp::InstallHosts {
            staged: "/tmp/hosts.new".into(),
            target: "/etc/hosts".into(),
        };
        let cmds = render_unix(&op);
        assert_eq!(cmds[0], Argv::new(["cp", "/tmp/hosts.new", "/etc/hosts"]));
        assert_eq!(cmds[1].program(), "chmod");
    }

    #[test]
    fn the_node_ca_variable_is_published_best_effort_and_validated() {
        let cmds = render(&[PrivOp::SetNodeCaEnv {
            cert: "/ca/rootCA.crt".into(),
        }]);
        #[cfg(target_os = "macos")]
        {
            assert_eq!(cmds.len(), 1);
            assert_eq!(cmds[0].program(), "launchctl");
            assert!(cmds[0].0.contains(&"NODE_EXTRA_CA_CERTS".to_string()));
            assert_eq!(cmds[0].0.last().unwrap(), "/ca/rootCA.crt");
            assert!(
                cmds[0].1,
                "a machine with no GUI session must not fail the batch"
            );
        }
        let _ = cmds;

        // The variable makes every Node client trust whatever it points at, so it is held to
        // the same rule as the trust store itself.
        assert!(validate(&[PrivOp::SetNodeCaEnv {
            cert: "/tmp/somebody-elses-ca.crt".into(),
        }])
        .is_err());
        validate(&[PrivOp::UnsetNodeCaEnv]).expect("withdrawing it is always allowed");
    }

    #[test]
    fn reloading_the_resolver_is_a_tolerated_restart() {
        let cmds = render(&[PrivOp::ReloadResolver]);
        assert_eq!(cmds.len(), 1);
        assert!(
            cmds[0].1,
            "a resolver that is not running is not a reason to fail the batch"
        );
        #[cfg(target_os = "macos")]
        assert_eq!(cmds[0].0, ["killall", "mDNSResponder"]);
        // It carries no paths or names, so it is always safe to run elevated.
        validate(&[PrivOp::ReloadResolver]).expect("the reload op needs no validation");
    }

    #[test]
    fn display_quotes_arguments_that_contain_spaces() {
        let argv = Argv::new(["cp", "/tmp/a b/hosts.staged", "/etc/hosts"]);
        assert_eq!(
            argv.display(),
            "cp \"/tmp/a b/hosts.staged\" /etc/hosts",
            "an unquoted path with a space would read as two arguments in the log"
        );
    }

    #[test]
    fn recording_executor_captures_without_side_effects() {
        let exec = RecordingExecutor::default();
        exec.run(&[PrivOp::FlushDns]).unwrap();
        assert_eq!(exec.ops.lock().unwrap().len(), 1);
    }
}
