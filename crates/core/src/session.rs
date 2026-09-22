//! Turning interception on and off: staging the hosts file and describing the privileged batch.
//!
//! Both the CLI daemon and (later) the desktop app call these, so the sequence of privileged
//! operations is defined in exactly one place. File contents are staged to a normal-user temp
//! path; the privileged batch only copies a prepared file into place.

use std::path::PathBuf;

use crate::cert::CertStore;
use crate::config::Tool;
use crate::privilege::PrivOp;
use crate::{hosts, paths, Error, Result};

fn kiro_hosts() -> Vec<&'static str> {
    Tool::Kiro.hosts().to_vec()
}

fn read_hosts() -> Result<String> {
    let path = paths::hosts_file();
    std::fs::read_to_string(path).map_err(|e| Error::io(path, e))
}

fn stage(contents: &str) -> Result<PathBuf> {
    let dir = paths::data_dir()?;
    paths::ensure_dir(&dir)?;
    let staged = dir.join("hosts.staged");
    std::fs::write(&staged, contents).map_err(|e| Error::io(&staged, e))?;
    // The daemon stages this as root; keep it owned by the invoking user.
    paths::chown_to_real_user(&staged);
    Ok(staged)
}

/// The privileged batch that enables interception: point Node clients at our root, redirect
/// the hosts, flush DNS.
pub fn enable_ops(store: &CertStore) -> Result<Vec<PrivOp>> {
    let hosts = kiro_hosts();
    let staged = stage(&hosts::apply(&read_hosts()?, &hosts))?;
    Ok(enable_ops_for(store.root_cert_path()?, staged))
}

/// The batch itself, without the IO, so its shape is testable.
///
/// Installing the root into the system trust store is deliberately *not* here. That write needs
/// an authorization prompt this session may have no way to show, and the batch is all-or-
/// nothing: one refused trust-settings write would abort an otherwise healthy startup — on a
/// machine that still works for every client reading `NODE_EXTRA_CA_CERTS`. Trusting the root
/// is therefore a separate, best-effort step the caller runs first, and these three are what
/// interception actually consists of.
fn enable_ops_for(cert: PathBuf, staged: PathBuf) -> Vec<PrivOp> {
    vec![
        PrivOp::SetNodeCaEnv { cert },
        PrivOp::InstallHosts {
            staged,
            target: paths::hosts_file().to_path_buf(),
        },
        PrivOp::FlushDns,
    ]
}

/// Is the machine still redirected, i.e. did something leave our block in the hosts file?
pub fn hosts_are_redirected() -> Result<bool> {
    Ok(hosts::is_applied(&read_hosts()?))
}

/// The hijacked hosts the *system resolver* is not yet sending to us.
///
/// Writing `/etc/hosts` and having the OS honour it are two different things (see
/// [`crate::cert::trust::unix_reload_resolver`]), and the difference is invisible: every step
/// of the enable batch succeeds, the proxy binds :443, and the IDE goes on talking to AWS. This
/// asks the same question the IDE's own connect will ask — `getaddrinfo` — and is the only
/// honest confirmation that interception is live.
pub fn hosts_not_hijacked() -> Vec<String> {
    kiro_hosts()
        .iter()
        .filter(|host| !resolves_to_loopback(host))
        .map(|host| host.to_string())
        .collect()
}

fn resolves_to_loopback(host: &str) -> bool {
    use std::net::ToSocketAddrs;

    match (host, 443u16).to_socket_addrs() {
        // Every answer must be ours: one real address left in the list is one the IDE may pick.
        Ok(mut addrs) => addrs.all(|addr| addr.ip().is_loopback()),
        // A name that resolves nowhere is not reaching the real service either. Don't fail a
        // startup over a DNS outage we are not responsible for.
        Err(_) => true,
    }
}

/// The privileged batch that disables interception: restore the hosts and flush DNS.
///
/// The CA is intentionally left trusted — repeated enable/disable cycles should not re-prompt,
/// and an untrusted-CA teardown belongs to an explicit uninstall. `NODE_EXTRA_CA_CERTS` follows
/// the same lifetime, and must: a process reads it once at startup and never again, so
/// withdrawing it here poisons every helper the IDE happens to spawn while the proxy is off —
/// they come back without it and reject our certificate on the next enable, with only a full
/// IDE restart to cure them. It is withdrawn by [`uninstall_ops`], where the root it points at
/// is untrusted too.
pub fn disable_ops() -> Result<Vec<PrivOp>> {
    let staged = stage(&hosts::strip(&read_hosts()?))?;
    Ok(vec![
        PrivOp::InstallHosts {
            staged,
            target: paths::hosts_file().to_path_buf(),
        },
        PrivOp::FlushDns,
    ])
}

/// The privileged batch that fully removes trust — used by an explicit uninstall.
pub fn uninstall_ops(store: &CertStore) -> Result<Vec<PrivOp>> {
    let mut ops = disable_ops()?;
    ops.push(PrivOp::RemoveCa {
        cn: crate::cert::gen::ROOT_CN.to_string(),
        fingerprint: store.fingerprint().to_string(),
    });
    // The root is going away, so nothing should keep pointing Node clients at it.
    ops.push(PrivOp::UnsetNodeCaEnv);
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(ops: &[PrivOp]) -> Vec<&'static str> {
        ops.iter()
            .map(|op| match op {
                PrivOp::InstallCa { .. } => "install-ca",
                PrivOp::InstallHosts { .. } => "install-hosts",
                PrivOp::RemoveCa { .. } => "remove-ca",
                PrivOp::FlushDns => "flush-dns",
                PrivOp::ReloadResolver => "reload-resolver",
                PrivOp::SetNodeCaEnv { .. } => "set-node-ca-env",
                PrivOp::UnsetNodeCaEnv => "unset-node-ca-env",
            })
            .collect()
    }

    #[test]
    fn turning_interception_off_leaves_node_clients_trusting_our_root() {
        // Reading the hosts file is enough of a side effect to keep this honest about the
        // machine it runs on; the op list is what matters.
        let ops = disable_ops().expect("/etc/hosts is readable");
        assert!(
            !kinds(&ops).contains(&"unset-node-ca-env"),
            "a helper spawned while the proxy is off would come back without the variable and \
reject our certificate for the rest of its life"
        );
    }

    #[test]
    fn loopback_detection_answers_the_question_getaddrinfo_would() {
        assert!(
            resolves_to_loopback("localhost"),
            "localhost is the one name every machine points at itself"
        );
        assert!(
            resolves_to_loopback("9rai-does-not-exist.invalid"),
            "a name that resolves nowhere is not reaching the real service either"
        );
    }

    #[test]
    fn enabling_never_risks_the_startup_on_a_trust_store_write() {
        let ops = enable_ops_for("/ca/rootCA.crt".into(), "/staged/hosts".into());
        assert_eq!(kinds(&ops), ["set-node-ca-env", "install-hosts", "flush-dns"]);
        assert!(
            !kinds(&ops).contains(&"install-ca"),
            "a refused trust-settings write would abort a startup that is otherwise fine"
        );
    }
}
