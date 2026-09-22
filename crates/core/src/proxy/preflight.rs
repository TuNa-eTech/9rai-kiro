//! Binding port 443 on loopback, with a friendly diagnosis when something already holds it.
//!
//! Two constraints shape this module. First, the hosts file maps Kiro's domains to **both**
//! `127.0.0.1` and `::1`, so the listener must exist on both loopback stacks — a client that
//! resolves AAAA first must not get a connection-refused. Second, we bind *only* loopback:
//! binding `0.0.0.0` would expose a cert-minting MITM listener to the whole LAN.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::net::TcpListener;

use crate::{Error, Result};

/// Bind both loopback stacks. IPv6 failure degrades to a warning (a v4-only host is legal);
/// an IPv4 failure is fatal, and port conflicts name the squatter when we can find it.
pub async fn bind_loopback(port: u16) -> Result<Vec<TcpListener>> {
    let v4 = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let owner = port_owner(port).unwrap_or_else(|| "unknown process".into());
            return Err(Error::Provider(format!(
                "port {port} is already in use by {owner}; stop it and retry"
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(Error::Elevation(format!(
                "binding port {port} requires elevated privileges"
            )));
        }
        Err(e) => return Err(Error::Provider(format!("bind 127.0.0.1:{port}: {e}"))),
    };

    let v6 = match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
        Ok(listener) => Some(listener),
        Err(e) => {
            tracing::warn!(error = %e, "IPv6 loopback unavailable; serving IPv4 only");
            None
        }
    };

    Ok(std::iter::once(v4).chain(v6).collect())
}

/// Best-effort identification of whatever is listening on `port`.
#[cfg(not(windows))]
fn port_owner(port: u16) -> Option<String> {
    let pids = std::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .ok()?;
    let pid = String::from_utf8_lossy(&pids.stdout)
        .split_whitespace()
        .next()?
        .to_string();
    let comm = std::process::Command::new("ps")
        .args(["-p", &pid, "-o", "comm="])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&comm.stdout).trim().to_string();
    Some(format!("{name} (pid {pid})"))
}

#[cfg(windows)]
fn port_owner(port: u16) -> Option<String> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetTCPConnection -LocalPort {port} -State Listen | \
                 Select-Object -First 1 -ExpandProperty OwningProcess | \
                 ForEach-Object {{ (Get-Process -Id $_).ProcessName }})"
            ),
        ])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!name.is_empty()).then_some(name)
}
