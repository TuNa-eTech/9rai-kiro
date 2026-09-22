//! Where local state lives, per platform.
//!
//! One subtlety drives most of this module: the daemon runs as **root** on macOS (port 443
//! requires it), but the config, CA and staged files belong to the *invoking* user. If we let
//! `dirs::data_dir()` follow the effective uid, `sudo 9rai daemon` would read root's
//! `/var/root/...` config while `9rai config` writes the user's `~/Library/...` — the two
//! sides would never see the same state, and files the daemon wrote would be root-owned and
//! unreadable back. So when euid is 0 we resolve the invoking user (sudo env, doas env, or the
//! console owner for osascript elevation) and use *their* data dir, chowning everything back.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// `~/Library/Application Support/9rai` (macOS) or `%APPDATA%\9rai` (Windows), resolved for
/// the invoking user rather than the (possibly root) effective uid.
pub fn data_dir() -> Result<PathBuf> {
    #[cfg(unix)]
    if let Some(user) = real_user() {
        return Ok(user.data_root().join("9rai"));
    }
    let base = dirs::data_dir()
        .ok_or_else(|| Error::Cert("cannot resolve platform data directory".into()))?;
    Ok(base.join("9rai"))
}

pub fn cert_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("cert"))
}

pub fn root_ca_cert() -> Result<PathBuf> {
    Ok(cert_dir()?.join("rootCA.crt"))
}

pub fn root_ca_key() -> Result<PathBuf> {
    Ok(cert_dir()?.join("rootCA.key"))
}

pub fn log_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("logs"))
}

/// The OS hosts file.
pub fn hosts_file() -> &'static Path {
    #[cfg(windows)]
    {
        Path::new(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        Path::new("/etc/hosts")
    }
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
    chown_to_real_user(path);
    Ok(())
}

/// Write a file that holds secrets (CA key, config with API key) with 0600 **at creation
/// time** — not a chmod after the fact, which would leave a default-umask window. The JS
/// reference leaves its root key world-readable; this closes that (FIX 8).
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::io(path, e))?;
        file.write_all(contents).map_err(|e| Error::io(path, e))?;
        // An existing file keeps its old mode; force it in case we just truncated one.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(path, e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).map_err(|e| Error::io(path, e))?;
    }
    chown_to_real_user(path);
    Ok(())
}

/// The uid of the GUI session user, when we are root on their behalf.
///
/// `None` means "we are that user already", so a `launchctl` call needs no `asuser` hop.
pub fn gui_user_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        real_user().map(|user| user.uid)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Hand `path` back to the invoking (non-root) user. No-op when not running as root via an
/// elevation mechanism, and on non-Unix.
pub fn chown_to_real_user(path: &Path) {
    #[cfg(unix)]
    if let Some(user) = real_user() {
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
            return;
        };
        // Best effort: a failure here only means the user may need sudo to delete the file.
        unsafe { libc::chown(c_path.as_ptr(), user.uid, user.gid) };
    }
    #[cfg(not(unix))]
    let _ = path;
}

// ── Invoking-user resolution (Unix only) ─────────────────────────────────────

#[cfg(unix)]
#[derive(Debug, Clone)]
struct RealUser {
    name: String,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl RealUser {
    #[cfg(target_os = "macos")]
    fn data_root(&self) -> PathBuf {
        Path::new("/Users")
            .join(&self.name)
            .join("Library/Application Support")
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn data_root(&self) -> PathBuf {
        home_of(&self.name).join(".local/share")
    }
}

/// Who asked for this process to run, when we are root? `None` means "we are a normal
/// unprivileged process" (or we cannot tell), in which case the euid-based default is correct.
/// Memoized: `data_dir` is called from several modules and detection spawns subprocesses.
#[cfg(unix)]
fn real_user() -> Option<&'static RealUser> {
    static USER: std::sync::LazyLock<Option<RealUser>> = std::sync::LazyLock::new(detect_real_user);
    USER.as_ref()
}

#[cfg(unix)]
fn detect_real_user() -> Option<RealUser> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    if let Ok(name) = std::env::var("SUDO_USER") {
        if !name.is_empty() && name != "root" {
            let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
            let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
            return Some(RealUser { name, uid, gid });
        }
    }
    if let Ok(name) = std::env::var("DOAS_USER") {
        if !name.is_empty() && name != "root" {
            let uid = id_of(&name, "-u")?;
            let gid = id_of(&name, "-g")?;
            return Some(RealUser { name, uid, gid });
        }
    }
    // macOS-only fallback. `osascript ... with administrator privileges` (how the GUI
    // elevates) does not set SUDO_*; the console owner is the logged-in GUI user.
    #[cfg(target_os = "macos")]
    let from_console = console_user();
    #[cfg(not(target_os = "macos"))]
    let from_console = None;
    from_console
}

/// The user owning `/dev/console` — i.e. the GUI session owner. macOS only.
#[cfg(target_os = "macos")]
fn console_user() -> Option<RealUser> {
    let name = std::process::Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;
    if name.is_empty() || name == "root" {
        return None;
    }
    let uid = id_of(&name, "-u")?;
    let gid = id_of(&name, "-g")?;
    Some(RealUser { name, uid, gid })
}

#[cfg(unix)]
fn id_of(name: &str, flag: &str) -> Option<u32> {
    let out = std::process::Command::new("id")
        .args([flag, name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn home_of(name: &str) -> PathBuf {
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let mut fields = line.split(':');
            if fields.next() == Some(name) {
                if let Some(home) = line.split(':').nth(5) {
                    let home = PathBuf::from(home);
                    if home.is_dir() {
                        return home;
                    }
                }
            }
        }
    }
    Path::new("/home").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_creates_files_with_0600_from_the_start() {
        let dir = std::env::temp_dir().join(format!("9rai-paths-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret");
        // A permissive umask must not leak through.
        write_private(&file, b"key material").unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be owner-only, got {mode:o}");

        // Rewriting an existing file also keeps 0600.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&file, b"rotated").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn data_dir_is_inside_a_platform_location() {
        let dir = data_dir().unwrap();
        assert!(
            dir.ends_with("9rai"),
            "unexpected data dir {}",
            dir.display()
        );
    }
}
