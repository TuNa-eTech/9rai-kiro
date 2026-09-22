//! Test-only helper: point `$HOME` at a scratch directory.
//!
//! Config, CA and daemon-session paths all resolve from the data dir, so without this a test
//! would write into the developer's real state. `$HOME` is process-wide, hence the lock.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

static HOME_LOCK: Mutex<()> = Mutex::new(());

pub struct ScratchHome {
    _lock: MutexGuard<'static, ()>,
    previous: Option<OsString>,
}

impl ScratchHome {
    /// Take the lock, repoint `$HOME`, and hand back a guard plus the directory in use.
    pub fn new(tag: &str) -> (Self, PathBuf) {
        let lock = HOME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!("9rai-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch home");
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
