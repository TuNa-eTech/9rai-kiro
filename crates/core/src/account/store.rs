//! Persistence for the Kiro account pool.
//!
//! The pool lives in its own `accounts.json` (0600) beside `config.json`, never inside the
//! provider config: credentials are the one thing a user may want to back up or wipe without
//! touching the provider/mappings the MITM engine reads every request.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{KiroAccount, AccountStatus};
use crate::{paths, Error, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountStore {
    #[serde(default)]
    pub accounts: Vec<KiroAccount>,
}

impl AccountStore {
    pub fn path() -> Result<PathBuf> {
        Ok(paths::data_dir()?.join("accounts.json"))
    }

    /// Load from disk, or an empty pool if absent.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(Error::from),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    /// Persist with 0600 from creation — the file holds refresh tokens and API keys.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        paths::ensure_dir(&paths::data_dir()?)?;
        let json = serde_json::to_vec_pretty(self)?;
        paths::write_private(&path, &json)
    }

    pub fn list(&self) -> impl Iterator<Item = &KiroAccount> {
        self.accounts.iter()
    }

    pub fn get_by_label(&self, label: &str) -> Option<&KiroAccount> {
        self.accounts.iter().find(|a| a.label == label)
    }

    pub fn upsert(&mut self, account: KiroAccount) {
        match self
            .accounts
            .iter_mut()
            .find(|a| a.id == account.id || a.label == account.label)
        {
            Some(slot) => *slot = account,
            None => self.accounts.push(account),
        }
    }

    pub fn remove_by_label(&mut self, label: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.label != label);
        self.accounts.len() != before
    }

    /// Active accounts only — the pool an auto-switch may draw from.
    pub fn active(&self) -> Vec<&KiroAccount> {
        self.accounts
            .iter()
            .filter(|a| a.status == AccountStatus::Active)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::KiroCredential;

    fn account(label: &str) -> KiroAccount {
        KiroAccount {
            id: format!("id-{label}"),
            label: label.into(),
            email: format!("{label}@example.com"),
            status: AccountStatus::Active,
            credit_total: 1000.0,
            credit_used: 0.0,
            cycle_reset_at: None,
            last_used_at: None,
            credential: KiroCredential {
                access_token: "at".into(),
                refresh_token: "rt".into(),
                expires_at: "".into(),
                region: "us-east-1".into(),
                auth_method: "IdC".into(),
                provider: "Enterprise".into(),
                client_id: "cid".into(),
                client_secret: "cs".into(),
                client_id_hash: "".into(),
                profile_arn: "".into(),
                start_url: "".into(),
            },
        }
    }

    #[test]
    fn upsert_by_label_replaces_in_place() {
        let mut store = AccountStore::default();
        store.upsert(account("a"));
        store.upsert(account("b"));
        assert_eq!(store.accounts.len(), 2);

        let mut changed = account("a");
        changed.credit_used = 500.0;
        store.upsert(changed);
        assert_eq!(store.accounts.len(), 2);
        assert_eq!(store.get_by_label("a").unwrap().credit_used, 500.0);
    }

    #[test]
    fn active_filters_out_exhausted() {
        let mut store = AccountStore::default();
        store.upsert(account("a"));
        let mut dead = account("b");
        dead.status = AccountStatus::Exhausted;
        store.upsert(dead);

        assert_eq!(store.active().len(), 1);
        assert_eq!(store.active()[0].label, "a");
    }
}
