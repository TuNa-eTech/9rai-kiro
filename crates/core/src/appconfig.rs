//! Persisted application configuration: the provider credentials and the model map.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::mapping::ModelMap;
use crate::provider::ProviderConfig;
use crate::{paths, Error, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub provider: ProviderConfig,
    #[serde(default)]
    pub mappings: ModelMap,
}

impl AppConfig {
    pub fn path() -> Result<PathBuf> {
        Ok(paths::data_dir()?.join("config.json"))
    }

    /// Load from disk, or return defaults if absent.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(Error::from),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    /// Persist with 0600 from creation — the file holds the provider API key.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        paths::ensure_dir(&paths::data_dir()?)?;
        let json = serde_json::to_vec_pretty(self)?;
        paths::write_private(&path, &json)
    }
}
