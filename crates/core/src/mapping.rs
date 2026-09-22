//! Kiro model id -> provider model.
//!
//! A miss is not an error: an unmapped model means "leave this conversation alone", and the
//! router passes it through to the real upstream untouched.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelMap {
    /// Exact `modelId` -> provider model name.
    #[serde(default)]
    pub models: HashMap<String, String>,
    /// Applied when no exact entry matches. `None` means "pass through".
    #[serde(default)]
    pub default: Option<String>,
}

impl ModelMap {
    pub fn resolve(&self, model_id: &str) -> Option<&str> {
        self.models
            .get(model_id)
            .map(String::as_str)
            .or(self.default.as_deref())
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty() && self.default.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> ModelMap {
        ModelMap {
            models: HashMap::from([("auto".to_string(), "gpt-4o".to_string())]),
            default: None,
        }
    }

    #[test]
    fn exact_match_wins() {
        assert_eq!(map().resolve("auto"), Some("gpt-4o"));
    }

    #[test]
    fn unmapped_without_a_default_means_passthrough() {
        assert_eq!(map().resolve("claude-sonnet-4"), None);
    }

    #[test]
    fn default_catches_everything_else() {
        let mut m = map();
        m.default = Some("fallback".into());
        assert_eq!(m.resolve("anything"), Some("fallback"));
        assert_eq!(m.resolve("auto"), Some("gpt-4o"));
    }
}
