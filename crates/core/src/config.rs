//! Which hosts we hijack, and how to tell an interceptable chat turn from everything else.

use std::fmt;

/// Hosts written to the system hosts file as `127.0.0.1` when interception is on.
pub const TOOL_HOSTS: &[(Tool, &[&str])] = &[(
    Tool::Kiro,
    &[
        "runtime.us-east-1.kiro.dev",
        "q.us-east-1.amazonaws.com",
        "codewhisperer.us-east-1.amazonaws.com",
    ],
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    Kiro,
}

impl Tool {
    pub fn hosts(self) -> &'static [&'static str] {
        TOOL_HOSTS
            .iter()
            .find(|(t, _)| *t == self)
            .map(|(_, h)| *h)
            .unwrap_or(&[])
    }

    /// Map a `Host:` header (port stripped) back to the tool that owns it.
    pub fn from_host(host: &str) -> Option<Self> {
        let bare = host.split(':').next().unwrap_or(host);
        TOOL_HOSTS
            .iter()
            .find(|(_, hosts)| hosts.contains(&bare))
            .map(|(t, _)| *t)
    }
}

impl fmt::Display for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tool::Kiro => f.write_str("kiro"),
        }
    }
}

/// Model ids Kiro's agent actually sends, in the form they appear in the request body.
///
/// Ported from the reference 9router MITM configuration (verified against request dumps of
/// `generateAssistantResponse`): the agent/"vibe" mode sends `auto` for the main turn and
/// `simple-task` for background sub-tasks, and the others appear when the user picks a model
/// in the IDE picker. Both `auto` and `simple-task` must stay mappable — an unmapped id is
/// passed through to AWS untouched, which silently defeats interception.
pub const KIRO_MODEL_SLOTS: &[(&str, &str)] = &[
    ("auto", "Auto (Kiro Agent)"),
    ("claude-sonnet-5", "Claude Sonnet 5"),
    ("claude-sonnet-4.5", "Claude Sonnet 4.5"),
    ("claude-sonnet-4", "Claude Sonnet 4"),
    ("claude-haiku-4.5", "Claude Haiku 4.5"),
    ("deepseek-3.2", "DeepSeek 3.2"),
    ("minimax-m2.1", "MiniMax M2.1"),
    ("gpt-5.6-sol", "GPT 5.6 Sol"),
    ("gpt-5.6-terra", "GPT 5.6 Terra"),
    ("gpt-5.6-luna", "GPT 5.6 Luna"),
    ("simple-task", "Simple Task (background sub-tasks)"),
];

/// Port we bind locally. Must be 443 — the hosts-file hijack gives us no way to change
/// the port the client dials.
pub const LISTEN_PORT: u16 = 443;

/// Resolver used for passthrough. The system resolver is unusable while our hosts entries
/// are installed, since every target host points back at us.
pub const UPSTREAM_DNS: &str = "8.8.8.8:53";

/// Is this request the chat turn we want to take over?
///
/// Kiro Runtime moved `GenerateAssistantResponse` off the legacy path and onto
/// `POST /` + `x-amz-target`. Both forms are still seen in the wild depending on IDE version.
pub fn is_chat_request(tool: Tool, path: &str, amz_target: Option<&str>) -> bool {
    match tool {
        Tool::Kiro => {
            path.contains("/generateAssistantResponse")
                || amz_target.is_some_and(|t| t.contains("GenerateAssistantResponse"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_hosts_and_ignores_others() {
        assert_eq!(
            Tool::from_host("runtime.us-east-1.kiro.dev"),
            Some(Tool::Kiro)
        );
        assert_eq!(
            Tool::from_host("q.us-east-1.amazonaws.com:443"),
            Some(Tool::Kiro)
        );
        assert_eq!(Tool::from_host("example.com"), None);
    }

    #[test]
    fn detects_both_legacy_path_and_amz_target_forms() {
        assert!(is_chat_request(
            Tool::Kiro,
            "/generateAssistantResponse",
            None
        ));
        assert!(is_chat_request(
            Tool::Kiro,
            "/",
            Some("KiroRuntimeService.GenerateAssistantResponse")
        ));
        assert!(!is_chat_request(
            Tool::Kiro,
            "/",
            Some("KiroRuntimeService.ListAvailableModels")
        ));
        assert!(!is_chat_request(Tool::Kiro, "/telemetry", None));
    }

    #[test]
    fn kiro_model_slots_are_unique_and_cover_agent_modes() {
        let mut seen = std::collections::HashSet::new();
        for (id, name) in KIRO_MODEL_SLOTS {
            assert!(!name.is_empty(), "slot `{id}` needs a display name");
            assert!(seen.insert(*id), "duplicate slot id `{id}`");
        }
        // The agent's main turn and its background sub-tasks are the two ids the IDE sends
        // without the user touching the picker; losing either would silently pass those
        // turns through to AWS.
        assert!(seen.contains("auto"));
        assert!(seen.contains("simple-task"));
    }
}
