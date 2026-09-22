//! Request classification: intercept, pass through, or answer the health probe.

use crate::config::{is_chat_request, Tool};
use crate::mapping::ModelMap;
use crate::types::cw;

pub const HEALTH_PATH: &str = "/_mitm_health";

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Local liveness probe.
    Health,
    /// Translate this chat turn to the provider and target this mapped model.
    Intercept { model: String },
    /// Forward untouched to the real upstream. Every non-chat turn, every unmapped model,
    /// and every unparseable body lands here — interception must never break normal traffic.
    Passthrough,
}

/// Decide what to do with a request, given its host, method, path, the `x-amz-target` header,
/// the raw body, and the configured model map.
pub fn classify(
    host: &str,
    path: &str,
    amz_target: Option<&str>,
    body: &[u8],
    map: &ModelMap,
) -> Decision {
    if path == HEALTH_PATH {
        return Decision::Health;
    }

    let Some(tool) = Tool::from_host(host) else {
        return Decision::Passthrough;
    };

    if !is_chat_request(tool, path, amz_target) {
        return Decision::Passthrough;
    }

    // Only a body that parses as a CodeWhisperer conversation is a candidate. A binary
    // EventStream body (or anything else) parses as None and passes through untouched —
    // the reference wrongly forces those into a 500.
    let Some(model_id) = parse_model_id(body) else {
        return Decision::Passthrough;
    };

    match map.resolve(&model_id) {
        Some(model) => Decision::Intercept {
            model: model.to_string(),
        },
        None => Decision::Passthrough,
    }
}

fn parse_model_id(body: &[u8]) -> Option<String> {
    let req: cw::Request = serde_json::from_slice(body).ok()?;
    req.model_id().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const KIRO_HOST: &str = "codewhisperer.us-east-1.amazonaws.com";

    fn map() -> ModelMap {
        ModelMap {
            models: HashMap::from([("auto".to_string(), "gpt-4o".to_string())]),
            default: None,
        }
    }

    fn body(model: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": { "content": "hi", "modelId": model } }
            }
        }))
        .unwrap()
    }

    #[test]
    fn health_path_is_recognized_regardless_of_host() {
        assert_eq!(
            classify("anything", HEALTH_PATH, None, b"", &map()),
            Decision::Health
        );
    }

    #[test]
    fn a_mapped_kiro_chat_turn_is_intercepted() {
        let d = classify(
            KIRO_HOST,
            "/",
            Some("KiroRuntimeService.GenerateAssistantResponse"),
            &body("auto"),
            &map(),
        );
        assert_eq!(
            d,
            Decision::Intercept {
                model: "gpt-4o".into()
            }
        );
    }

    #[test]
    fn legacy_path_form_is_also_intercepted() {
        let d = classify(
            KIRO_HOST,
            "/generateAssistantResponse",
            None,
            &body("auto"),
            &map(),
        );
        assert_eq!(
            d,
            Decision::Intercept {
                model: "gpt-4o".into()
            }
        );
    }

    #[test]
    fn an_unmapped_model_passes_through() {
        let d = classify(
            KIRO_HOST,
            "/generateAssistantResponse",
            None,
            &body("claude-x"),
            &map(),
        );
        assert_eq!(d, Decision::Passthrough);
    }

    #[test]
    fn an_unknown_host_passes_through() {
        assert_eq!(
            classify(
                "example.com",
                "/generateAssistantResponse",
                None,
                &body("auto"),
                &map()
            ),
            Decision::Passthrough
        );
    }

    #[test]
    fn a_non_chat_kiro_request_passes_through() {
        assert_eq!(
            classify(KIRO_HOST, "/telemetry", None, b"{}", &map()),
            Decision::Passthrough
        );
    }

    #[test]
    fn a_binary_eventstream_body_passes_through_instead_of_erroring() {
        // Looks like a chat request by header, but the body is not JSON.
        let binary = [0u8, 0, 1, 44, 0, 0, 0, 92, 0xde, 0xad, 0xbe, 0xef];
        let d = classify(
            KIRO_HOST,
            "/",
            Some("GenerateAssistantResponse"),
            &binary,
            &map(),
        );
        assert_eq!(d, Decision::Passthrough);
    }
}
