//! CodeWhisperer conversation state -> OpenAI chat-completions request.
//!
//! Kiro never sends a `system` role: its system prompt is prefixed into the first user turn's
//! text (CodeWhisperer rejects a top-level `systemPrompt` with 400 REQUEST_BODY_INVALID), so it
//! arrives here as ordinary user content and is forwarded verbatim.

use crate::types::{cw, openai};
use crate::{Error, Result};

/// Image formats Kiro may inline, mapped to the MIME type for the data URL.
fn image_mime(format: &str) -> Option<&'static str> {
    match format.to_ascii_lowercase().as_str() {
        "png" => Some("image/png"),
        "jpeg" | "jpg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

/// CodeWhisperer carries tool input as parsed JSON; OpenAI requires a string. Passing the
/// object through would stringify to `[object Object]`-equivalent garbage downstream.
fn arguments_string(input: Option<&serde_json::Value>) -> String {
    match input {
        None | Some(serde_json::Value::Null) => "{}".to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string()),
    }
}

/// One CodeWhisperer user turn fans out to several OpenAI messages: every tool result becomes
/// its own `role: "tool"` message, and only then comes the text/image message.
fn convert_user_message(msg: &cw::UserInputMessage, out: &mut Vec<openai::ChatMessage>) {
    let ctx = msg.user_input_message_context.as_ref();
    let tool_results = ctx.map(|c| c.tool_results.as_slice()).unwrap_or(&[]);

    for result in tool_results {
        let mut text = result
            .content
            .iter()
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        // The JS reference drops `status`, making a failed tool indistinguishable from a
        // successful one. Marking it keeps the model from treating an error as a result.
        if result.status.as_deref() == Some("error") {
            text = format!("[tool error] {text}");
        }

        out.push(openai::ChatMessage {
            role: openai::Role::Tool,
            content: Some(openai::Content::Text(text)),
            tool_call_id: Some(result.tool_use_id.clone().unwrap_or_default()),
            tool_calls: Vec::new(),
        });
    }

    let text = msg.content.as_deref().unwrap_or("").trim().to_string();

    let images: Vec<openai::ContentPart> = msg
        .images
        .iter()
        .filter_map(|img| {
            let mime = image_mime(img.format.as_deref()?)?;
            let bytes = img.source.as_ref()?.bytes.as_deref()?;
            if bytes.is_empty() {
                return None;
            }
            Some(openai::ContentPart::ImageUrl {
                image_url: openai::ImageUrl {
                    url: format!("data:{mime};base64,{bytes}"),
                },
            })
        })
        .collect();

    if !images.is_empty() {
        let mut parts = Vec::with_capacity(images.len() + 1);
        if !text.is_empty() {
            parts.push(openai::ContentPart::Text { text });
        }
        parts.extend(images);
        out.push(openai::ChatMessage {
            role: openai::Role::User,
            content: Some(openai::Content::Parts(parts)),
            tool_call_id: None,
            tool_calls: Vec::new(),
        });
        return;
    }

    // A turn that carries nothing but tool results must not emit an empty user message.
    if !text.is_empty() || tool_results.is_empty() {
        out.push(openai::ChatMessage::text(openai::Role::User, text));
    }
}

fn convert_assistant_message(msg: &cw::AssistantResponseMessage) -> openai::ChatMessage {
    if msg.tool_uses.is_empty() {
        return openai::ChatMessage::text(
            openai::Role::Assistant,
            msg.content.clone().unwrap_or_default(),
        );
    }

    let tool_calls = msg
        .tool_uses
        .iter()
        .enumerate()
        .map(|(i, tu)| openai::ToolCall {
            id: tu
                .tool_use_id
                .clone()
                .unwrap_or_else(|| format!("call_{i}")),
            kind: "function",
            function: openai::FunctionCall {
                name: tu.name.clone().unwrap_or_default(),
                arguments: arguments_string(tu.input.as_ref()),
            },
        })
        .collect();

    openai::ChatMessage {
        role: openai::Role::Assistant,
        content: msg
            .content
            .as_ref()
            .filter(|c| !c.is_empty())
            .map(|c| openai::Content::Text(c.clone())),
        tool_call_id: None,
        tool_calls,
    }
}

/// Tools live on the current turn, or on the first history turn that declared them.
fn extract_tools(state: &cw::ConversationState) -> Vec<openai::Tool> {
    let slots = state
        .current_message
        .as_ref()
        .and_then(|m| m.user_input_message.as_ref())
        .and_then(|m| m.user_input_message_context.as_ref())
        .map(|c| c.tools.as_slice())
        .filter(|t| !t.is_empty())
        .or_else(|| {
            state
                .history
                .iter()
                .filter_map(|item| {
                    let ctx = item
                        .user_input_message
                        .as_ref()?
                        .user_input_message_context
                        .as_ref()?;
                    (!ctx.tools.is_empty()).then_some(ctx.tools.as_slice())
                })
                .next()
        })
        .unwrap_or(&[]);

    slots
        .iter()
        .filter_map(|slot| {
            let spec = slot.spec()?;
            let name = spec.name.clone().unwrap_or_default();
            Some(openai::Tool {
                kind: "function",
                function: openai::Function {
                    name: name.clone(),
                    description: spec
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("Tool: {name}")),
                    parameters: spec
                        .input_schema
                        .as_ref()
                        .and_then(|s| s.json.clone())
                        .unwrap_or_else(
                            || serde_json::json!({"type":"object","properties":{},"required":[]}),
                        ),
                },
            })
        })
        .collect()
}

/// Build the upstream request. `model` is the already-mapped provider model, not Kiro's id.
pub fn to_chat_request(req: &cw::Request, model: impl Into<String>) -> Result<openai::ChatRequest> {
    let state = &req.conversation_state;
    let mut messages = Vec::new();

    for item in &state.history {
        if let Some(user) = &item.user_input_message {
            convert_user_message(user, &mut messages);
        } else if let Some(assistant) = &item.assistant_response_message {
            messages.push(convert_assistant_message(assistant));
        }
    }

    if let Some(current) = state
        .current_message
        .as_ref()
        .and_then(|m| m.user_input_message.as_ref())
    {
        convert_user_message(current, &mut messages);
    }

    if messages.is_empty() {
        return Err(Error::Translate("conversation produced no messages".into()));
    }

    let tools = extract_tools(state);
    Ok(openai::ChatRequest {
        model: model.into(),
        messages,
        stream: true,
        stream_options: Some(openai::StreamOptions {
            include_usage: true,
        }),
        tool_choice: (!tools.is_empty()).then_some("auto"),
        tools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> cw::Request {
        serde_json::from_value(json).expect("fixture must parse")
    }

    #[test]
    fn plain_turn_becomes_a_single_user_message() {
        let req = parse(serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": { "content": "hello", "modelId": "auto" } },
                "history": []
            }
        }));
        let out = to_chat_request(&req, "gpt-4").unwrap();
        assert_eq!(out.messages.len(), 1);
        assert_eq!(out.messages[0].role, openai::Role::User);
        assert_eq!(out.model, "gpt-4");
        assert!(out.tools.is_empty());
        assert!(out.tool_choice.is_none());
    }

    #[test]
    fn tool_use_input_object_is_serialized_to_a_string() {
        let req = parse(serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": { "content": "go" } },
                "history": [{
                    "assistantResponseMessage": {
                        "content": "",
                        "toolUses": [{ "toolUseId": "t1", "name": "read", "input": { "path": "/a" } }]
                    }
                }]
            }
        }));
        let out = to_chat_request(&req, "m").unwrap();
        let call = &out.messages[0].tool_calls[0];
        assert_eq!(call.id, "t1");
        assert_eq!(call.function.arguments, r#"{"path":"/a"}"#);
        // Pure tool-call assistant turns carry no text content.
        assert!(out.messages[0].content.is_none());
    }

    #[test]
    fn tool_result_turn_emits_tool_message_and_no_empty_user_message() {
        let req = parse(serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": {
                    "content": "",
                    "userInputMessageContext": {
                        "toolResults": [{ "toolUseId": "t1", "content": [{ "text": "ok" }] }]
                    }
                }},
                "history": []
            }
        }));
        let out = to_chat_request(&req, "m").unwrap();
        assert_eq!(out.messages.len(), 1);
        assert_eq!(out.messages[0].role, openai::Role::Tool);
        assert_eq!(out.messages[0].tool_call_id.as_deref(), Some("t1"));
    }

    #[test]
    fn errored_tool_result_is_marked() {
        let req = parse(serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": {
                    "content": "",
                    "userInputMessageContext": {
                        "toolResults": [{
                            "toolUseId": "t1",
                            "status": "error",
                            "content": [{ "text": "ENOENT" }]
                        }]
                    }
                }},
                "history": []
            }
        }));
        let out = to_chat_request(&req, "m").unwrap();
        let openai::Content::Text(text) = out.messages[0].content.as_ref().unwrap() else {
            panic!("expected text content");
        };
        assert!(text.starts_with("[tool error]"), "got {text:?}");
    }

    #[test]
    fn images_become_data_urls_alongside_the_text_part() {
        let req = parse(serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": {
                    "content": "look",
                    "images": [{ "format": "jpg", "source": { "bytes": "QUJD" } }]
                }},
                "history": []
            }
        }));
        let out = to_chat_request(&req, "m").unwrap();
        let openai::Content::Parts(parts) = out.messages[0].content.as_ref().unwrap() else {
            panic!("expected multi-part content");
        };
        assert_eq!(parts.len(), 2);
        match &parts[1] {
            // `jpg` must normalize to the image/jpeg MIME type.
            openai::ContentPart::ImageUrl { image_url } => {
                assert_eq!(image_url.url, "data:image/jpeg;base64,QUJD");
            }
            _ => panic!("expected an image part"),
        }
    }

    #[test]
    fn tools_fall_back_to_the_first_history_turn_that_declared_them() {
        let req = parse(serde_json::json!({
            "conversationState": {
                "currentMessage": { "userInputMessage": { "content": "hi" } },
                "history": [{
                    "userInputMessage": {
                        "content": "earlier",
                        "userInputMessageContext": {
                            "tools": [{ "toolSpecification": {
                                "name": "grep",
                                "description": "search",
                                "inputSchema": { "json": { "type": "object" } }
                            }}]
                        }
                    }
                }]
            }
        }));
        let out = to_chat_request(&req, "m").unwrap();
        assert_eq!(out.tools.len(), 1);
        assert_eq!(out.tools[0].function.name, "grep");
        assert_eq!(out.tool_choice, Some("auto"));
    }

    #[test]
    fn empty_conversation_is_an_error_rather_than_an_empty_request() {
        let req = parse(serde_json::json!({ "conversationState": { "history": [] } }));
        assert!(to_chat_request(&req, "m").is_err());
    }
}
