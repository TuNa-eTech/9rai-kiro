//! Wire types for both protocols.
//!
//! [`cw`] mirrors what Kiro IDE sends (CodeWhisperer / KiroRuntimeService shapes); we only
//! declare the fields we actually read, since serde drops unknown ones. [`openai`] mirrors the
//! chat-completions request we send upstream and the stream chunks we get back.

pub mod cw {
    use serde::Deserialize;
    use serde_json::Value;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Request {
        pub conversation_state: ConversationState,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ConversationState {
        pub conversation_id: Option<String>,
        pub current_message: Option<Message>,
        pub history: Vec<Message>,
    }

    /// A history slot holds exactly one of the two, never both.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Message {
        pub user_input_message: Option<UserInputMessage>,
        pub assistant_response_message: Option<AssistantResponseMessage>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct UserInputMessage {
        pub content: Option<String>,
        pub model_id: Option<String>,
        pub images: Vec<Image>,
        pub user_input_message_context: Option<UserInputMessageContext>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct UserInputMessageContext {
        pub tool_results: Vec<ToolResult>,
        pub tools: Vec<ToolSlot>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ToolResult {
        pub tool_use_id: Option<String>,
        pub content: Vec<ToolResultBlock>,
        /// `"success"` / `"error"`. The JS reference drops this; we surface it so an errored
        /// result is not indistinguishable from a successful one.
        pub status: Option<String>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct ToolResultBlock {
        pub text: Option<String>,
    }

    /// Kiro wraps specs in `{toolSpecification: ...}`, but older builds send them bare.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ToolSlot {
        pub tool_specification: Option<ToolSpecification>,
        #[serde(flatten)]
        pub bare: Option<ToolSpecification>,
    }

    impl ToolSlot {
        pub fn spec(&self) -> Option<&ToolSpecification> {
            self.tool_specification.as_ref().or(self.bare.as_ref())
        }
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ToolSpecification {
        pub name: Option<String>,
        pub description: Option<String>,
        pub input_schema: Option<InputSchema>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct InputSchema {
        pub json: Option<Value>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct Image {
        pub format: Option<String>,
        pub source: Option<ImageSource>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct ImageSource {
        pub bytes: Option<String>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AssistantResponseMessage {
        pub content: Option<String>,
        pub tool_uses: Vec<ToolUse>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ToolUse {
        pub tool_use_id: Option<String>,
        pub name: Option<String>,
        /// Parsed JSON in CodeWhisperer; OpenAI requires it re-serialized to a string.
        pub input: Option<Value>,
    }

    impl Request {
        /// The model Kiro asked for, used as the alias-mapping key.
        pub fn model_id(&self) -> Option<&str> {
            self.conversation_state
                .current_message
                .as_ref()?
                .user_input_message
                .as_ref()?
                .model_id
                .as_deref()
        }
    }
}

pub mod openai {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    #[derive(Debug, Clone, Serialize)]
    pub struct ChatRequest {
        pub model: String,
        pub messages: Vec<ChatMessage>,
        pub stream: bool,
        /// OpenAI-compatible servers omit `usage` from streams unless explicitly asked. Without
        /// this field the usage-fix in `translate::response` would never fire against a real
        /// provider. Providers that don't know the field ignore it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stream_options: Option<StreamOptions>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub tools: Vec<Tool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_choice: Option<&'static str>,
    }

    #[derive(Debug, Clone, Copy, Serialize)]
    pub struct StreamOptions {
        pub include_usage: bool,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct ChatMessage {
        pub role: Role,
        /// `None` is a meaningful value for an assistant turn that is pure tool calls.
        pub content: Option<Content>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_call_id: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub tool_calls: Vec<ToolCall>,
    }

    impl ChatMessage {
        pub fn text(role: Role, content: impl Into<String>) -> Self {
            Self {
                role,
                content: Some(Content::Text(content.into())),
                tool_call_id: None,
                tool_calls: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Role {
        User,
        Assistant,
        Tool,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(untagged)]
    pub enum Content {
        Text(String),
        Parts(Vec<ContentPart>),
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ContentPart {
        Text { text: String },
        ImageUrl { image_url: ImageUrl },
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct ImageUrl {
        pub url: String,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct Tool {
        #[serde(rename = "type")]
        pub kind: &'static str,
        pub function: Function,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct Function {
        pub name: String,
        pub description: String,
        pub parameters: Value,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct ToolCall {
        pub id: String,
        #[serde(rename = "type")]
        pub kind: &'static str,
        pub function: FunctionCall,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct FunctionCall {
        pub name: String,
        /// Always a JSON *string*, never an object.
        pub arguments: String,
    }

    // ── Streaming response ───────────────────────────────────────────────────

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct StreamChunk {
        pub model: Option<String>,
        pub choices: Vec<Choice>,
        pub usage: Option<Usage>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct Choice {
        pub delta: Delta,
        pub finish_reason: Option<String>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct Delta {
        pub content: Option<String>,
        pub reasoning_content: Option<String>,
        pub tool_calls: Vec<ToolCallDelta>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct ToolCallDelta {
        pub index: usize,
        pub id: Option<String>,
        pub function: Option<FunctionCallDelta>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(default)]
    pub struct FunctionCallDelta {
        pub name: Option<String>,
        /// A partial fragment of the JSON arguments string.
        pub arguments: Option<String>,
    }

    #[derive(Debug, Clone, Copy, Default, Deserialize)]
    #[serde(default)]
    pub struct Usage {
        pub prompt_tokens: u64,
        pub completion_tokens: u64,
    }
}
