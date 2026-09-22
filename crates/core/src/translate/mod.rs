//! Bidirectional translation between Kiro's CodeWhisperer protocol and OpenAI chat-completions.

pub mod request;
pub mod response;
pub mod sse;
pub mod thinking;

pub use request::to_chat_request;
pub use response::StreamState;
pub use sse::SseReader;
