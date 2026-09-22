//! 9rai-core — MITM engine for redirecting Kiro IDE traffic to a custom provider.
//!
//! Pipeline: Kiro IDE -> hosts-file hijack -> local TLS :443 (SNI leaf cert signed by our
//! root CA) -> classify request -> either translate to an OpenAI-compatible provider and
//! re-encode the reply as an AWS EventStream, or pass through untouched to the real upstream.

pub mod appconfig;
pub mod cert;
pub mod config;
pub mod dns;
pub mod error;
pub mod eventstream;
pub mod hosts;
pub mod mapping;
pub mod paths;
pub mod privilege;
pub mod provider;
pub mod proxy;
pub mod session;
pub mod translate;
pub mod types;

pub use config::{Tool, TOOL_HOSTS};
pub use error::{Error, Result};
