//! Shared response-body type for the proxy service.

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};

use crate::Error;

/// Every response the service returns — passthrough or intercept — is erased to this type.
/// Unsync because both a streaming channel receiver and hyper's `Incoming` are `Send` but not
/// `Sync`; the server only requires `Send`.
pub type BoxBody = UnsyncBoxBody<Bytes, Error>;

/// Box any `Send` body whose error is [`Error`].
pub fn box_body<B>(body: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes, Error = Error> + Send + 'static,
{
    body.boxed_unsync()
}

/// A complete in-memory body (health responses, error bodies).
pub fn full(bytes: impl Into<Bytes>) -> BoxBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}
