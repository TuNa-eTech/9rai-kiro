use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    RawIo(#[from] std::io::Error),

    #[error("certificate error: {0}")]
    Cert(String),

    #[error("trust store: {0}")]
    TrustStore(String),

    #[error("hosts file: {0}")]
    Hosts(String),

    #[error("privilege escalation failed: {0}")]
    Elevation(String),

    #[error("upstream provider: {0}")]
    Provider(String),

    #[error("translate: {0}")]
    Translate(String),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
