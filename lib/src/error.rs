use web_transport_quinn::quinn;

/// A Mushi error.
///
/// Mostly these are transport errors; at connection startup you may also encounter I/O and
/// addressing errors.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("session error: {0}")]
    Session(#[from] web_transport_quinn::SessionError),

    #[error("client error: {0}")]
    Client(#[from] web_transport_quinn::ClientError),

    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("connect error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("write error: {0}")]
    Write(web_transport_quinn::WriteError),

    #[error("read error: {0}")]
    Read(web_transport_quinn::ReadError),

    #[error("no addresses found")]
    NoAddrs,

    #[error("peer key mismatch on reconnection")]
    PeerKeyMismatch,
}

impl From<web_transport_quinn::WriteError> for Error {
    fn from(e: web_transport_quinn::WriteError) -> Self {
        match e {
            web_transport_quinn::WriteError::SessionError(e) => Error::Session(e),
            e => Error::Write(e),
        }
    }
}
impl From<web_transport_quinn::ReadError> for Error {
    fn from(e: web_transport_quinn::ReadError) -> Self {
        match e {
            web_transport_quinn::ReadError::SessionError(e) => Error::Session(e),
            e => Error::Read(e),
        }
    }
}
