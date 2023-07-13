
use thiserror::Error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid domain")]
    InvalidDomain,

    #[error("InternalError")]
    InternalError,

    #[error("NoConnection")]
    NoConnection,

    #[error("TcpStreamError")]
    TcpStreamError(#[from] std::io::Error),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use std::error::Error;

        self.description() == other.description()
    }
}