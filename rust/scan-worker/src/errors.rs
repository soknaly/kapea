use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("integrity error: {0}")]
    Integrity(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("scanner error ({engine}): {message}")]
    Scanner { engine: String, message: String },

    #[error("timeout after {0}ms")]
    Timeout(u64),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type WorkerResult<T> = Result<T, WorkerError>;
