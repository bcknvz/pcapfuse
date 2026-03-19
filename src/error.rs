use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No source files found in {path}")]
    NoSourceFiles { path: PathBuf },

    #[error("Failed to parse {path}: {reason}")]
    Parse { path: PathBuf, reason: String },

    #[error("Unsupported file format in {path}: {reason}")]
    UnsupportedFormat { path: PathBuf, reason: String },

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Glob pattern error: {0}")]
    Glob(#[from] glob::PatternError),
}

pub type Result<T> = std::result::Result<T, Error>;
