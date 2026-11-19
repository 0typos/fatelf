//! Errors shared by packing, decoding, and launching.

use std::io;

use thiserror::Error;

/// Failure to build, validate, reconstruct, or execute a container.
#[derive(Debug, Error)]
pub enum Error {
    /// An input or container violates the supported format or limits.
    #[error("{0}")]
    Invalid(String),
    /// A named operation failed, preserving the original cause.
    #[error("{operation}")]
    Operation {
        operation: String,
        #[source]
        source: Box<Self>,
    },
    /// A filesystem operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Manifest serialization or decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A TOML configuration is syntactically invalid or violates its schema.
    #[error(transparent)]
    #[cfg(feature = "builder")]
    TomlDecode(#[from] toml::de::Error),
    /// A configuration could not be represented as TOML.
    #[error(transparent)]
    #[cfg(feature = "builder")]
    TomlEncode(#[from] toml::ser::Error),
    /// The RSL bitsandbytes footer codec rejected an encoding or input.
    #[error(transparent)]
    Codec(#[from] bnb::BitError),
    /// ELF parsing failed.
    #[error(transparent)]
    #[cfg(feature = "builder")]
    Elf(#[from] object::Error),
    /// A Linux descriptor or execution operation failed.
    #[error("Linux operation failed: {0}")]
    Linux(#[from] rustix::io::Errno),
}

impl Error {
    /// Attach operation context without erasing the error kind.
    pub(crate) fn context(self, operation: String) -> Self {
        Self::Operation {
            operation,
            source: Box::new(self),
        }
    }
}
