use factr_core::error::VaultEncryptError;
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum StorageError {
    Read(std::io::Error),
    Write(std::io::Error),
    Deserialize(serde_json::Error),
    Serialize(serde_json::Error),
    Encryption(VaultEncryptError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "Could not read the vault: {error}"),
            Self::Write(error) => write!(f, "Could not write the vault: {error}"),
            Self::Deserialize(error) => write!(f, "Invalid vault format: {error}"),
            Self::Serialize(error) => write!(f, "Could not serialize the vault: {error}"),
            Self::Encryption(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(error) | Self::Write(error) => Some(error),
            Self::Deserialize(error) | Self::Serialize(error) => Some(error),
            Self::Encryption(error) => Some(error),
        }
    }
}
