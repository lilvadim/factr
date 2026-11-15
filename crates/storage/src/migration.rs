use std::fmt::Display;

use factr_core::vault::{Vault, VaultDecryptError};

use crate::Storage;

pub mod v1;

#[derive(Debug)]
pub enum MigrationError {
    Decrypt(VaultDecryptError),
    InvalidSalt(argon2::password_hash::phc::Error),
    KeyDerivation(argon2::Error),
    InvalidCheck,
    InvalidAccount(factr_core::error::AccountError),
    AlreadyCurrent,
}

impl Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decrypt(error) => Display::fmt(error, f),
            Self::InvalidSalt(error) => write!(f, "Invalid legacy salt: {error}"),
            Self::KeyDerivation(error) => write!(f, "Could not derive legacy key: {error}"),
            Self::InvalidCheck => f.write_str("Invalid legacy verification value"),
            Self::InvalidAccount(error) => Display::fmt(error, f),
            Self::AlreadyCurrent => f.write_str("The vault is already V2; reopen it"),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decrypt(error) => Some(error),
            Self::InvalidAccount(error) => Some(error),
            Self::InvalidSalt(error) => Some(error),
            Self::KeyDerivation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VaultDecryptError> for MigrationError {
    fn from(error: VaultDecryptError) -> Self {
        Self::Decrypt(error)
    }
}

/// Converts a supported legacy format into the current domain model.
pub(crate) fn migrate(storage: Storage, password: &str) -> Result<Vault, MigrationError> {
    match storage {
        Storage::V1(storage) => storage.decrypt(password),
        Storage::V2(_) => Err(MigrationError::AlreadyCurrent),
    }
}
