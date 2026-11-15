use std::fmt::Display;

use factr_core::vault::{Vault, VaultDecryptError};

use crate::Storage;

pub mod v1;

#[derive(Debug)]
pub enum MigrationError {
    Decrypt(VaultDecryptError),
    Other(String),
}

impl Display for MigrationError {
    /// Formats a legacy migration error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decrypt(error) => Display::fmt(error, f),
            Self::Other(error) => f.write_str(error),
        }
    }
}

/// Converts a supported legacy format into the current domain model.
pub(crate) fn migrate(storage: Storage, password: &str) -> Result<Vault, MigrationError> {
    match storage {
        Storage::V1(storage) => storage.decrypt(password).map_err(MigrationError::Decrypt),
        Storage::V2(_) => Err(MigrationError::Other(
            "The vault is already V2; reopen it".to_string(),
        )),
    }
}
