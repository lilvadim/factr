use std::{fmt::Display, path::Path};

use factr_core::{recovery, vault::Vault};
use zeroize::Zeroizing;

use crate::{
    ProtectedStorageV2, Storage,
    migration::{self, MigrationError},
};

#[derive(Debug)]
pub enum InitializationError {
    Migration(MigrationError),
    Other(String),
}

impl Display for InitializationError {
    /// Formats a vault initialization error without presentation-specific text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Migration(error) => Display::fmt(error, f),
            Self::Other(error) => f.write_str(error),
        }
    }
}

/// A new or migrated vault awaiting recovery-key confirmation.
pub struct PendingVault {
    pub vault: Vault,
    pub recovery_key: Zeroizing<String>,
    source: Option<Vec<u8>>,
}

impl PendingVault {
    /// Prepares V2 and its recovery key without modifying the source file.
    pub fn initialize(path: &Path, password: &str) -> Result<Self, InitializationError> {
        let source = read_source(path).map_err(InitializationError::Other)?;
        let mut vault = match source.as_deref() {
            Some(bytes) => {
                let storage = serde_json::from_slice::<Storage>(bytes)
                    .map_err(|e| InitializationError::Other(e.to_string()))?;
                migration::migrate(storage, password).map_err(InitializationError::Migration)?
            }
            None => Vault::create(Vec::new()),
        };
        let (protected_key, recovery_key) =
            recovery::create(vault.id, &vault.master_key).map_err(InitializationError::Other)?;
        vault.protected_keys.push(protected_key);
        Ok(Self {
            vault,
            recovery_key,
            source,
        })
    }

    /// Verifies V2 and atomically replaces an unchanged source file.
    pub fn commit(&self, path: &Path) -> Result<(), String> {
        if read_source(path)? != self.source {
            return Err("The vault changed; cancel and reopen it".to_string());
        }
        let storage = ProtectedStorageV2::from_vault(&self.vault)?;
        storage
            .decrypt(self.vault.master_key.clone())
            .map_err(|e| e.to_string())?;
        Storage::V2(storage).write(path)
    }
}

/// Reads the original bytes while distinguishing a missing vault from an I/O error.
fn read_source(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}
