use std::{fmt::Display, path::Path};

use factr_core::{recovery, vault::Vault};
use zeroize::Zeroizing;

use crate::{
    ProtectedStorageV2, Storage, StorageError,
    migration::{self, MigrationError},
};

#[derive(Debug)]
pub enum InitializationError {
    Migration(MigrationError),
    Storage(StorageError),
    Recovery(factr_core::error::RecoveryError),
    Verification(factr_core::error::VaultDecryptError),
    SourceChanged,
}

impl Display for InitializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Migration(error) => Display::fmt(error, f),
            Self::Storage(error) => Display::fmt(error, f),
            Self::Recovery(error) => Display::fmt(error, f),
            Self::Verification(error) => Display::fmt(error, f),
            Self::SourceChanged => f.write_str("The vault changed; cancel and reopen it"),
        }
    }
}

impl std::error::Error for InitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Migration(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::SourceChanged => None,
        }
    }
}

impl From<StorageError> for InitializationError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
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
        let source = read_source(path)?;
        let mut vault = match source.as_deref() {
            Some(bytes) => {
                let storage = serde_json::from_slice::<Storage>(bytes)
                    .map_err(|e| InitializationError::Storage(StorageError::Deserialize(e)))?;
                migration::migrate(storage, password).map_err(InitializationError::Migration)?
            }
            None => Vault::create(Vec::new()),
        };
        let (protected_key, recovery_key) =
            recovery::create(vault.id, &vault.master_key).map_err(InitializationError::Recovery)?;
        vault.protected_keys.push(protected_key);
        Ok(Self {
            vault,
            recovery_key,
            source,
        })
    }

    /// Verifies V2 and atomically replaces an unchanged source file.
    pub fn commit(&self, path: &Path) -> Result<(), InitializationError> {
        if read_source(path)? != self.source {
            return Err(InitializationError::SourceChanged);
        }
        let storage = ProtectedStorageV2::from_vault(&self.vault)?;
        storage
            .decrypt(self.vault.master_key.clone())
            .map_err(InitializationError::Verification)?;
        Storage::V2(storage)
            .write(path)
            .map_err(InitializationError::Storage)
    }
}

/// Reads the original bytes while distinguishing a missing vault from an I/O error.
fn read_source(path: &Path) -> Result<Option<Vec<u8>>, StorageError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StorageError::Read(error)),
    }
}
