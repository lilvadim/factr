use std::{error::Error, fmt};

#[derive(Debug)]
pub(super) enum AppError {
    Account(factr_core::error::AccountError),
    Recovery(factr_core::error::RecoveryError),
    Decrypt(factr_core::error::VaultDecryptError),
    Storage(factr_storage::StorageError),
    Initialization(factr_storage::InitializationError),
    SystemProtection(factr_system_protection::SystemProtectionError),
    ExpectedV2,
    MissingSystemKey,
    NoVault,
    NoAccount,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Account(error) => fmt::Display::fmt(error, f),
            Self::Recovery(error) => fmt::Display::fmt(error, f),
            Self::Decrypt(error) => fmt::Display::fmt(error, f),
            Self::Storage(error) => fmt::Display::fmt(error, f),
            Self::Initialization(error) => fmt::Display::fmt(error, f),
            Self::SystemProtection(error) => fmt::Display::fmt(error, f),
            Self::ExpectedV2 => f.write_str("Expected a V2 vault"),
            Self::MissingSystemKey => {
                f.write_str("No system key for this device; use the recovery key")
            }
            Self::NoVault => f.write_str("No open vault"),
            Self::NoAccount => f.write_str("Account no longer exists"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Account(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::Decrypt(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Initialization(error) => Some(error),
            Self::SystemProtection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<factr_core::error::AccountError> for AppError {
    fn from(error: factr_core::error::AccountError) -> Self {
        Self::Account(error)
    }
}

impl From<factr_core::error::RecoveryError> for AppError {
    fn from(error: factr_core::error::RecoveryError) -> Self {
        Self::Recovery(error)
    }
}

impl From<factr_core::error::VaultDecryptError> for AppError {
    fn from(error: factr_core::error::VaultDecryptError) -> Self {
        Self::Decrypt(error)
    }
}

impl From<factr_storage::StorageError> for AppError {
    fn from(error: factr_storage::StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<factr_storage::InitializationError> for AppError {
    fn from(error: factr_storage::InitializationError) -> Self {
        Self::Initialization(error)
    }
}

impl From<factr_system_protection::SystemProtectionError> for AppError {
    fn from(error: factr_system_protection::SystemProtectionError) -> Self {
        Self::SystemProtection(error)
    }
}
