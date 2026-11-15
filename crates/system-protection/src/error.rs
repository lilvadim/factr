use factr_core::error::{VaultDecryptError, VaultEncryptError};
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum SystemProtectionError {
    UnsupportedPlatform,
    UnsupportedKey,
    KeyMissing,
    KeyMismatch,
    InvalidKey,
    AuthenticationCancelled,
    AuthenticationDenied,
    MissingPolicy,
    SecretServiceUnavailable,
    PolkitUnavailable,
    DeviceIdentityUnavailable,
    SettingsUnavailable,
    InvalidResponse,
    StateUnavailable,
    Platform(Box<dyn Error + Send + Sync>),
    Encryption(VaultEncryptError),
    Decryption(VaultDecryptError),
}

impl SystemProtectionError {
    /// Preserves a native error without exposing platform details to the UI.
    pub(crate) fn platform(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Platform(Box::new(error))
    }
}

impl fmt::Display for SystemProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                f.write_str("System protection is not supported on this OS")
            }
            Self::UnsupportedKey => f.write_str("Unsupported or non-local system protected key"),
            Self::KeyMissing => f.write_str("System key is missing; use the recovery key"),
            Self::KeyMismatch => f.write_str("System key does not match this vault"),
            Self::InvalidKey => f.write_str("Invalid system protected key data"),
            Self::AuthenticationCancelled => f.write_str("System authentication was cancelled"),
            Self::AuthenticationDenied => f.write_str("System authentication was denied"),
            Self::MissingPolicy => f.write_str("Factr's Polkit policy is missing"),
            Self::SecretServiceUnavailable => f.write_str("Secret Service is unavailable"),
            Self::PolkitUnavailable => f.write_str("Polkit is unavailable"),
            Self::DeviceIdentityUnavailable => {
                f.write_str("Cannot identify this device or session")
            }
            Self::SettingsUnavailable => f.write_str("Could not open system sign-in settings"),
            Self::InvalidResponse => f.write_str("Invalid response from system protection"),
            Self::StateUnavailable => f.write_str("System protection state is unavailable"),
            Self::Platform(error) => write!(f, "System protection failed: {error}"),
            Self::Encryption(error) => fmt::Display::fmt(error, f),
            Self::Decryption(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for SystemProtectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error.as_ref()),
            Self::Encryption(error) => Some(error),
            Self::Decryption(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VaultEncryptError> for SystemProtectionError {
    fn from(error: VaultEncryptError) -> Self {
        Self::Encryption(error)
    }
}

impl From<VaultDecryptError> for SystemProtectionError {
    fn from(error: VaultDecryptError) -> Self {
        Self::Decryption(error)
    }
}
