use std::{error::Error, fmt};

#[derive(Debug)]
pub enum AccountError {
    InvalidSecret(totp_rs::SecretParseError),
    InvalidOtpAuthUrl(totp_rs::TotpError),
    InvalidParameters(totp_rs::TotpError),
    InvalidDigits,
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret(error) => write!(f, "Invalid account secret: {error}"),
            Self::InvalidOtpAuthUrl(error) => write!(f, "Invalid OTP auth URL: {error}"),
            Self::InvalidParameters(error) => write!(f, "Invalid TOTP parameters: {error}"),
            Self::InvalidDigits => f.write_str("Invalid number of TOTP digits"),
        }
    }
}

impl Error for AccountError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSecret(error) => Some(error),
            Self::InvalidOtpAuthUrl(error) | Self::InvalidParameters(error) => Some(error),
            Self::InvalidDigits => None,
        }
    }
}

#[derive(Debug)]
pub enum VaultEncryptError {
    RandomGenerationFailed,
    EncryptionFailed,
}

impl fmt::Display for VaultEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RandomGenerationFailed => "Could not generate an encryption nonce",
            Self::EncryptionFailed => "Could not encrypt vault data",
        })
    }
}

impl Error for VaultEncryptError {}

#[derive(Debug)]
pub enum VaultDecryptError {
    InvalidEncoding(base64::DecodeError),
    InvalidPayload,
    InvalidAccounts(serde_json::Error),
    DecryptFailed,
}

impl fmt::Display for VaultDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(error) => write!(f, "Invalid encrypted data encoding: {error}"),
            Self::InvalidPayload => f.write_str("Invalid encrypted data length"),
            Self::InvalidAccounts(error) => write!(f, "Invalid decrypted account data: {error}"),
            Self::DecryptFailed => {
                f.write_str("Cannot decrypt the vault: incorrect key or damaged data")
            }
        }
    }
}

impl Error for VaultDecryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEncoding(error) => Some(error),
            Self::InvalidAccounts(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum RecoveryError {
    InvalidFormat,
    IncorrectKey,
    InvalidVaultKey,
    Encryption(VaultEncryptError),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => f.write_str("Invalid recovery key format"),
            Self::IncorrectKey => f.write_str("Incorrect recovery key or damaged protected key"),
            Self::InvalidVaultKey => f.write_str("Invalid vault key length"),
            Self::Encryption(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for RecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encryption(error) => Some(error),
            _ => None,
        }
    }
}
