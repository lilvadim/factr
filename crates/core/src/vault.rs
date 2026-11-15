use uuid::Uuid;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Generate},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

const LEGACY_SECRET_LEN: usize = 10;
const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

pub const DEFAULT_ALGO: Algorithm = Algorithm::SHA1;
pub const DEFAULT_DIGITS: usize = 6;
pub const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_SKEW: u16 = 1;

pub use crate::error::{AccountError, VaultDecryptError, VaultEncryptError};

#[derive(Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub totp: Totp,
    pub created_at: i64,
    pub modified_at: i64,
    pub custom_position: usize,
}

impl Account {
    fn new(totp: Totp, custom_position: usize) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4(),
            totp,
            created_at: now,
            modified_at: now,
            custom_position,
        }
    }
    pub fn from_otp_auth_url(otp_auth_url: &str, position: usize) -> Result<Self, AccountError> {
        Ok(Self::new(
            Totp::from_url(otp_auth_url).map_err(AccountError::InvalidOtpAuthUrl)?,
            position,
        ))
    }

    pub fn from_manual_with_defaults(
        issuer: Option<String>,
        account_name: String,
        secret: String,
        position: usize,
    ) -> Result<Self, AccountError> {
        Self::from_manual(
            issuer,
            account_name,
            DEFAULT_ALGO,
            DEFAULT_DIGITS,
            DEFAULT_PERIOD,
            secret,
            position,
        )
    }

    pub fn from_manual(
        issuer: Option<String>,
        account_name: String,
        algo: Algorithm,
        digits: usize,
        period: u64,
        secret_b32: String,
        position: usize,
    ) -> Result<Self, AccountError> {
        let secret = Secret::try_from_base32(&secret_b32).map_err(AccountError::InvalidSecret)?;
        let totp = init_totp(
            issuer,
            account_name,
            algo,
            digits,
            period,
            secret.as_bytes().to_vec(),
        )?;
        Ok(Self::new(totp, position))
    }

    pub fn current_state(&self) -> Result<(String, u64), AccountError> {
        let totp = &self.totp;
        let remaining = totp.ttl();
        let code = totp.generate_current().to_string();
        Ok((code, remaining))
    }
}

/// A vault key encrypted by a system or recovery provider.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtectedVaultKey {
    pub id: Uuid,
    pub provider: String,
    pub version: u32,
    pub metadata: serde_json::Value,
    pub wrapped_key_b64: String,
}

/// Binds encryption to the vault, protected key, and provider version.
pub fn encryption_context(
    vault_id: Uuid,
    protected_key_id: Uuid,
    provider: &str,
    version: u32,
) -> Vec<u8> {
    // Keep the authenticated label stable for existing V2 files.
    format!("Factr V2 key slot:{vault_id}:{protected_key_id}:{provider}:{version}").into_bytes()
}

pub struct Vault {
    pub master_key: Zeroizing<[u8; KEY_LEN]>,
    pub id: Uuid,
    pub protected_keys: Vec<ProtectedVaultKey>,
    pub accounts: Vec<Account>,
}

impl Vault {
    /// Creates an in-memory vault with a random encryption key.
    pub fn create(accounts: Vec<Account>) -> Vault {
        Vault {
            master_key: random_key(),
            id: Uuid::new_v4(),
            protected_keys: Vec::new(),
            accounts,
        }
    }
}

/// Builds a TOTP instance with support for legacy short secrets.
pub fn init_totp(
    issuer: Option<String>,
    account_name: String,
    algo: Algorithm,
    digits: usize,
    period: u64,
    secret: Vec<u8>,
) -> Result<Totp, AccountError> {
    let digits = u8::try_from(digits).map_err(|_| AccountError::InvalidDigits)?;
    let short_secret = secret.len() == LEGACY_SECRET_LEN;
    let builder = Builder::new()
        .with_algorithm(algo)
        .with_digits(digits)
        .with_skew(DEFAULT_SKEW)
        .with_step_duration(period)
        .with_secret(secret)
        .with_issuer(issuer)
        .with_account_name(account_name);
    let totp = if short_secret {
        // Google Authenticator Compatibility
        builder.build_noncompliant()
    } else {
        builder.build().map_err(AccountError::InvalidParameters)?
    };
    Ok(totp)
}

/// Generates a random 256-bit key in a zeroizing buffer.
pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    use rand::RngExt;
    Zeroizing::new(rand::rng().random())
}

/// Encrypts data and authenticates its associated context.
pub fn encrypt_bound(
    secret: &[u8],
    key: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<String, VaultEncryptError> {
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_generate().map_err(|_| VaultEncryptError::RandomGenerationFailed)?;
    let cipher_text = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: secret,
                aad: context,
            },
        )
        .map_err(|_| VaultEncryptError::EncryptionFailed)?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&cipher_text);
    Ok(BASE64_STANDARD.encode(&combined))
}

/// Decrypts data only when its key, context, and authentication tag match.
pub fn decrypt_bound(
    encrypted_secret_b64: &str,
    key: &[u8; KEY_LEN],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultDecryptError> {
    use aes_gcm::aead::Payload;
    let combined = BASE64_STANDARD
        .decode(encrypted_secret_b64)
        .map_err(VaultDecryptError::InvalidEncoding)?;
    let (nonce_bytes, cipher_text) = combined
        .split_at_checked(NONCE_LEN)
        .ok_or(VaultDecryptError::InvalidPayload)?;
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| VaultDecryptError::InvalidPayload)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: cipher_text,
                aad: context,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultDecryptError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc6238() {
        for (algorithm, secret, expected) in [
            (
                Algorithm::SHA1,
                b"12345678901234567890".as_slice(),
                "94287082",
            ),
            (
                Algorithm::SHA256,
                b"12345678901234567890123456789012".as_slice(),
                "46119246",
            ),
            (
                Algorithm::SHA512,
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                "90693936",
            ),
        ] {
            let totp =
                init_totp(None, "test".to_string(), algorithm, 8, 30, secret.to_vec()).unwrap();
            assert_eq!(totp.generate(59).to_string(), expected);
        }
    }

    #[test]
    fn account_import_supports_manual_and_otp_auth_url() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let manual = Account::from_manual_with_defaults(
            Some("Issuer".to_string()),
            "user".to_string(),
            secret.to_string(),
            0,
        )
        .unwrap();
        let url = Account::from_otp_auth_url(
            &format!("otpauth://totp/Issuer:user?secret={secret}&issuer=Issuer"),
            0,
        )
        .unwrap();
        assert_eq!(manual.totp, url.totp);
        assert!(
            Account::from_manual_with_defaults(
                None,
                "user".to_string(),
                "JBSWY3DPEHPK3PXP".to_string(),
                0,
            )
            .is_ok()
        );
    }
}
