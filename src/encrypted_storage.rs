use argon2::{Argon2, password_hash::phc::SaltString};
use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::vault::{self, Account, ProtectedVaultKey, Vault, VaultDecryptError};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedAccount {
    pub id: Uuid,
    pub created_at: i64,
    pub modified_at: i64,
    pub custom_position: usize,
    pub issuer: Option<String>,
    pub account_name: String,
    pub encrypted_secret_b64: String,
    pub algo: Algorithm,
    pub digits: usize,
    pub period: u64,
}

impl EncryptedAccount {
    /// Decrypts a V1 account into its domain representation.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Account, VaultDecryptError> {
        let secret = vault::decrypt_bound(&self.encrypted_secret_b64, key, &[])?;
        let totp = vault::init_totp(
            self.issuer.to_owned(),
            self.account_name.to_owned(),
            self.algo,
            self.digits,
            self.period,
            secret.to_vec(),
        )
        .map_err(|e| VaultDecryptError::Other(e.to_string()))?;
        Ok(Account {
            id: self.id,
            totp,
            created_at: self.created_at,
            modified_at: self.modified_at,
            custom_position: self.custom_position,
        })
    }

    /// Encodes an account in the V1 storage format.
    #[cfg(test)]
    pub fn encrypt_account(
        account: &crate::vault::Account,
        key: &[u8; 32],
    ) -> Result<Self, String> {
        Ok(Self {
            id: account.id,
            created_at: account.created_at,
            modified_at: account.modified_at,
            custom_position: account.custom_position,
            issuer: account.totp.issuer().map(str::to_owned),
            account_name: account.totp.account_name().to_owned(),
            encrypted_secret_b64: crate::vault::encrypt_secret(
                account.totp.secret().as_bytes(),
                key,
            )?,
            algo: account.totp.algorithm(),
            digits: account.totp.digits().into(),
            period: account.totp.step(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegacyStorageV1 {
    pub salt_b64: String,
    pub sealed_check: String,
    pub accounts: Vec<EncryptedAccount>,
}

impl LegacyStorageV1 {
    pub const SEALED_CHECK: &[u8] = b"FACTR_AUTH_CHECK";

    /// Decrypts V1 accounts and creates a vault with a new random key.
    pub fn decrypt(&self, password: &str) -> Result<Vault, VaultDecryptError> {
        let master_key =
            Zeroizing::new(master_key(password, &self.salt_b64).map_err(VaultDecryptError::Other)?);
        let check_value = vault::decrypt_bound(&self.sealed_check, &master_key, &[])?;
        if check_value.as_slice() != LegacyStorageV1::SEALED_CHECK {
            return Err(VaultDecryptError::Other("Wrong Check Value".to_string()));
        }
        let accounts: Result<Vec<Account>, VaultDecryptError> = self
            .accounts
            .iter()
            .map(|account| account.decrypt(&master_key))
            .collect();
        accounts.map(Vault::create)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "version")]
pub enum Storage {
    V1(LegacyStorageV1),
    V2(ProtectedStorageV2),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtectedStorageV2 {
    pub id: Uuid,
    pub protected_keys: Vec<ProtectedVaultKey>,
    pub encrypted_accounts_b64: String,
}

impl ProtectedStorageV2 {
    /// Authenticates and decrypts V2 accounts with an unlocked vault key.
    pub fn decrypt(&self, master_key: Zeroizing<[u8; 32]>) -> Result<Vault, VaultDecryptError> {
        let bytes = vault::decrypt_bound(
            &self.encrypted_accounts_b64,
            &master_key,
            self.id.as_bytes(),
        )?;
        let accounts =
            serde_json::from_slice(&bytes).map_err(|e| VaultDecryptError::Other(e.to_string()))?;
        Ok(Vault {
            master_key,
            id: self.id,
            protected_keys: self.protected_keys.clone(),
            accounts,
        })
    }

    /// Encrypts all account data while preserving protected vault keys.
    pub fn from_vault(vault: &Vault) -> Result<Self, String> {
        let accounts =
            Zeroizing::new(serde_json::to_vec(&vault.accounts).map_err(|e| e.to_string())?);
        Ok(Self {
            id: vault.id,
            protected_keys: vault.protected_keys.clone(),
            encrypted_accounts_b64: vault::encrypt_bound(
                &accounts,
                &vault.master_key,
                vault.id.as_bytes(),
            )?,
        })
    }
}

impl Storage {
    /// Reads a supported vault format from disk.
    pub fn read(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }

    /// Atomically writes an encrypted vault without retaining a backup.
    pub fn write(&self, path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;

        // Replace the actual vault when a user-configured path is a symlink;
        // replacing only the link would leave the old V1 target behind.
        let target = if path.exists() {
            path.canonicalize().map_err(|e| e.to_string())?
        } else {
            path.to_owned()
        };
        let path = target.as_path();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        // Persist in the same directory: the old file survives until an atomic
        // replacement succeeds. No password-protected V1 backup is retained.
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Derives the V1 encryption key from the legacy password and encoded salt.
fn master_key(password: &str, salt_b64: &str) -> Result<[u8; 32], String> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt_b64).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    argon2
        // V1 derives the key from the encoded salt, not its decoded bytes.
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_round_trip_preserves_accounts() {
        let mut vault = Vault::create(Vec::new());
        for secret in ["1234567890", "12345678901234567890"] {
            let totp = vault::init_totp(
                Some("Issuer".to_string()),
                "user".to_string(),
                vault::DEFAULT_ALGO,
                6,
                30,
                secret.as_bytes().to_vec(),
            )
            .unwrap();
            vault.accounts.push(Account {
                id: Uuid::new_v4(),
                totp,
                created_at: 1,
                modified_at: 2,
                custom_position: vault.accounts.len(),
            });
        }
        let (protected_key, recovery) =
            crate::recovery::create(vault.id, &vault.master_key).unwrap();
        vault.protected_keys.push(protected_key);
        let storage = Storage::V2(ProtectedStorageV2::from_vault(&vault).unwrap());
        let json = serde_json::to_string(&storage).unwrap();
        let Storage::V2(storage) = serde_json::from_str(&json).unwrap() else {
            panic!("Expected V2")
        };
        assert!(!json.contains("Issuer"));
        assert!(!json.contains("user"));
        let key = crate::recovery::unlock(storage.id, &storage.protected_keys, &recovery).unwrap();
        let decrypted = storage.decrypt(key).unwrap();
        assert_eq!(vault.accounts.len(), decrypted.accounts.len());
        for (old, new) in vault.accounts.iter().zip(&decrypted.accounts) {
            assert_eq!(old.id, new.id);
            assert_eq!(old.created_at, new.created_at);
            assert_eq!(old.modified_at, new.modified_at);
            assert_eq!(old.custom_position, new.custom_position);
            assert_eq!(old.totp.issuer(), new.totp.issuer());
            assert_eq!(old.totp.account_name(), new.totp.account_name());
            assert_eq!(old.totp.secret().as_bytes(), new.totp.secret().as_bytes());
            assert_eq!(old.totp.algorithm(), new.totp.algorithm());
            assert_eq!(old.totp.digits(), new.totp.digits());
            assert_eq!(old.totp.step(), new.totp.step());
            assert_eq!(
                old.totp.generate(59).to_string(),
                new.totp.generate(59).to_string()
            );
        }
    }
}
