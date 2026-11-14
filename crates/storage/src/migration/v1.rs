use argon2::{Argon2, password_hash::phc::SaltString};
use factr_core::vault::{self, Account, KEY_LEN, Vault, VaultDecryptError};
use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;
use uuid::Uuid;
use zeroize::Zeroizing;

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
    pub fn decrypt(&self, key: &[u8; KEY_LEN]) -> Result<Account, VaultDecryptError> {
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
    pub fn encrypt_account(account: &Account, key: &[u8; KEY_LEN]) -> Result<Self, String> {
        Ok(Self {
            id: account.id,
            created_at: account.created_at,
            modified_at: account.modified_at,
            custom_position: account.custom_position,
            issuer: account.totp.issuer().map(str::to_owned),
            account_name: account.totp.account_name().to_owned(),
            encrypted_secret_b64: vault::encrypt_bound(account.totp.secret().as_bytes(), key, &[])?,
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

/// Derives the V1 encryption key from the legacy password and encoded salt.
fn master_key(password: &str, salt_b64: &str) -> Result<[u8; KEY_LEN], String> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt_b64).map_err(|e| e.to_string())?;
    let mut key = [0u8; KEY_LEN];
    argon2
        // V1 derives the key from the encoded salt, not its decoded bytes.
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PendingVault, Storage};
    use factr_core::recovery;

    #[test]
    /// Checks that migration preserves accounts and replaces V1 only on commit.
    fn migration_requires_password_and_confirmation_and_preserves_accounts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.json");
        let salt = SaltString::generate();
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::default()
            .hash_password_into(b"old-password", salt.as_ref().as_bytes(), &mut *key)
            .unwrap();
        let account = vault::Account::from_otp_auth_url(
            "otpauth://totp/Issuer:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Issuer",
            0,
        )
        .unwrap();
        let id = account.id;
        let legacy = Storage::V1(LegacyStorageV1 {
            salt_b64: salt.to_string(),
            sealed_check: vault::encrypt_bound(LegacyStorageV1::SEALED_CHECK, &key, &[]).unwrap(),
            accounts: vec![EncryptedAccount::encrypt_account(&account, &key).unwrap()],
        });
        legacy.write(&path).unwrap();
        #[cfg(unix)]
        let path = {
            let link = directory.path().join("linked-vault.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            link
        };
        let original = std::fs::read(&path).unwrap();
        assert!(PendingVault::initialize(&path, "wrong").is_err());
        let pending = PendingVault::initialize(&path, "old-password").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_ne!(*pending.vault.master_key, *key);
        pending.commit(&path).unwrap();
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            if cfg!(unix) { 2 } else { 1 }
        );
        assert!(matches!(
            Storage::read(&directory.path().join("vault.json")).unwrap(),
            Storage::V2(_)
        ));
        let Storage::V2(storage) = Storage::read(&path).unwrap() else {
            panic!("Expected V2")
        };
        let key =
            recovery::unlock(storage.id, &storage.protected_keys, &pending.recovery_key).unwrap();
        let restored = storage.decrypt(key).unwrap();
        assert_eq!(restored.accounts.len(), 1);
        let restored = &restored.accounts[0];
        assert_eq!(restored.id, id);
        assert_eq!(restored.created_at, account.created_at);
        assert_eq!(restored.modified_at, account.modified_at);
        assert_eq!(restored.custom_position, account.custom_position);
        assert_eq!(restored.totp, account.totp);
        assert!(pending.commit(&path).is_err());
    }
}
