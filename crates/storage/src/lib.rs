use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use factr_core::vault::{self, ProtectedVaultKey, Vault, VaultDecryptError};

mod initialization;
pub mod migration;

pub use initialization::{InitializationError, PendingVault};
use migration::v1::LegacyStorageV1;

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

#[cfg(test)]
mod tests {
    use super::*;
    use factr_core::{recovery, vault::Account};

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
            factr_core::recovery::create(vault.id, &vault.master_key).unwrap();
        vault.protected_keys.push(protected_key);
        let storage = Storage::V2(ProtectedStorageV2::from_vault(&vault).unwrap());
        let json = serde_json::to_string(&storage).unwrap();
        let Storage::V2(storage) = serde_json::from_str(&json).unwrap() else {
            panic!("Expected V2")
        };
        assert!(!json.contains("Issuer"));
        assert!(!json.contains("user"));
        let key =
            factr_core::recovery::unlock(storage.id, &storage.protected_keys, &recovery).unwrap();
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

    #[test]
    /// Checks authenticated data and compatibility with unknown providers.
    fn v2_authenticates_payload_and_preserves_unknown_providers() {
        let mut vault = Vault::create(Vec::new());
        let (protected_key, _) = recovery::create(vault.id, &vault.master_key).unwrap();
        vault.protected_keys.push(protected_key);
        vault.protected_keys.push(ProtectedVaultKey {
            id: Uuid::new_v4(),
            provider: "future-provider".to_string(),
            version: 42,
            metadata: serde_json::json!({"opaque": "data"}),
            wrapped_key_b64: "opaque".to_string(),
        });
        let json =
            serde_json::to_value(Storage::V2(ProtectedStorageV2::from_vault(&vault).unwrap()))
                .unwrap();
        let Storage::V2(mut storage) = serde_json::from_value(json).unwrap() else {
            panic!("Expected V2")
        };
        let opened = storage.decrypt(vault.master_key.clone()).unwrap();
        assert_eq!(opened.protected_keys[1].provider, "future-provider");
        assert_eq!(opened.protected_keys[1].metadata["opaque"], "data");
        storage.id = Uuid::new_v4();
        assert!(storage.decrypt(vault.master_key.clone()).is_err());
        storage.id = vault.id;
        let replacement = if storage.encrypted_accounts_b64.starts_with('A') {
            "B"
        } else {
            "A"
        };
        storage
            .encrypted_accounts_b64
            .replace_range(..1, replacement);
        assert!(storage.decrypt(vault.master_key.clone()).is_err());
    }
}
