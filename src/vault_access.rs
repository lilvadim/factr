use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    encrypted_storage::{ProtectedStorageV2, Storage},
    recovery, system_protection,
    vault::{ProtectedVaultKey, Vault},
    view::model::{VaultAccessAction, VaultAccessDisplay, VaultAccessScreen},
};

struct PendingVault {
    vault: Vault,
    recovery_key: Zeroizing<String>,
    source: Option<Vec<u8>>,
}

enum JobResult {
    Prepared(PendingVault),
    SaveFailed(PendingVault, String),
    Unlocked(Vault),
    Protection {
        id: Uuid,
        protected_key: Option<ProtectedVaultKey>,
    },
}

pub struct VaultAccess {
    pub display: VaultAccessDisplay,
    storage: Option<Storage>,
    pending: Option<PendingVault>,
    job: Option<Receiver<Result<JobResult, String>>>,
}

impl VaultAccess {
    /// Initializes the unlock flow from the current vault file.
    pub fn new(path: &Path) -> Self {
        let mut access = Self {
            display: VaultAccessDisplay::default(),
            storage: None,
            pending: None,
            job: None,
        };
        access.reload(path);
        if access.display.system_enabled {
            access.display.action = Some(VaultAccessAction::UnlockSystem);
        }
        access
    }

    /// Reloads vault metadata and clears transient secrets.
    pub fn reload(&mut self, path: &Path) {
        self.display.clear_secrets();
        self.pending = None;
        self.display.error = None;
        self.storage = if path.exists() {
            match Storage::read(path) {
                Ok(storage) => Some(storage),
                Err(error) => {
                    self.display.error = Some(error);
                    None
                }
            }
        } else {
            None
        };
        self.display.screen = match &self.storage {
            Some(Storage::V1(_)) => VaultAccessScreen::Legacy,
            Some(Storage::V2(_)) => VaultAccessScreen::Locked,
            None => VaultAccessScreen::Create,
        };
        self.display.can_create = !path.exists();
        self.display.need_default_focus = true;
        self.display.use_system =
            self.display.system_available && !matches!(self.storage, Some(Storage::V2(_)));
        self.display.system_enabled = match &self.storage {
            Some(Storage::V2(storage)) => storage
                .protected_keys
                .iter()
                .any(system_protection::is_local),
            _ => false,
        };
    }

    /// Runs a protection operation without blocking the UI thread.
    fn start(
        &mut self,
        ctx: &egui::Context,
        task: impl FnOnce() -> Result<JobResult, String> + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        self.display.busy = true;
        self.display.error = None;
        self.job = Some(receiver);
        std::thread::spawn(move || {
            let _ = sender.send(task());
            ctx.request_repaint();
        });
    }

    /// Processes unlock actions and reports a successful vault unlock.
    pub fn update(&mut self, ctx: &egui::Context, path: &Path, vault: &mut Option<Vault>) -> bool {
        let mut unlocked = false;
        let result = self.job.as_ref().and_then(|job| match job.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                Some(Err("System protection worker stopped".to_string()))
            }
        });
        if let Some(result) = result {
            self.job = None;
            self.display.busy = false;
            match result {
                Ok(JobResult::Prepared(mut pending)) => {
                    self.display.recovery_key = std::mem::take(&mut pending.recovery_key);
                    self.pending = Some(pending);
                    self.display.screen = VaultAccessScreen::ConfirmRecovery;
                }
                Ok(JobResult::SaveFailed(pending, error)) => {
                    self.pending = Some(pending);
                    self.display.error = Some(error);
                }
                Ok(JobResult::Unlocked(opened)) => {
                    self.display.system_enabled = opened
                        .protected_keys
                        .iter()
                        .any(system_protection::is_local);
                    *vault = Some(opened);
                    self.display.clear_secrets();
                    unlocked = true;
                }
                Ok(JobResult::Protection { id, protected_key }) => {
                    if let Some(vault) = vault.as_mut().filter(|vault| vault.id == id) {
                        let old = vault.protected_keys.clone();
                        vault
                            .protected_keys
                            .retain(|protected_key| !system_protection::is_local(protected_key));
                        if let Some(protected_key) = protected_key {
                            vault.protected_keys.push(protected_key);
                        }
                        if let Err(error) = ProtectedStorageV2::from_vault(vault)
                            .and_then(|storage| Storage::V2(storage).write(path))
                        {
                            vault.protected_keys = old;
                            self.display.error = Some(error);
                        }
                        self.display.system_enabled =
                            vault.protected_keys.iter().any(system_protection::is_local);
                    }
                }
                Err(error) => self.display.error = Some(error),
            }
        }
        if self.display.busy {
            return unlocked;
        }
        let Some(action) = self.display.action.take() else {
            return unlocked;
        };
        let path = path.to_owned();
        match action {
            VaultAccessAction::Prepare => {
                let password = std::mem::take(&mut self.display.input);
                let use_system = self.display.use_system;
                self.start(ctx, move || {
                    prepare(&path, &password, use_system).map(JobResult::Prepared)
                });
            }
            VaultAccessAction::Confirm => {
                if !self.display.recovery_saved {
                    return unlocked;
                }
                if let Some(pending) = self.pending.take() {
                    self.start(ctx, move || {
                        if let Err(error) =
                            replace(&path, pending.source.as_deref(), &pending.vault)
                        {
                            return Ok(JobResult::SaveFailed(pending, error));
                        }
                        Ok(JobResult::Unlocked(pending.vault))
                    });
                    // Retain the recovery text until the atomic save succeeds,
                    // so an I/O error cannot leave the user without a copy.
                }
            }
            VaultAccessAction::Cancel => self.reload(&path),
            VaultAccessAction::UnlockRecovery => {
                let text = std::mem::take(&mut self.display.input);
                let use_system = self.display.use_system;
                self.start(ctx, move || {
                    let Storage::V2(storage) = Storage::read(&path)? else {
                        return Err("Expected a V2 vault".to_string());
                    };
                    let key = recovery::unlock(storage.id, &storage.protected_keys, &text)?;
                    let mut vault = storage.decrypt(key).map_err(|e| e.to_string())?;
                    if use_system && !vault.protected_keys.iter().any(system_protection::is_local) {
                        vault
                            .protected_keys
                            .push(system_protection::protect(vault.id, &vault.master_key)?);
                        Storage::V2(ProtectedStorageV2::from_vault(&vault)?).write(&path)?;
                    }
                    Ok(JobResult::Unlocked(vault))
                });
            }
            VaultAccessAction::UnlockSystem => {
                self.start(ctx, move || {
                    let Storage::V2(storage) = Storage::read(&path)? else {
                        return Err("Expected a V2 vault".to_string());
                    };
                    let protected_key = storage
                        .protected_keys
                        .iter()
                        .find(|protected_key| system_protection::is_local(protected_key))
                        .ok_or("No system key for this device; use the recovery key")?;
                    let key = system_protection::unlock(storage.id, protected_key)?;
                    storage
                        .decrypt(key)
                        .map(JobResult::Unlocked)
                        .map_err(|e| e.to_string())
                });
            }
            VaultAccessAction::SetSystemProtection(enabled) => {
                if let Some(vault) = vault.as_ref() {
                    let id = vault.id;
                    let key = vault.master_key.clone();
                    let current = vault
                        .protected_keys
                        .iter()
                        .find(|protected_key| system_protection::is_local(protected_key))
                        .cloned();
                    self.start(ctx, move || {
                        let protected_key = if enabled {
                            Some(system_protection::protect(id, &key)?)
                        } else {
                            // Removing system protection also requires fresh authorization.
                            if let Some(protected_key) = current {
                                system_protection::unlock(id, &protected_key)?;
                            }
                            None
                        };
                        Ok(JobResult::Protection { id, protected_key })
                    });
                }
            }
        }
        unlocked
    }
}

/// Prepares a new or migrated vault without changing the original file.
fn prepare(path: &Path, password: &str, use_system: bool) -> Result<PendingVault, String> {
    let source = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let mut vault = match source.as_deref() {
        Some(bytes) => match serde_json::from_slice::<Storage>(bytes).map_err(|e| e.to_string())? {
            Storage::V1(storage) => storage
                .decrypt(password)
                .map_err(|_| rust_i18n::t!("wrong-password").to_string())?,
            Storage::V2(_) => return Err("The vault is already V2; reopen it".to_string()),
        },
        None => Vault::create(Vec::new()),
    };
    let (protected_key, recovery_key) = recovery::create(vault.id, &vault.master_key)?;
    vault.protected_keys.push(protected_key);
    if use_system {
        vault
            .protected_keys
            .push(system_protection::protect(vault.id, &vault.master_key)?);
    }
    Ok(PendingVault {
        vault,
        recovery_key,
        source,
    })
}

/// Verifies V2 and replaces the file only if its original contents are unchanged.
fn replace(path: &PathBuf, source: Option<&[u8]>, vault: &Vault) -> Result<(), String> {
    let current = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    if current.as_deref() != source {
        return Err("The vault changed during migration; cancel and reopen it".to_string());
    }
    let storage = ProtectedStorageV2::from_vault(vault)?;
    // Verify the complete V2 payload before replacing the original file.
    storage
        .decrypt(vault.master_key.clone())
        .map_err(|e| e.to_string())?;
    Storage::V2(storage).write(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_storage::{EncryptedAccount, LegacyStorageV1};
    use argon2::{Argon2, password_hash::phc::SaltString};

    #[test]
    /// Checks that migration preserves accounts and replaces V1 only on commit.
    fn migration_requires_password_and_confirmation_and_preserves_accounts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.json");
        let salt = SaltString::generate();
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(b"old-password", salt.as_ref().as_bytes(), &mut *key)
            .unwrap();
        let account = crate::vault::Account::from_otp_auth_url(
            "otpauth://totp/Issuer:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Issuer",
            0,
        )
        .unwrap();
        let id = account.id;
        let legacy = Storage::V1(LegacyStorageV1 {
            salt_b64: salt.to_string(),
            sealed_check: crate::vault::encrypt_secret(LegacyStorageV1::SEALED_CHECK, &key)
                .unwrap(),
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
        assert!(prepare(&path, "wrong", false).is_err());
        let pending = prepare(&path, "old-password", false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_ne!(*pending.vault.master_key, *key);
        replace(&path, pending.source.as_deref(), &pending.vault).unwrap();
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
        assert!(replace(&path, pending.source.as_deref(), &pending.vault).is_err());
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
