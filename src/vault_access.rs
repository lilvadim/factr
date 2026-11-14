use std::{
    path::Path,
    sync::mpsc::{self, Receiver, TryRecvError},
};

use factr_core::{
    recovery,
    vault::{KEY_LEN, ProtectedVaultKey, Vault},
};
use factr_storage::{InitializationError, PendingVault, ProtectedStorageV2, Storage};
use factr_system_protection as system_protection;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) enum VaultSetupResult {
    ReadyToComplete(PendingVault),
    SaveFailed(PendingVault, String),
    Failed(InitializationError),
    Completed(Vault),
}

pub(crate) enum VaultAccessResult {
    Setup(VaultSetupResult),
    Unlocked(Vault),
    SystemProtectionReady {
        id: Uuid,
        protected_key: Option<ProtectedVaultKey>,
    },
}

#[derive(Default)]
pub struct VaultAccess {
    pub pending: Option<PendingVault>,
    job: Option<Receiver<Result<VaultAccessResult, String>>>,
}

impl VaultAccess {
    /// Runs an access operation and notifies the caller when it finishes.
    fn start(
        &mut self,
        task: impl FnOnce() -> Result<VaultAccessResult, String> + Send + 'static,
        notify: impl FnOnce() + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::channel();
        self.job = Some(receiver);
        std::thread::spawn(move || {
            let _ = sender.send(task());
            notify();
        });
    }

    /// Starts setup in the background without committing the vault.
    pub fn start_vault_setup_in_background(
        &mut self,
        path: &Path,
        password: Zeroizing<String>,
        use_system: bool,
        reason: String,
        notify: impl FnOnce() + Send + 'static,
    ) {
        let path = path.to_owned();
        self.start(
            move || {
                let result = match start_vault_setup(&path, &password, use_system, &reason) {
                    Ok(pending) => VaultSetupResult::ReadyToComplete(pending),
                    Err(error) => VaultSetupResult::Failed(error),
                };
                Ok(VaultAccessResult::Setup(result))
            },
            notify,
        );
    }

    /// Commits the pending setup in the background.
    pub fn complete_vault_setup_in_background(
        &mut self,
        path: &Path,
        notify: impl FnOnce() + Send + 'static,
    ) {
        if let Some(pending) = self.pending.take() {
            let path = path.to_owned();
            self.start(
                move || {
                    Ok(VaultAccessResult::Setup(complete_vault_setup(
                        &path, pending,
                    )))
                },
                notify,
            );
        }
    }

    /// Starts recovery-key unlock and optional system enrollment.
    pub fn recovery_unlock_in_background(
        &mut self,
        path: &Path,
        text: Zeroizing<String>,
        use_system: bool,
        reason: String,
        notify: impl FnOnce() + Send + 'static,
    ) {
        let path = path.to_owned();
        self.start(
            move || {
                recovery_unlock(&path, &text, use_system, &reason).map(VaultAccessResult::Unlocked)
            },
            notify,
        );
    }

    /// Starts unlock through the local system protection provider.
    pub fn system_unlock_in_background(
        &mut self,
        path: &Path,
        reason: String,
        notify: impl FnOnce() + Send + 'static,
    ) {
        let path = path.to_owned();
        self.start(
            move || system_unlock(&path, &reason).map(VaultAccessResult::Unlocked),
            notify,
        );
    }

    /// Starts enrollment or authorization to remove system protection.
    pub fn set_system_protection_in_background(
        &mut self,
        vault: &Vault,
        enabled: bool,
        reason: String,
        notify: impl FnOnce() + Send + 'static,
    ) {
        let id = vault.id;
        let key = vault.master_key.clone();
        let current = vault
            .protected_keys
            .iter()
            .find(|key| system_protection::is_local(key))
            .cloned();
        self.start(
            move || {
                let protected_key =
                    set_system_protection(id, &key, current.as_ref(), enabled, &reason)?;
                Ok(VaultAccessResult::SystemProtectionReady { id, protected_key })
            },
            notify,
        );
    }

    /// Reports whether an access operation is still pending.
    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    /// Takes a completed operation result without blocking.
    pub fn poll(&mut self) -> Option<Result<VaultAccessResult, String>> {
        let result = match self.job.as_ref()?.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err("System protection worker stopped".to_string()),
        };
        self.job = None;
        Some(result)
    }
}

/// Applies a protection change atomically, restoring keys if saving fails.
pub fn apply_system_protection_changes(
    path: &Path,
    vault: &mut Vault,
    protected_key: Option<ProtectedVaultKey>,
) -> Result<(), String> {
    let old = vault.protected_keys.clone();
    vault
        .protected_keys
        .retain(|key| !system_protection::is_local(key));
    if let Some(protected_key) = protected_key {
        vault.protected_keys.push(protected_key);
    }
    if let Err(error) =
        ProtectedStorageV2::from_vault(vault).and_then(|storage| Storage::V2(storage).write(path))
    {
        vault.protected_keys = old;
        return Err(error);
    }
    Ok(())
}

/// Starts vault setup and optionally enrolls system protection.
fn start_vault_setup(
    path: &Path,
    password: &str,
    use_system: bool,
    reason: &str,
) -> Result<PendingVault, InitializationError> {
    let mut pending = PendingVault::initialize(path, password)?;
    if use_system {
        pending.vault.protected_keys.push(
            system_protection::protect(pending.vault.id, &pending.vault.master_key, reason)
                .map_err(InitializationError::Other)?,
        );
    }
    Ok(pending)
}

/// Commits setup, retaining its pending state if saving fails.
fn complete_vault_setup(path: &Path, pending: PendingVault) -> VaultSetupResult {
    if let Err(error) = pending.commit(path) {
        return VaultSetupResult::SaveFailed(pending, error);
    }
    VaultSetupResult::Completed(pending.vault)
}

/// Unlocks with a recovery key and optionally enrolls system protection.
fn recovery_unlock(
    path: &Path,
    text: &str,
    use_system: bool,
    reason: &str,
) -> Result<Vault, String> {
    let Storage::V2(storage) = Storage::read(path)? else {
        return Err("Expected a V2 vault".to_string());
    };
    let key = recovery::unlock(storage.id, &storage.protected_keys, text)?;
    let mut vault = storage.decrypt(key).map_err(|e| e.to_string())?;
    if use_system && !vault.protected_keys.iter().any(system_protection::is_local) {
        vault.protected_keys.push(system_protection::protect(
            vault.id,
            &vault.master_key,
            reason,
        )?);
        Storage::V2(ProtectedStorageV2::from_vault(&vault)?).write(path)?;
    }
    Ok(vault)
}

/// Unlocks a vault through its local system protection.
fn system_unlock(path: &Path, reason: &str) -> Result<Vault, String> {
    let Storage::V2(storage) = Storage::read(path)? else {
        return Err("Expected a V2 vault".to_string());
    };
    let protected_key = storage
        .protected_keys
        .iter()
        .find(|protected_key| system_protection::is_local(protected_key))
        .ok_or("No system key for this device; use the recovery key")?;
    let key = system_protection::unlock(storage.id, protected_key, reason)?;
    storage.decrypt(key).map_err(|e| e.to_string())
}

/// Creates or authorizes removal of a local system protection record.
fn set_system_protection(
    id: Uuid,
    key: &[u8; KEY_LEN],
    current: Option<&ProtectedVaultKey>,
    enabled: bool,
    reason: &str,
) -> Result<Option<ProtectedVaultKey>, String> {
    let protected_key = if enabled {
        Some(system_protection::protect(id, key, reason)?)
    } else {
        // Removing system protection also requires fresh authorization.
        if let Some(protected_key) = current {
            system_protection::unlock(id, protected_key, reason)?;
        }
        None
    };
    Ok(protected_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_reports_background_failure_and_clears_busy_state() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", Uuid::new_v4()));
        let mut access = VaultAccess::default();
        let (sender, receiver) = mpsc::channel();
        access.system_unlock_in_background(&path, String::new(), move || {
            sender.send(()).unwrap();
        });
        assert!(access.is_busy());
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(access.poll().unwrap().is_err());
        assert!(!access.is_busy());
        assert!(access.poll().is_none());
    }

    #[test]
    fn setup_can_retry_saving_and_unlock_with_recovery() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", Uuid::new_v4()));
        let pending = start_vault_setup(&path, "", false, "").unwrap();
        let recovery_key = pending.recovery_key.clone();
        let id = pending.vault.id;
        assert!(!path.exists());

        std::fs::write(&path, b"changed").unwrap();
        let VaultSetupResult::SaveFailed(pending, _) = complete_vault_setup(&path, pending) else {
            panic!("Expected a recoverable save failure");
        };
        assert_eq!(*pending.recovery_key, *recovery_key);
        assert_eq!(std::fs::read(&path).unwrap(), b"changed");

        std::fs::remove_file(&path).unwrap();
        let VaultSetupResult::Completed(vault) = complete_vault_setup(&path, pending) else {
            panic!("Expected a completed setup");
        };
        let recovered = recovery_unlock(&path, &recovery_key, false, "").unwrap();
        assert_eq!(recovered.id, id);
        assert_eq!(*recovered.master_key, *vault.master_key);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn protection_change_restores_keys_when_saving_fails() {
        let path = std::env::temp_dir().join(format!("factr-{}", Uuid::new_v4()));
        std::fs::write(&path, b"not a directory").unwrap();
        let mut vault = Vault::create(Vec::new());
        let (recovery, _) = recovery::create(vault.id, &vault.master_key).unwrap();
        let original_id = recovery.id;
        vault.protected_keys.push(recovery);
        let extra = ProtectedVaultKey {
            id: Uuid::new_v4(),
            provider: "future-provider".to_string(),
            version: 1,
            metadata: serde_json::Value::Null,
            wrapped_key_b64: "opaque".to_string(),
        };

        assert!(
            apply_system_protection_changes(&path.join("vault.json"), &mut vault, Some(extra))
                .is_err()
        );
        assert_eq!(vault.protected_keys.len(), 1);
        assert_eq!(vault.protected_keys[0].id, original_id);
        std::fs::remove_file(path).unwrap();
    }
}
