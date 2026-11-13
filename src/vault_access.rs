use std::{
    path::Path,
    sync::mpsc::{self, Receiver, TryRecvError},
};

use factr_core::{
    recovery,
    vault::{ProtectedVaultKey, Vault},
};
use factr_storage::{
    InitializationError, PendingVault, ProtectedStorageV2, Storage, migration::MigrationError,
};
use uuid::Uuid;

use factr_system_protection as system_protection;

use crate::view::model::{VaultAccessAction, VaultAccessDisplay, VaultAccessScreen};

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
        self.display.use_system = self.display.system_available;
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
                        if let Err(error) = pending.commit(&path) {
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
                        vault.protected_keys.push(system_protection::protect(
                            vault.id,
                            &vault.master_key,
                            &rust_i18n::t!("access.system-reason"),
                        )?);
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
                    let key = system_protection::unlock(
                        storage.id,
                        protected_key,
                        &rust_i18n::t!("access.system-reason"),
                    )?;
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
                            Some(system_protection::protect(
                                id,
                                &key,
                                &rust_i18n::t!("access.system-reason"),
                            )?)
                        } else {
                            // Removing system protection also requires fresh authorization.
                            if let Some(protected_key) = current {
                                system_protection::unlock(
                                    id,
                                    &protected_key,
                                    &rust_i18n::t!("access.system-reason"),
                                )?;
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

/// Prepares a vault and optionally enrolls system protection.
fn prepare(path: &Path, password: &str, use_system: bool) -> Result<PendingVault, String> {
    let mut pending = PendingVault::initialize(path, password).map_err(|error| match error {
        InitializationError::Migration(MigrationError::Decrypt(_)) => {
            rust_i18n::t!("wrong-password").to_string()
        }
        error => error.to_string(),
    })?;
    if use_system {
        pending
            .vault
            .protected_keys
            .push(system_protection::protect(
                pending.vault.id,
                &pending.vault.master_key,
                &rust_i18n::t!("access.system-reason"),
            )?);
    }
    Ok(pending)
}
