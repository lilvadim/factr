use std::path::Path;

use factr_core::vault::{KEY_LEN, ProtectedVaultKey, Vault};
use factr_storage::{ProtectedStorageV2, Storage};
use factr_system_protection as provider;
use uuid::Uuid;

use super::task::Task;
use crate::view::{
    model::system_protection::{SystemProtectionAction, SystemProtectionDisplay},
    widget::system_protection::SystemProtectionControl,
};

#[derive(Default)]
pub(super) struct SystemProtectionApp {
    pub(super) display: SystemProtectionDisplay,
    task: Task<SystemProtectionResult>,
}

enum SystemProtectionResult {
    Availability(Result<bool, String>),
    #[cfg(target_os = "windows")]
    SettingsOpened,
    ChangeReady {
        id: Uuid,
        protected_key: Option<ProtectedVaultKey>,
    },
}

impl SystemProtectionApp {
    /// Refreshes the local binding without discarding pending work.
    pub(super) fn reset_for_storage(&mut self, storage: Option<&Storage>) {
        self.display.enabled = storage.is_some_and(is_enabled);
        self.display.check = None;
        self.display.error = None;
        self.display.action = None;
    }

    /// Queues a non-interactive availability check.
    pub(super) fn request_check(&mut self) {
        self.display.action = Some(SystemProtectionAction::Check);
    }

    /// Refreshes the binding after opening a vault.
    pub(super) fn vault_opened(&mut self, vault: &Vault) {
        self.display.enabled = vault.protected_keys.iter().any(provider::is_local);
    }

    /// Reports whether a platform operation is pending.
    pub(super) fn is_busy(&self) -> bool {
        self.task.is_busy()
    }

    /// Draws protection settings and queues requested actions.
    pub(super) fn show(&mut self, ui: &mut egui::Ui, busy: bool) {
        ui.add(SystemProtectionControl {
            display: &mut self.display,
            busy,
        });
        if self.display.action.is_some() {
            ui.ctx().request_repaint();
        }
    }

    /// Applies platform results and starts checks or authorized changes.
    pub(super) fn update(
        &mut self,
        ctx: &egui::Context,
        path: &Path,
        mut vault: Option<&mut Vault>,
        blocked: bool,
    ) -> Option<bool> {
        let mut available = None;
        if let Some(result) = self.task.poll() {
            match result.and_then(|result| self.handle_result(result, vault.as_deref_mut(), path)) {
                Ok(changed) => available = changed,
                Err(error) => self.display.error = Some(error),
            }
        }
        if blocked || self.is_busy() {
            return available;
        }
        if let Some(action) = self.display.action.take() {
            match action {
                SystemProtectionAction::Check => self.task.start(ctx, || {
                    Ok(SystemProtectionResult::Availability(
                        provider::check_availability(),
                    ))
                }),
                #[cfg(target_os = "windows")]
                SystemProtectionAction::OpenSettings => self.task.start(ctx, || {
                    provider::open_settings().map(|_| SystemProtectionResult::SettingsOpened)
                }),
                SystemProtectionAction::SetEnabled(enabled) => {
                    if let Some(vault) = vault {
                        let id = vault.id;
                        let key = vault.master_key.clone();
                        let current = vault
                            .protected_keys
                            .iter()
                            .find(|key| provider::is_local(key))
                            .cloned();
                        let reason = rust_i18n::t!("access.system-reason").to_string();
                        self.task.start(ctx, move || {
                            set_system_protection(id, &key, current.as_ref(), enabled, &reason).map(
                                |protected_key| SystemProtectionResult::ChangeReady {
                                    id,
                                    protected_key,
                                },
                            )
                        });
                    }
                }
            }
            if self.is_busy() {
                self.display.error = None;
            }
        }
        available
    }

    /// Updates readiness or commits a change for the matching open vault.
    fn handle_result(
        &mut self,
        result: SystemProtectionResult,
        vault: Option<&mut Vault>,
        path: &Path,
    ) -> Result<Option<bool>, String> {
        match result {
            SystemProtectionResult::Availability(result) => {
                let available = matches!(result, Ok(true));
                self.display.available = available;
                self.display.check = Some(result);
                Ok(Some(available))
            }
            #[cfg(target_os = "windows")]
            SystemProtectionResult::SettingsOpened => Ok(None),
            SystemProtectionResult::ChangeReady { id, protected_key } => {
                if let Some(vault) = vault.filter(|vault| vault.id == id) {
                    let saved = apply_system_protection_changes(path, vault, protected_key);
                    self.vault_opened(vault);
                    saved?;
                }
                Ok(None)
            }
        }
    }
}

/// Checks whether storage has a protection record for this device.
pub fn is_enabled(storage: &Storage) -> bool {
    match storage {
        Storage::V2(storage) => storage.protected_keys.iter().any(provider::is_local),
        _ => false,
    }
}

/// Applies a protection change atomically, restoring keys if saving fails.
pub fn apply_system_protection_changes(
    path: &Path,
    vault: &mut Vault,
    protected_key: Option<ProtectedVaultKey>,
) -> Result<(), String> {
    let old = vault.protected_keys.clone();
    vault.protected_keys.retain(|key| !provider::is_local(key));
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

/// Creates or authorizes removal of a local system protection record.
fn set_system_protection(
    id: Uuid,
    key: &[u8; KEY_LEN],
    current: Option<&ProtectedVaultKey>,
    enabled: bool,
    reason: &str,
) -> Result<Option<ProtectedVaultKey>, String> {
    let protected_key = if enabled {
        Some(provider::protect(id, key, reason)?)
    } else {
        // Removing system protection also requires fresh authorization.
        if let Some(protected_key) = current {
            provider::unlock(id, protected_key, reason)?;
        }
        None
    };
    Ok(protected_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use factr_core::recovery;
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

    #[test]
    fn availability_checks_keep_diagnostics_and_do_not_enroll_the_vault() {
        let mut app = SystemProtectionApp::default();
        let mut vault = Vault::create(Vec::new());
        let path = std::env::temp_dir().join(format!("factr-{}.json", Uuid::new_v4()));
        let changed = app
            .handle_result(
                SystemProtectionResult::Availability(Ok(true)),
                Some(&mut vault),
                &path,
            )
            .unwrap();
        assert_eq!(changed, Some(true));
        assert!(app.display.available);
        assert!(!app.display.enabled);
        assert!(vault.protected_keys.is_empty());
        assert!(!path.exists());
        app.handle_result(
            SystemProtectionResult::Availability(Err("service unavailable".to_string())),
            None,
            &path,
        )
        .unwrap();
        assert!(!app.display.available);
        assert!(matches!(app.display.check, Some(Err(_))));
    }
}
