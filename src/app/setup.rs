use std::path::Path;

use factr_core::vault::Vault;
use factr_storage::{InitializationError, PendingVault, Storage};
use factr_system_protection as system_protection;

use super::{error::AppError, error_messages, task::Task};
use crate::view::{
    model::{
        setup::{
            RecoveryConfirmationDisplay, SetupAction, SetupDisplay, SetupInputDisplay, SetupScreen,
        },
        system_protection::SystemProtectionDisplay,
    },
    widget::setup::SetupForm,
};

#[derive(Default)]
pub(super) struct SetupApp {
    display: SetupDisplay,
    pending: Option<PendingVault>,
    task: Task<SetupTaskResult, AppError>,
}

pub(super) enum SetupResult {
    Cancelled,
    Unlocked(Vault),
}

enum SetupTaskResult {
    ReadyToComplete(PendingVault),
    SaveFailed(PendingVault, InitializationError),
    Completed(Vault),
}

impl SetupApp {
    /// Builds input for a new vault or legacy migration.
    pub(super) fn new(
        storage: Option<&Storage>,
        path: &Path,
        available: bool,
        error: Option<String>,
    ) -> Self {
        Self {
            display: SetupDisplay {
                screen: SetupScreen::Input(SetupInputDisplay {
                    legacy: matches!(storage, Some(Storage::V1(_))),
                    can_create: !path.exists(),
                    use_system: available,
                    ..Default::default()
                }),
                error,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Reports whether setup is running in the background.
    pub(super) fn is_busy(&self) -> bool {
        self.task.is_busy()
    }

    /// Updates the setup choice after a platform check.
    pub(super) fn protection_changed(&mut self, available: bool) {
        if let SetupScreen::Input(input) = &mut self.display.screen {
            input.use_system = available;
        }
    }

    /// Draws setup input and recovery confirmation.
    pub(super) fn show(
        &mut self,
        ui: &mut egui::Ui,
        system: &mut SystemProtectionDisplay,
        busy: bool,
    ) {
        ui.add(SetupForm {
            display: &mut self.display,
            system,
            busy,
        });
        if self.display.action.is_some() || system.action.is_some() {
            ui.ctx().request_repaint();
        }
    }

    /// Applies completed work and starts the requested setup step.
    pub(super) fn update(
        &mut self,
        ctx: &egui::Context,
        path: &Path,
        blocked: bool,
    ) -> Option<SetupResult> {
        if let Some(result) = self.task.poll() {
            match result {
                Ok(result) => {
                    if let Some(vault) = self.handle_result(result) {
                        return Some(SetupResult::Unlocked(vault));
                    }
                }
                Err(error) => self.display.error = Some(error_messages::task_error(error)),
            }
        }
        if blocked || self.is_busy() {
            return None;
        }
        let action = self.display.action.take()?;
        match action {
            SetupAction::Start => {
                let SetupScreen::Input(input) = &mut self.display.screen else {
                    return None;
                };
                if !input.legacy && !input.can_create {
                    return None;
                }
                let password = std::mem::take(&mut input.password);
                let use_system = input.use_system;
                let path = path.to_owned();
                let reason = rust_i18n::t!("access.system-reason").to_string();
                self.task.start(ctx, move || {
                    start_vault_setup(&path, &password, use_system, &reason)
                        .map(SetupTaskResult::ReadyToComplete)
                });
            }
            SetupAction::Complete => {
                let SetupScreen::ConfirmRecovery(confirmation) = &self.display.screen else {
                    return None;
                };
                if !confirmation.saved {
                    return None;
                }
                let pending = self.pending.take()?;
                let path = path.to_owned();
                self.task
                    .start(ctx, move || Ok(complete_vault_setup(&path, pending)));
            }
            SetupAction::Cancel => return Some(SetupResult::Cancelled),
        }
        self.display.error = None;
        None
    }

    /// Retains pending setup on failure and clears secrets after completion.
    fn handle_result(&mut self, result: SetupTaskResult) -> Option<Vault> {
        match result {
            SetupTaskResult::ReadyToComplete(mut pending) => {
                let key = std::mem::take(&mut pending.recovery_key);
                self.pending = Some(pending);
                self.display.screen =
                    SetupScreen::ConfirmRecovery(RecoveryConfirmationDisplay { key, saved: false });
            }
            SetupTaskResult::SaveFailed(pending, error) => {
                self.pending = Some(pending);
                self.display.error = Some(error_messages::initialization_error(&error));
            }
            SetupTaskResult::Completed(vault) => {
                self.pending = None;
                self.display = SetupDisplay::default();
                return Some(vault);
            }
        }
        None
    }
}

/// Starts vault setup and optionally enrolls system protection.
fn start_vault_setup(
    path: &Path,
    password: &str,
    use_system: bool,
    reason: &str,
) -> Result<PendingVault, AppError> {
    let mut pending = PendingVault::initialize(path, password)?;
    if use_system {
        pending
            .vault
            .protected_keys
            .push(system_protection::protect(
                pending.vault.id,
                &pending.vault.master_key,
                reason,
            )?);
    }
    Ok(pending)
}

/// Commits setup, retaining its pending state if saving fails.
fn complete_vault_setup(path: &Path, pending: PendingVault) -> SetupTaskResult {
    if let Err(error) = pending.commit(path) {
        return SetupTaskResult::SaveFailed(pending, error);
    }
    SetupTaskResult::Completed(pending.vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    #[test]
    fn setup_can_retry_saving_and_unlock_with_recovery() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", Uuid::new_v4()));
        let pending = start_vault_setup(&path, "", false, "").unwrap();
        let recovery_key = pending.recovery_key.clone();
        let id = pending.vault.id;
        assert!(!path.exists());

        std::fs::write(&path, b"changed").unwrap();
        let SetupTaskResult::SaveFailed(pending, _) = complete_vault_setup(&path, pending) else {
            panic!("Expected a recoverable save failure");
        };
        assert_eq!(*pending.recovery_key, *recovery_key);
        assert_eq!(std::fs::read(&path).unwrap(), b"changed");

        std::fs::remove_file(&path).unwrap();
        let SetupTaskResult::Completed(vault) = complete_vault_setup(&path, pending) else {
            panic!("Expected a completed setup");
        };
        let original = std::fs::read(&path).unwrap();
        let recovered = super::super::unlock::recovery_unlock(&path, &recovery_key).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(recovered.id, id);
        assert_eq!(*recovered.master_key, *vault.master_key);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn confirmation_survives_save_failure_and_is_cleared_after_completion() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        let pending = PendingVault::initialize(&path, "").unwrap();
        let key = pending.recovery_key.clone();
        let mut app = SetupApp::default();
        app.handle_result(SetupTaskResult::ReadyToComplete(pending));
        let SetupScreen::ConfirmRecovery(confirmation) = &mut app.display.screen else {
            panic!("Expected recovery confirmation");
        };
        assert_eq!(*confirmation.key, *key);
        confirmation.saved = true;
        let pending = app.pending.take().unwrap();
        app.handle_result(SetupTaskResult::SaveFailed(
            pending,
            InitializationError::SourceChanged,
        ));
        let SetupScreen::ConfirmRecovery(confirmation) = &app.display.screen else {
            panic!("Expected retained confirmation");
        };
        assert_eq!(*confirmation.key, *key);
        assert!(confirmation.saved);
        let pending = app.pending.take().unwrap();
        assert!(
            app.handle_result(SetupTaskResult::Completed(pending.vault))
                .is_some()
        );
        assert!(matches!(app.display.screen, SetupScreen::Input(_)));
        assert!(app.pending.is_none());
    }

    #[test]
    fn completion_requires_confirmation_and_existing_files_cannot_be_overwritten() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        let mut app = SetupApp::default();
        let pending = PendingVault::initialize(&path, "").unwrap();
        app.handle_result(SetupTaskResult::ReadyToComplete(pending));
        app.display.action = Some(SetupAction::Complete);
        assert!(
            app.update(&egui::Context::default(), &path, false)
                .is_none()
        );
        assert!(!app.is_busy());
        assert!(app.pending.is_some());
        std::fs::write(&path, b"invalid storage").unwrap();
        let mut app = SetupApp::new(None, &path, false, Some("read failed".to_string()));
        app.display.action = Some(SetupAction::Start);
        app.update(&egui::Context::default(), &path, false);
        assert!(!app.is_busy());
        assert_eq!(std::fs::read(&path).unwrap(), b"invalid storage");
        std::fs::remove_file(path).unwrap();
    }
}
