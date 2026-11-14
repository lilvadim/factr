use factr_core::vault::{ProtectedVaultKey, Vault};
use factr_storage::{InitializationError, Storage, migration::MigrationError};
use factr_system_protection as system_protection;
use uuid::Uuid;

use super::FactrApp;
use crate::{
    vault_access::{self, VaultAccessResult, VaultSetupResult},
    view::model::{VaultAccessAction, VaultAccessScreen, VaultSetupAction, VaultSetupScreen},
};

impl FactrApp {
    /// Resets the access flow using the current vault file.
    pub(super) fn reset_access(&mut self) {
        let path = &self.config.storage_file;
        self.access_display.clear_secrets();
        self.access.pending = None;
        self.access_display.error = None;
        let storage = if path.exists() {
            match Storage::read(path) {
                Ok(storage) => Some(storage),
                Err(error) => {
                    self.access_display.error = Some(error);
                    None
                }
            }
        } else {
            None
        };
        self.access_display.screen = match &storage {
            Some(Storage::V1(_)) => VaultAccessScreen::Setup(VaultSetupScreen::Legacy),
            Some(Storage::V2(_)) => VaultAccessScreen::Locked,
            None => VaultAccessScreen::Setup(VaultSetupScreen::Create),
        };
        self.access_display.can_create = !path.exists();
        self.access_display.need_default_focus = true;
        self.access_display.use_system = self.access_display.system_available;
        self.access_display.system_enabled = match &storage {
            Some(Storage::V2(storage)) => storage
                .protected_keys
                .iter()
                .any(system_protection::is_local),
            _ => false,
        };
    }

    /// Processes completed operations and pending access actions.
    pub(super) fn update_access(&mut self, ctx: &egui::Context) {
        let result = self.access.poll();
        if let Some(result) = result {
            self.access_display.busy = false;
            self.handle_access_result(result);
        }
        if self.access_display.busy {
            return;
        }
        let Some(action) = self.access_display.action.take() else {
            return;
        };
        self.handle_access_action(ctx, action);
    }

    /// Updates application and display state from a completed access operation.
    fn handle_access_result(&mut self, result: Result<VaultAccessResult, String>) {
        match result {
            Ok(VaultAccessResult::Setup(result)) => self.handle_setup_result(result),
            Ok(VaultAccessResult::Unlocked(vault)) => self.apply_unlocked_vault(vault),
            Ok(VaultAccessResult::SystemProtectionReady { id, protected_key }) => {
                self.apply_system_protection_changes(id, protected_key);
            }
            Err(error) => self.access_display.error = Some(error),
        }
    }

    /// Updates setup confirmation, errors, or the newly opened vault.
    fn handle_setup_result(&mut self, result: VaultSetupResult) {
        match result {
            VaultSetupResult::ReadyToComplete(mut pending) => {
                self.access_display.recovery_key = std::mem::take(&mut pending.recovery_key);
                self.access.pending = Some(pending);
                self.access_display.screen =
                    VaultAccessScreen::Setup(VaultSetupScreen::ConfirmRecovery);
            }
            VaultSetupResult::SaveFailed(pending, error) => {
                self.access.pending = Some(pending);
                self.access_display.error = Some(error);
            }
            VaultSetupResult::Failed(error) => {
                self.access_display.error = Some(match error {
                    InitializationError::Migration(MigrationError::Decrypt(_)) => {
                        rust_i18n::t!("wrong-password").to_string()
                    }
                    error => error.to_string(),
                });
            }
            VaultSetupResult::Completed(vault) => self.apply_unlocked_vault(vault),
        }
    }

    /// Opens the vault and clears transient access input.
    fn apply_unlocked_vault(&mut self, vault: Vault) {
        self.access_display.system_enabled =
            vault.protected_keys.iter().any(system_protection::is_local);
        self.vault = Some(vault);
        self.access_display.clear_secrets();
        self.display.need_default_focus = true;
    }

    /// Saves a system protection change and updates its displayed state.
    fn apply_system_protection_changes(
        &mut self,
        id: Uuid,
        protected_key: Option<ProtectedVaultKey>,
    ) {
        if let Some(vault) = self.vault.as_mut().filter(|vault| vault.id == id) {
            self.access_display.error = vault_access::apply_system_protection_changes(
                &self.config.storage_file,
                vault,
                protected_key,
            )
            .err();
            self.access_display.system_enabled =
                vault.protected_keys.iter().any(system_protection::is_local);
        }
    }

    /// Handles an access action and starts its background operation.
    fn handle_access_action(&mut self, ctx: &egui::Context, action: VaultAccessAction) {
        let path = &self.config.storage_file;
        let reason = rust_i18n::t!("access.system-reason").to_string();
        let ctx = ctx.clone();
        let notify = move || ctx.request_repaint();
        match action {
            VaultAccessAction::Setup(action) => self.handle_setup_action(action, reason, notify),
            VaultAccessAction::RecoveryUnlock => {
                let text = std::mem::take(&mut self.access_display.input);
                self.access.recovery_unlock_in_background(
                    path,
                    text,
                    self.access_display.use_system,
                    reason,
                    notify,
                );
            }
            VaultAccessAction::SystemUnlock => self
                .access
                .system_unlock_in_background(path, reason, notify),
            VaultAccessAction::SetSystemProtection(enabled) => {
                if let Some(vault) = self.vault.as_ref() {
                    self.access
                        .set_system_protection_in_background(vault, enabled, reason, notify);
                }
            }
        }
        if self.access.is_busy() {
            self.access_display.busy = true;
            self.access_display.error = None;
        }
    }

    /// Handles setup actions before recovery-key confirmation and saving.
    fn handle_setup_action(
        &mut self,
        action: VaultSetupAction,
        reason: String,
        notify: impl FnOnce() + Send + 'static,
    ) {
        let path = &self.config.storage_file;
        match action {
            VaultSetupAction::Start => {
                let password = std::mem::take(&mut self.access_display.input);
                self.access.start_vault_setup_in_background(
                    path,
                    password,
                    self.access_display.use_system,
                    reason,
                    notify,
                );
            }
            VaultSetupAction::Complete => {
                if self.access_display.recovery_saved {
                    // Keep the recovery text visible until the save succeeds.
                    self.access.complete_vault_setup_in_background(path, notify);
                }
            }
            VaultSetupAction::Cancel => self.reset_access(),
        }
    }
}
