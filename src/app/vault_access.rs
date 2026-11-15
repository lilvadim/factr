use factr_core::vault::Vault;
use factr_storage::Storage;

use super::{
    FactrApp,
    setup::{SetupApp, SetupResult},
    unlock::UnlockApp,
};

pub(super) enum VaultAccess {
    Setup(SetupApp),
    Unlock(UnlockApp),
}

impl Default for VaultAccess {
    fn default() -> Self {
        Self::Setup(SetupApp::default())
    }
}

impl VaultAccess {
    /// Reports whether the active access workflow has pending work.
    fn is_busy(&self) -> bool {
        match self {
            Self::Setup(setup) => setup.is_busy(),
            Self::Unlock(unlock) => unlock.is_busy(),
        }
    }
}

impl FactrApp {
    /// Resets access forms from the current vault file.
    pub(super) fn reset_access(&mut self) {
        let path = &self.config.storage_file;
        let mut error = None;
        let storage = path
            .exists()
            .then(|| {
                Storage::read(path)
                    .inspect_err(|err| error = Some(super::error_messages::storage_error(err)))
                    .ok()
            })
            .flatten();
        self.system_protection.reset_for_storage(storage.as_ref());
        self.access = match storage.as_ref() {
            Some(Storage::V2(_)) => {
                VaultAccess::Unlock(UnlockApp::new(&self.system_protection.display))
            }
            _ => VaultAccess::Setup(SetupApp::new(
                storage.as_ref(),
                path,
                self.system_protection.display.available,
                error,
            )),
        };
        self.system_protection.request_check();
    }

    /// Reports whether any access workflow is running.
    pub(super) fn access_busy(&self) -> bool {
        self.access.is_busy() || self.system_protection.is_busy()
    }

    /// Coordinates independent access workflows and their application-wide outcomes.
    pub(super) fn update_access(&mut self, ctx: &egui::Context) {
        let blocked = self.access.is_busy();
        let changed = self.system_protection.update(
            ctx,
            &self.config.storage_file,
            self.vault.as_mut(),
            blocked,
        );
        if self.vault.is_some() {
            return;
        }
        let blocked = self.system_protection.is_busy();
        match &mut self.access {
            VaultAccess::Setup(setup) => {
                if let Some(available) = changed {
                    setup.protection_changed(available);
                }
                match setup.update(ctx, &self.config.storage_file, blocked) {
                    Some(SetupResult::Cancelled) => self.reset_access(),
                    Some(SetupResult::Unlocked(vault)) => self.apply_unlocked_vault(vault),
                    None => {}
                }
            }
            VaultAccess::Unlock(unlock) => {
                if changed.is_some() {
                    unlock.protection_changed(&self.system_protection.display);
                }
                if let Some(vault) = unlock.update(ctx, &self.config.storage_file, blocked) {
                    self.apply_unlocked_vault(vault);
                }
            }
        }
    }

    /// Draws the active access workflow.
    pub(super) fn display_access(&mut self, ui: &mut egui::Ui) {
        let busy = self.access_busy();
        match &mut self.access {
            VaultAccess::Setup(setup) => setup.show(ui, &mut self.system_protection.display, busy),
            VaultAccess::Unlock(unlock) => unlock.show(ui, &self.system_protection.display, busy),
        }
    }

    /// Opens a returned vault and restores the main screen's initial focus.
    fn apply_unlocked_vault(&mut self, vault: Vault) {
        self.system_protection.vault_opened(&vault);
        self.access = VaultAccess::Unlock(UnlockApp::new(&self.system_protection.display));
        self.vault = Some(vault);
        self.display.need_default_focus = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::system_protection::SystemProtectionApp,
        config::Config,
        view::model::{AppDisplay, system_protection::SystemProtectionAction},
    };

    #[test]
    fn initial_setup_queues_availability_check_without_running_it_inline() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        let app = FactrApp::init(Config {
            storage_file: path,
            ..Default::default()
        });
        assert!(matches!(app.access, VaultAccess::Setup(_)));
        assert!(matches!(
            app.system_protection.display.action,
            Some(SystemProtectionAction::Check)
        ));
        assert!(app.system_protection.display.check.is_none());
        assert!(!app.system_protection.is_busy());
    }

    #[test]
    fn opening_replaces_setup_and_locking_queues_a_fresh_check() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        let mut app = FactrApp {
            config: Config {
                storage_file: path.clone(),
                ..Default::default()
            },
            display: AppDisplay::default(),
            access: VaultAccess::default(),
            system_protection: SystemProtectionApp::default(),
            vault: None,
            error: None,
        };
        app.apply_unlocked_vault(Vault::create(Vec::new()));
        assert!(app.vault.is_some());
        assert!(matches!(app.access, VaultAccess::Unlock(_)));
        app.lock_vault().unwrap();
        assert!(app.vault.is_none());
        assert!(matches!(app.access, VaultAccess::Unlock(_)));
        assert!(matches!(
            app.system_protection.display.action,
            Some(SystemProtectionAction::Check)
        ));
        std::fs::remove_file(path).unwrap();
    }
}
