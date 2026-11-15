use std::path::Path;

use factr_core::{recovery, vault::Vault};
use factr_storage::Storage;
use factr_system_protection::{self as system_protection, SystemProtectionError};

use super::{
    error::AppError,
    error_messages,
    task::{Task, TaskError},
};
use crate::view::{
    model::{
        system_protection::SystemProtectionDisplay,
        unlock::{UnlockAction, UnlockDisplay},
    },
    widget::unlock::UnlockForm,
};

#[derive(Default)]
pub(super) struct UnlockApp {
    display: UnlockDisplay,
    task: Task<Vault, AppError>,
}

impl UnlockApp {
    /// Selects an unlock method from this device's protection status.
    pub(super) fn new(system: &SystemProtectionDisplay) -> Self {
        Self {
            display: UnlockDisplay {
                use_recovery_key: !system.system_protection_bound || !system.available,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Queues the initial system unlock prompt after the availability check.
    pub(super) fn request_system_unlock(&mut self) {
        self.display.use_recovery_key = false;
        self.display.action = Some(UnlockAction::System);
    }

    /// Reports whether an unlock operation is pending.
    pub(super) fn is_busy(&self) -> bool {
        self.task.is_busy()
    }

    /// Offers recovery when the existing system binding cannot be used.
    pub(super) fn protection_changed(&mut self, system: &SystemProtectionDisplay) {
        if !system.available || !system.system_protection_bound {
            self.require_recovery();
            if matches!(self.display.action, Some(UnlockAction::System)) {
                self.display.action = None;
            }
        }
    }

    /// Selects recovery without repeatedly taking input focus.
    fn require_recovery(&mut self) {
        if !self.display.use_recovery_key {
            self.display.use_recovery_key = true;
            self.display.need_default_focus = true;
        }
    }

    /// Draws the selected unlock method.
    pub(super) fn show(&mut self, ui: &mut egui::Ui, system: &SystemProtectionDisplay, busy: bool) {
        ui.add(UnlockForm {
            display: &mut self.display,
            system,
            busy,
        });
        if self.display.action.is_some() {
            ui.ctx().request_repaint();
        }
    }

    /// Receives unlock results and starts the selected method.
    pub(super) fn update(
        &mut self,
        ctx: &egui::Context,
        path: &Path,
        blocked: bool,
    ) -> Option<Vault> {
        if let Some(result) = self.task.poll() {
            match result {
                Ok(vault) => {
                    self.display = UnlockDisplay::default();
                    return Some(vault);
                }
                Err(error) => {
                    if !matches!(
                        &error,
                        TaskError::Operation(AppError::SystemProtection(
                            SystemProtectionError::AuthenticationCancelled
                        ))
                    ) {
                        self.require_recovery();
                    }
                    self.display.error = Some(error_messages::task_error(error));
                }
            }
        }
        if blocked || self.is_busy() {
            return None;
        }
        let action = self.display.action.take()?;
        let path = path.to_owned();
        match action {
            UnlockAction::Recovery => {
                let key = std::mem::take(&mut self.display.recovery_key);
                self.task.start(ctx, move || recovery_unlock(&path, &key));
            }
            UnlockAction::System => {
                let reason = rust_i18n::t!("access.system-reason").to_string();
                self.task.start(ctx, move || system_unlock(&path, &reason));
            }
        }
        self.display.error = None;
        None
    }
}

/// Unlocks a vault with its recovery key without modifying the file.
pub(super) fn recovery_unlock(path: &Path, text: &str) -> Result<Vault, AppError> {
    let Storage::V2(storage) = Storage::read(path)? else {
        return Err(AppError::ExpectedV2);
    };
    let key = recovery::unlock(storage.id, &storage.protected_keys, text)?;
    storage.decrypt(key).map_err(AppError::from)
}

/// Unlocks a vault through its local system protection.
fn system_unlock(path: &Path, reason: &str) -> Result<Vault, AppError> {
    let Storage::V2(storage) = Storage::read(path)? else {
        return Err(AppError::ExpectedV2);
    };
    let protected_key = storage
        .protected_keys
        .iter()
        .find(|protected_key| system_protection::is_local(protected_key))
        .ok_or(AppError::MissingSystemKey)?;
    let key = system_protection::unlock(storage.id, protected_key, reason)?;
    storage.decrypt(key).map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_unlock_waits_for_the_initial_availability_check() {
        let mut system = SystemProtectionDisplay {
            system_protection_bound: true,
            ..Default::default()
        };
        let mut app = UnlockApp::new(&system);
        app.request_system_unlock();
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        assert!(app.update(&egui::Context::default(), &path, true).is_none());
        assert!(!app.is_busy());
        assert!(matches!(app.display.action, Some(UnlockAction::System)));
        system.available = true;
        app.protection_changed(&system);
        assert!(!app.display.use_recovery_key);
        assert!(matches!(app.display.action, Some(UnlockAction::System)));
    }

    #[test]
    fn unavailable_protection_selects_recovery_and_cancels_automatic_unlock() {
        let mut system = SystemProtectionDisplay {
            system_protection_bound: true,
            available: true,
            ..Default::default()
        };
        let mut app = UnlockApp::new(&system);
        app.display.need_default_focus = false;
        app.request_system_unlock();
        system.available = false;
        app.protection_changed(&system);
        assert!(app.display.use_recovery_key);
        assert!(app.display.need_default_focus);
        assert!(app.display.action.is_none());
        app.display.need_default_focus = false;
        app.protection_changed(&system);
        assert!(!app.display.need_default_focus);
    }

    #[test]
    fn cancelled_system_unlock_keeps_the_selected_method() {
        let mut app = UnlockApp::default();
        let ctx = egui::Context::default();
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        app.display.need_default_focus = false;
        app.task.start(&ctx, || {
            Err(AppError::SystemProtection(
                SystemProtectionError::AuthenticationCancelled,
            ))
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.is_busy() {
            assert!(std::time::Instant::now() < deadline);
            assert!(app.update(&ctx, &path, false).is_none());
            std::thread::yield_now();
        }
        assert!(!app.display.use_recovery_key);
        assert!(!app.display.need_default_focus);
        assert!(app.display.error.is_none());
        assert!(app.display.action.is_none());
        assert!(!path.exists());
    }

    #[test]
    fn denied_system_unlock_allows_retry_without_recovery() {
        let mut app = UnlockApp::default();
        let ctx = egui::Context::default();
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        app.task.start(&ctx, || {
            Err(AppError::SystemProtection(
                SystemProtectionError::AuthenticationDenied,
            ))
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.is_busy() {
            assert!(std::time::Instant::now() < deadline);
            assert!(app.update(&ctx, &path, false).is_none());
            std::thread::yield_now();
        }
        assert!(!app.display.use_recovery_key);
        assert!(app.display.error.is_some());
        assert!(!path.exists());
    }

    #[test]
    fn failed_unlock_offers_recovery_and_clears_busy_state() {
        let mut app = UnlockApp::default();
        let ctx = egui::Context::default();
        let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
        app.task.start(&ctx, || Err(AppError::MissingSystemKey));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.is_busy() {
            assert!(std::time::Instant::now() < deadline);
            assert!(app.update(&ctx, &path, false).is_none());
            std::thread::yield_now();
        }
        assert!(app.display.use_recovery_key);
        assert_eq!(
            app.display.error.as_deref(),
            Some(error_messages::app_error(&AppError::MissingSystemKey).as_str())
        );
        assert!(!path.exists());
    }
}
