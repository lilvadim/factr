use std::time::{Duration, Instant};

use egui::Event;

use super::{FactrApp, MainScreenAction};

pub(super) struct AutoLockTimer {
    last_activity: Instant,
}

impl Default for AutoLockTimer {
    fn default() -> Self {
        Self {
            last_activity: Instant::now(),
        }
    }
}

impl AutoLockTimer {
    /// Starts a fresh inactivity interval.
    pub(super) fn reset(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Records input while preserving an already expired deadline.
    fn remaining(&mut self, now: Instant, timeout: Duration, events: &[Event]) -> Duration {
        let remaining = timeout.saturating_sub(now.duration_since(self.last_activity));
        if remaining.is_zero() {
            return Duration::ZERO;
        }
        if events.iter().any(is_activity) {
            self.last_activity = now;
            timeout
        } else {
            remaining
        }
    }
}

/// Counts deliberate input rather than pointer movement or focus changes.
fn is_activity(event: &Event) -> bool {
    matches!(
        event,
        Event::Key { .. }
            | Event::Text(_)
            | Event::Ime(_)
            | Event::Copy
            | Event::Cut
            | Event::Paste(_)
            | Event::PasteImage(_)
            | Event::MiddleClickPaste { .. }
            | Event::PointerButton { .. }
            | Event::MouseWheel { .. }
            | Event::Zoom(_)
            | Event::Rotate(_)
            | Event::Touch { .. }
            | Event::AccessKitActionRequest(_)
    )
}

impl FactrApp {
    /// Locks an idle vault and schedules the next deadline check.
    pub(super) fn update_auto_lock(&mut self, ctx: &egui::Context) {
        if !self.is_vault_unlocked() {
            return;
        }
        let Some(timeout) = self.config.auto_lock.duration() else {
            return;
        };
        let remaining = ctx.input(|input| {
            self.auto_lock
                .remaining(Instant::now(), timeout, &input.events)
        });
        if remaining.is_zero() {
            self.handle_action(ctx, MainScreenAction::LockVault);
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_deliberate_input_restarts_the_timer() {
        let start = Instant::now();
        let mut timer = AutoLockTimer {
            last_activity: start,
        };
        let timeout = Duration::from_secs(60);
        assert_eq!(
            timer.remaining(
                start + Duration::from_secs(20),
                timeout,
                &[
                    Event::PointerMoved(egui::Pos2::ZERO),
                    Event::WindowFocused(true)
                ],
            ),
            Duration::from_secs(40)
        );
        assert_eq!(
            timer.remaining(
                start + Duration::from_secs(30),
                timeout,
                &[Event::Text("test".into())],
            ),
            timeout
        );
        assert_eq!(
            timer.remaining(start + Duration::from_secs(50), timeout, &[]),
            Duration::from_secs(40)
        );
    }

    #[test]
    fn input_cannot_extend_an_expired_deadline() {
        let start = Instant::now();
        let mut timer = AutoLockTimer {
            last_activity: start,
        };
        assert!(
            timer
                .remaining(
                    start + Duration::from_secs(60),
                    Duration::from_secs(60),
                    &[Event::Text("test".into())],
                )
                .is_zero()
        );
    }

    #[test]
    fn automatic_lock_discards_forms_only_when_enabled() {
        use crate::{
            config::{AutoLockTimeout, Config},
            view::model::{AccountFieldsDisplay, EditDisplay, SettingsDisplay},
        };
        use factr_core::vault::{Account, Vault};

        for timeout in [AutoLockTimeout::Disabled, AutoLockTimeout::OneMinute] {
            let path = std::env::temp_dir().join(format!("factr-{}.json", uuid::Uuid::new_v4()));
            let mut app = FactrApp::init(Config {
                storage_file: path.clone(),
                auto_lock: timeout,
                ..Default::default()
            });
            let account = Account::from_manual_with_defaults(
                None,
                "test".into(),
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                0,
            )
            .unwrap();
            app.display.edit_display = Some(EditDisplay::from_account(&account));
            app.display.add_display = Some(AccountFieldsDisplay::default());
            app.display.add_ui = true;
            app.display.settings_ui = true;
            app.display.settings_display = Some(SettingsDisplay::from_config(&app.config));
            app.vault = Some(Vault::create(vec![account]));
            app.auto_lock.last_activity = Instant::now() - Duration::from_secs(60);
            app.update_auto_lock(&egui::Context::default());

            if timeout == AutoLockTimeout::Disabled {
                assert!(app.vault.is_some());
                assert!(app.display.edit_display.is_some());
                assert!(app.display.add_ui);
                assert!(!path.exists());
            } else {
                assert!(app.vault.is_none());
                assert!(app.display.edit_display.is_none());
                assert!(app.display.add_display.is_none());
                assert!(!app.display.add_ui);
                assert!(!app.display.settings_ui);
                assert!(app.display.settings_display.is_none());
                assert!(matches!(
                    factr_storage::Storage::read(&path).unwrap(),
                    factr_storage::Storage::V2(_)
                ));
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    #[test]
    fn save_failure_does_not_leave_the_vault_unlocked() {
        use crate::config::{AutoLockTimeout, Config};
        use factr_core::vault::Vault;

        let path = std::env::temp_dir().join(format!("factr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let mut app = FactrApp::init(Config {
            storage_file: path.clone(),
            auto_lock: AutoLockTimeout::OneMinute,
            ..Default::default()
        });
        app.vault = Some(Vault::create(Vec::new()));
        app.auto_lock.last_activity = Instant::now() - Duration::from_secs(60);
        app.update_auto_lock(&egui::Context::default());
        assert!(app.vault.is_none());
        assert!(app.error.is_some());
        std::fs::remove_dir(path).unwrap();
    }
}
