use factr_core::vault::Account;
use uuid::Uuid;

use super::{FactrApp, error::AppError};

impl FactrApp {
    /// Adds an account only if the updated vault can be saved.
    pub(super) fn add_account(&mut self, account: Account) -> Result<(), AppError> {
        let vault = self.vault.as_mut().ok_or(AppError::NoVault)?;
        vault.accounts.push(account);
        self.save_account_changes(|accounts| {
            accounts.pop();
        })
    }

    /// Replaces an account while preserving its identity and original metadata.
    pub(super) fn replace_account(
        &mut self,
        id: Uuid,
        mut edited_account: Account,
    ) -> Result<(), AppError> {
        let vault = self.vault.as_mut().ok_or(AppError::NoVault)?;
        let editable_index = vault
            .accounts
            .iter()
            .position(|account| account.id == id)
            .ok_or(AppError::NoAccount)?;
        let editable = &mut vault.accounts[editable_index];
        edited_account.id = editable.id;
        edited_account.created_at = editable.created_at;
        edited_account.custom_position = editable.custom_position;
        edited_account.modified_at = if edited_account.totp == editable.totp {
            editable.modified_at
        } else {
            chrono::Utc::now().timestamp_millis()
        };
        let old = std::mem::replace(editable, edited_account);
        self.save_account_changes(move |accounts| accounts[editable_index] = old)
    }

    /// Deletes an account and compacts its custom position after a successful save.
    pub(super) fn delete_account(&mut self, id: Uuid) -> Result<(), AppError> {
        let vault = self.vault.as_mut().ok_or(AppError::NoVault)?;
        let index = vault
            .accounts
            .iter()
            .position(|account| account.id == id)
            .ok_or(AppError::NoAccount)?;
        let removed = vault.accounts.remove(index);
        for account in &mut vault.accounts {
            if account.custom_position > removed.custom_position {
                account.custom_position -= 1;
            }
        }
        self.save_account_changes(move |accounts| {
            for account in accounts.iter_mut() {
                if account.custom_position >= removed.custom_position {
                    account.custom_position += 1;
                }
            }
            accounts.insert(index, removed);
        })
    }

    /// Saves a visual reorder or restores the previous positions.
    pub(super) fn move_account(&mut self, source: Uuid, target: Uuid) -> Result<(), AppError> {
        let vault = self.vault.as_mut().ok_or(AppError::NoVault)?;
        let position = |id| {
            vault
                .accounts
                .iter()
                .find(|account| account.id == id)
                .map(|account| account.custom_position)
                .ok_or(AppError::NoAccount)
        };
        let from = position(source)?;
        let to = position(target)?;
        let old: Vec<_> = vault.accounts.iter().map(|a| a.custom_position).collect();
        for account in &mut vault.accounts {
            let position = account.custom_position;
            if position == from {
                account.custom_position = to;
            } else if from < to && position > from && position <= to {
                account.custom_position -= 1;
            } else if from > to && position >= to && position < from {
                account.custom_position += 1;
            }
        }
        self.save_account_changes(move |accounts| {
            for (account, position) in accounts.iter_mut().zip(old) {
                account.custom_position = position;
            }
        })
    }

    /// Restores an account change if encryption or file replacement fails.
    fn save_account_changes(
        &mut self,
        rollback: impl FnOnce(&mut Vec<Account>),
    ) -> Result<(), AppError> {
        if let Err(error) = self.save_storage() {
            rollback(&mut self.vault.as_mut().ok_or(AppError::NoVault)?.accounts);
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::MainScreenAction,
        config::Config,
        view::model::{AccountFieldsDisplay, EditDisplay},
    };
    use factr_core::vault::Vault;
    use factr_storage::Storage;
    use std::path::Path;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn account(name: &str, position: usize) -> Account {
        Account::from_manual_with_defaults(None, name.into(), SECRET, position).unwrap()
    }

    fn app(path: &Path) -> FactrApp {
        let mut app = FactrApp::init(Config {
            storage_file: path.to_owned(),
            ..Default::default()
        });
        app.vault = Some(Vault::create(vec![
            account("first", 0),
            account("second", 1),
        ]));
        app
    }

    fn accounts(app: &FactrApp) -> serde_json::Value {
        serde_json::to_value(&app.vault.as_ref().unwrap().accounts).unwrap()
    }

    #[test]
    fn successful_changes_are_saved_with_stable_identity_and_positions() {
        let path = std::env::temp_dir().join(format!("factr-{}.json", Uuid::new_v4()));
        let mut app = app(&path);
        let first = app.vault.as_ref().unwrap().accounts[0].id;
        let second = app.vault.as_ref().unwrap().accounts[1].id;
        let created_at = app.vault.as_ref().unwrap().accounts[0].created_at;
        let third = account("third", 2);
        let third_id = third.id;
        app.add_account(third).unwrap();
        app.replace_account(first, account("edited", 99)).unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().accounts[0].created_at,
            created_at
        );
        app.move_account(first, third_id).unwrap();
        app.delete_account(second).unwrap();
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(vault.accounts[0].id, first);
        assert_eq!(vault.accounts[0].custom_position, 1);
        assert_eq!(vault.accounts[1].custom_position, 0);
        let Storage::V2(storage) = Storage::read(&path).unwrap() else {
            panic!("Expected V2 storage");
        };
        let saved = storage.decrypt(vault.master_key.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(saved.accounts).unwrap(),
            accounts(&app)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_changes_restore_accounts_and_preserve_open_forms() {
        let parent = std::env::temp_dir().join(format!("factr-{}", Uuid::new_v4()));
        std::fs::write(&parent, b"not a directory").unwrap();
        let mut app = app(&parent.join("vault.json"));
        let vault = app.vault.as_mut().unwrap();
        vault.accounts[0].custom_position = 1;
        vault.accounts[1].custom_position = 0;
        let first = vault.accounts[0].id;
        let second = vault.accounts[1].id;
        let original = accounts(&app);
        assert!(app.add_account(account("third", 2)).is_err());
        assert_eq!(accounts(&app), original);
        assert!(app.replace_account(first, account("edited", 0)).is_err());
        assert_eq!(accounts(&app), original);
        assert!(app.move_account(first, second).is_err());
        assert_eq!(accounts(&app), original);
        assert!(app.delete_account(first).is_err());
        assert_eq!(accounts(&app), original);

        app.display.add_display = Some(AccountFieldsDisplay::default());
        let input = app.display.add_display.as_mut().unwrap();
        input.manual.account_name = "third".into();
        input.manual.secret = SECRET.into();
        app.display.add_ui = true;
        let ctx = egui::Context::default();
        app.handle_action(&ctx, MainScreenAction::Add);
        assert!(app.display.add_ui);
        let input = app.display.add_display.as_ref().unwrap();
        assert_eq!(input.manual.secret, SECRET);
        assert!(input.error.is_some());
        assert_eq!(accounts(&app), original);

        app.display.edit_display = Some(EditDisplay::from_account(
            &app.vault.as_ref().unwrap().accounts[0],
        ));
        app.handle_action(&ctx, MainScreenAction::Delete(first));
        assert!(app.display.edit_display.is_some());
        assert_eq!(accounts(&app), original);
        std::fs::remove_file(parent).unwrap();
    }
}
