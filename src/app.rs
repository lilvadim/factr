use crate::config;
use crate::display::AccountDisplay;
use crate::display::SettingsDisplay;
use crate::display::VaultDisplay;
use crate::encrypted_storage::Storage;
use crate::ui;
use crate::vault;
use std::{path::Path, sync::Arc};

use egui::Button;
use egui::DragValue;
use egui::Frame;
use egui::Id;
use egui::Key;
use egui::Ui;
use egui::ViewportCommand;
use egui::Widget;
use egui::Window;
use egui::WindowLevel;
use egui::{Color32, ComboBox, RichText, Stroke, TextEdit};
use totp_rs::Algorithm;

use crate::{
    config::Config,
    vault::{Account, Password, Vault},
};

pub struct FactrApp {
    config: Config,
    display: AppDisplay,
    is_initialized: bool,
    vault: Option<Vault>,
    error: Option<String>,
}

impl eframe::App for FactrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            self.ui(ui);
        });
        let close_shortcut = ctx.input(|i| i.key_pressed(Key::W) && i.modifiers.mac_cmd);
        if close_shortcut {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
    }
}

impl FactrApp {
    /// Setup default font and icon font
    pub fn setup_fonts(ctx: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();

        // Regular
        let ibm_plex = "IBM Plex Sans";
        fonts.font_data.insert(
            ibm_plex.to_owned(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/IBMPlexSans-VariableFont_wdth,wght.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, ibm_plex.to_owned());

        // Mono
        let jet_brains_mono = "JetBrains Mono";
        fonts.font_data.insert(
            jet_brains_mono.to_owned(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/JetBrainsMono-VariableFont_wght.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .insert(0, jet_brains_mono.to_owned());

        // Icons
        let phosphor = "Phosphor";
        fonts.font_data.insert(
            phosphor.to_owned(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/Phosphor.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(1, phosphor.to_owned());
        fonts
            .families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .insert(1, phosphor.to_owned());

        ctx.set_fonts(fonts);
    }

    pub fn init(config: Config) -> Self {
        let is_initialized = is_initialized(&config.storage_file);
        Self {
            is_initialized,
            vault: None,
            error: None,
            display: AppDisplay::default(),
            config,
        }
    }

    fn lock_vault(&mut self) -> Result<(), String> {
        self.save_storage()?;
        let _ = self.vault.take();
        Ok(())
    }

    fn unlock_vault(&mut self) -> Result<(), String> {
        if self.display.password.is_empty() {
            return Err("Password is empty!".to_string());
        }
        let storage: Storage = serde_json::from_str(
            &std::fs::read_to_string(&self.config.storage_file).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        self.vault = Some(Vault::decrypt_storage(&self.display.password, &storage)?);
        self.display.password = "".to_string();
        Ok(())
    }

    fn is_vault_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    fn ui(&mut self, ui: &mut Ui) {
        let actions = self.display(ui);
        self.handle_actions(ui.ctx(), actions);
    }

    fn display_setup(setup_display: &mut SetupDisplay, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        ui.heading("Hello!");
        ui.add_space(ui.spacing().item_spacing.y);
        ui.strong("You need a password to secure your codes.");
        ui.label("Sensitive data is encrypted with the password and stored on disk.");
        ui.label("This password will be asked every time you open the app to unlock the vault.");
        ui.strong("Remember it.");
        ui.add_space(ui.spacing().item_spacing.y * 4f32);
        ui.label("Enter Password:");
        TextEdit::singleline(&mut setup_display.password)
            .hint_text("Password")
            .password(true)
            .show(ui);
        if ui.button("Ok").clicked() {
            actions.push(UiAction::Setup);
        }
        if let Some(error) = &setup_display.error {
            Self::display_error(ui, error);
        }
        actions
    }

    fn display(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        if !self.is_initialized {
            Self::display_setup(self.display.setup_display.get_or_insert_default(), ui)
        } else {
            self.display_main(ui)
        }
    }

    fn display_add(display: &mut AddDisplay, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        let method_name = |method: &AddMethod| match method {
            AddMethod::OtpAuthUrl => "OTP Auth URL",
            AddMethod::ManualInput => "Manual Input",
        };
        ComboBox::from_label("Input Method")
            .selected_text(method_name(&display.method))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut display.method,
                    AddMethod::OtpAuthUrl,
                    method_name(&AddMethod::OtpAuthUrl),
                );
                ui.selectable_value(
                    &mut display.method,
                    AddMethod::ManualInput,
                    method_name(&AddMethod::ManualInput),
                );
            });
        match display.method {
            AddMethod::OtpAuthUrl => {
                TextEdit::singleline(&mut display.otp_auth_url)
                    .hint_text(method_name(&display.method))
                    .show(ui);
            }
            AddMethod::ManualInput => {
                ui.horizontal(|ui| {
                    ui.label("Issuer");
                    ui.text_edit_singleline(&mut display.manual.issuer);
                });
                ui.horizontal(|ui| {
                    ui.label("Account");
                    ui.text_edit_singleline(&mut display.manual.account_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Secret");
                    ui.text_edit_singleline(&mut display.manual.secret);
                });
                ui.checkbox(&mut display.extra_input, "Additional...");
                if display.extra_input {
                    let mut manual_extra = display.manual_extra.get_or_insert_default();
                    if ui.button("Restore Defaults").clicked() {
                        manual_extra = display.manual_extra.insert(ManualInputExtra::default());
                    }
                    ui.horizontal(|ui| {
                        ui.label("Algorithm");
                        ComboBox::from_id_salt(Id::new("manual_extra.algo"))
                            .selected_text(manual_extra.algo.to_string())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut manual_extra.algo,
                                    Algorithm::SHA1,
                                    Algorithm::SHA1.to_string(),
                                );
                                ui.selectable_value(
                                    &mut manual_extra.algo,
                                    Algorithm::SHA256,
                                    Algorithm::SHA256.to_string(),
                                );
                                ui.selectable_value(
                                    &mut manual_extra.algo,
                                    Algorithm::SHA512,
                                    Algorithm::SHA512.to_string(),
                                );
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Digits");
                        DragValue::new(&mut manual_extra.digits).range(6..=8).ui(ui);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Period");
                        DragValue::new(&mut manual_extra.period)
                            .range(5..=300)
                            .ui(ui);
                    });
                }
            }
        }
        if let Some(error) = &display.error {
            Self::display_error(ui, error);
        }
        if ui.button("Add").clicked() {
            actions.push(UiAction::Add);
        }
        actions
    }

    fn display_top_bar(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        ui.horizontal(|ui| {
            let filter = TextEdit::singleline(&mut self.display.filter_search)
                .hint_text("Filter...")
                .ui(ui);
            if self.display.search_focus {
                filter.request_focus();
            }
            ui.add_space(ui.spacing().item_spacing.x);
            if ui.button("Lock Vault").clicked() {
                actions.push(UiAction::LockVault);
            }
            if ui.button("Add New Code").clicked() {
                self.display.add_ui = true;
            }
            if ui.button("Settings").clicked() {
                self.display.settings_ui = true;
            }
        });
        actions
    }

    fn display_settings(settings: &mut SettingsDisplay, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        ui.vertical(|ui| {
            if ui
                .checkbox(&mut settings.close_after_copy, "Close After Copy")
                .clicked()
            {
                actions.push(UiAction::UpdateConfiguration);
            }
            if ui
                .checkbox(&mut settings.always_on_top, "Always on Top")
                .clicked()
            {
                actions.push(UiAction::UpdateConfiguration);
            }
        });
        actions
    }

    fn display_main(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();

        Window::new("Add New Code")
            .collapsible(false)
            .open(&mut self.display.add_ui)
            .show(ui.ctx(), |ui| {
                actions.extend(Self::display_add(
                    self.display.add_display.get_or_insert_default(),
                    ui,
                ));
            });
        Window::new("Settings")
            .collapsible(false)
            .open(&mut self.display.settings_ui)
            .show(ui.ctx(), |ui| {
                actions.extend(Self::display_settings(
                    self.display
                        .settings_display
                        .get_or_insert(SettingsDisplay::from_config(&self.config)),
                    ui,
                ));
            });

        self.display.search_focus = !self.display.add_ui;

        if self.is_vault_unlocked() {
            if let Some(error) = &self.error {
                Self::display_error(ui, error);
            }
            actions.extend(self.display_top_bar(ui));
            ui.add_space(ui.spacing().item_spacing.y);

            ui.horizontal_top(|ui| {
                let mut accounts: Vec<_> = self
                    .vault
                    .as_ref()
                    .map(VaultDisplay::from_vault)
                    .unwrap()
                    .expect("Cannot display")
                    .accounts
                    .into_iter()
                    .enumerate()
                    .map(|(i, acc)| {
                        (
                            i,
                            Self::filter_search_rate(&acc, &self.display.filter_search),
                            acc,
                        )
                    })
                    .filter(|(_i, rate, _acc)| *rate > 0)
                    .collect();
                if !self.display.filter_search.is_empty() {
                    accounts.sort_by(|(_, a_rate, _), (_, b_rate, _)| b_rate.cmp(a_rate));
                }
                accounts.into_iter().for_each(|(i, _, acc)| {
                    let response = ui::account_ui(ui, &acc);
                    if response.clicked() {
                        ui.ctx().copy_text(acc.code.to_owned());
                        if self.config.close_after_copy {
                            ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                        }
                    }
                    response.context_menu(|ui| {
                        if ui.button("Delete").clicked() {
                            actions.push(UiAction::Delete(i));
                        }
                    });
                });
            });
        } else {
            Frame::new().inner_margin(25.0).show(ui, |ui| {
                ui.heading("Vault is locked");
                ui.add_space(ui.spacing().item_spacing.y);
                TextEdit::singleline(&mut self.display.password)
                    .hint_text("Enter password")
                    .password(true)
                    .show(ui)
                    .response
                    .request_focus();
                ui.add_space(ui.spacing().item_spacing.y);
                if Button::new(RichText::new("Unlock Vault").strong())
                    .ui(ui)
                    .clicked()
                    || ui.input(|i| i.key_pressed(Key::Enter))
                {
                    actions.push(UiAction::UnlockVault);
                }
                if let Some(error) = &self.error {
                    ui.add_space(ui.spacing().item_spacing.y);
                    Self::display_error(ui, error);
                }
            });
        }
        actions
    }

    fn filter_search_rate(account: &AccountDisplay, query: &str) -> u32 {
        if query.is_empty() {
            return 1;
        }

        let issuer = account.issuer.to_owned().unwrap_or_default().to_lowercase();
        let account_name = account.account_name.to_lowercase();
        let query = query.to_lowercase();

        let mut rank = 0u32;

        rank += issuer.matches(&query).count() as u32;
        rank += account_name.matches(&query).count() as u32;

        if issuer.starts_with(&query) {
            rank += 10;
        }
        if account_name.starts_with(&query) {
            rank += 5;
        }

        rank
    }

    fn handle_actions(&mut self, ctx: &egui::Context, actions: Vec<UiAction>) {
        actions
            .into_iter()
            .for_each(|action| self.handle_action(ctx, action));
    }

    fn handle_action(&mut self, ctx: &egui::Context, action: UiAction) {
        match action {
            UiAction::UnlockVault => {
                self.error = self.unlock_vault().err();
            }
            UiAction::LockVault => {
                self.error = self.lock_vault().err();
            }
            UiAction::Setup => {
                self.finish_setup();
            }
            UiAction::Add => {
                let display = self.display.add_display.get_or_insert_default();
                let account_result = match display.method {
                    AddMethod::ManualInput => {
                        let issuer = display.manual.issuer.to_owned();
                        let issuer = if issuer.is_empty() {
                            None
                        } else {
                            Some(issuer)
                        };
                        if display.extra_input
                            && let Some(extra) = &display.manual_extra
                        {
                            Account::from_manual(
                                issuer,
                                display.manual.account_name.to_owned(),
                                extra.algo,
                                extra.digits,
                                extra.period,
                                display.manual.secret.to_owned(),
                            )
                        } else {
                            Account::from_manual_with_defaults(
                                issuer,
                                display.manual.account_name.to_owned(),
                                display.manual.secret.to_owned(),
                            )
                        }
                    }
                    AddMethod::OtpAuthUrl => Account::from_otp_auth_url(&display.otp_auth_url),
                };
                let result = account_result.and_then(|account| {
                    self.vault
                        .as_mut()
                        .map(|vault| vault.accounts.push(account))
                        .ok_or("No Vault".to_string())
                });
                if result.is_ok() {
                    self.error = self.save_storage().err();
                } else {
                    display.error = result.err();
                }
            }
            UiAction::Delete(idx) => {
                self.error = self
                    .vault
                    .as_mut()
                    .ok_or("No Vault".to_string())
                    .map(|vault| vault.accounts.remove(idx))
                    .and_then(|_| self.save_storage())
                    .err();
            }
            UiAction::UpdateConfiguration => {
                if let Some(settings_display) = &self.display.settings_display {
                    self.config.close_after_copy = settings_display.close_after_copy;
                    self.config.always_on_top = settings_display.always_on_top;

                    if self.config.always_on_top {
                        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
                            WindowLevel::AlwaysOnTop,
                        ));
                    } else {
                        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(WindowLevel::Normal));
                    }

                    self.error = config::save_to_dot_config(&self.config).err();
                }
            }
        }
    }

    fn finish_setup(&mut self) {
        let setup = self.display.setup_display.take().expect("No Setup");

        self.display.password = setup.password.to_owned();
        let result = Password::from_string(setup.password.to_owned())
            .map_err(|e| e.to_string())
            .and_then(|password| Vault::initialize(&password))
            .and_then(|vault| Storage::encrypt_vault(&vault))
            .and_then(|storage| write_storage_file(&self.config.storage_file, storage))
            .map_err(|e| format!("Storage Initialization Error: {e}"))
            .and_then(|_| {
                self.unlock_vault()
                    .map_err(|e| format!("Vault Unlock Error: {e}"))
            });

        self.is_initialized = result.is_ok();
        if result.is_err() {
            self.display.setup_display.insert(setup).error = result.err();
        }
    }

    fn display_error(ui: &mut Ui, error: &String) {
        Frame::new()
            .corner_radius(10.0)
            .stroke(Stroke::new(2.0_f32, Color32::LIGHT_RED))
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.label(RichText::new("Error").heading().color(Color32::LIGHT_RED));
                ui.label(error);
            });
    }

    fn save_storage(&self) -> Result<(), String> {
        Storage::encrypt_vault(self.vault.as_ref().ok_or("No Vault".to_string())?)
            .and_then(|storage| write_storage_file(&self.config.storage_file, storage))
    }
}

#[derive(Default)]
struct AppDisplay {
    filter_search: String,
    password: String,
    setup_display: Option<SetupDisplay>,
    add_ui: bool,
    add_display: Option<AddDisplay>,
    search_focus: bool,
    settings_ui: bool,
    settings_display: Option<SettingsDisplay>,
}

#[derive(Default)]
struct SetupDisplay {
    password: String,
    error: Option<String>,
}

#[derive(Default)]
struct AddDisplay {
    method: AddMethod,
    otp_auth_url: String,
    manual: ManualInput,
    extra_input: bool,
    manual_extra: Option<ManualInputExtra>,
    error: Option<String>,
}

#[derive(PartialEq, Eq, Default)]
enum AddMethod {
    OtpAuthUrl,
    #[default]
    ManualInput,
}

enum UiAction {
    UnlockVault,
    LockVault,
    Setup,
    Add,
    Delete(usize),
    UpdateConfiguration,
}

#[derive(Default)]
struct ManualInput {
    issuer: String,
    account_name: String,
    secret: String,
}

struct ManualInputExtra {
    algo: Algorithm,
    period: u64,
    digits: usize,
}

impl Default for ManualInputExtra {
    fn default() -> Self {
        Self {
            algo: vault::DEFAULT_ALGO,
            period: vault::DEFAULT_PERIOD,
            digits: vault::DEFAULT_DIGITS,
        }
    }
}

fn is_initialized(storage_file: &Path) -> bool {
    storage_file.exists()
}

fn write_storage_file(path: &Path, storage: Storage) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create config dir: {e}"))?;
    }
    let json = serde_json::to_string(&storage).map_err(|e| format!("Serialization Error: {e}"))?;
    std::fs::write(path, &json).map_err(|e| format!("File Write Error: {e}"))?;
    Ok(())
}
