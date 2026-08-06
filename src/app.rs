use crate::config;
use crate::display::AccountDisplay;
use crate::display::SettingsDisplay;
use crate::display::VaultDisplay;
use crate::encrypted_storage::Storage;
use crate::phosphor;
use crate::ui;
use crate::vault;
use crate::vault::VaultDecryptError;
use std::{path::Path, sync::Arc};

use egui::Button;
use egui::DragValue;
use egui::Frame;
use egui::Id;
use egui::Key;
use egui::Response;
use egui::Tooltip;
use egui::Ui;
use egui::ViewportCommand;
use egui::Widget;
use egui::Window;
use egui::WindowLevel;
use egui::{Color32, ComboBox, RichText, Stroke, TextEdit};
use rust_i18n::t;
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
        #[cfg(target_os = "macos")]
        {
            let close_shortcut = ctx.input(|i| i.key_pressed(Key::W) && i.modifiers.mac_cmd);
            if close_shortcut {
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
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
        let ibm_plex_mono = "IBM Plex Mono";
        fonts.font_data.insert(
            ibm_plex_mono.to_owned(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/IBMPlexMono-Regular.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&egui::FontFamily::Monospace)
            .unwrap()
            .insert(0, ibm_plex_mono.to_owned());

        // Icons
        let phosphor = "Phosphor";
        fonts.font_data.insert(
            phosphor.to_owned(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/Phosphor-Fill.ttf"
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
        let storage: Storage = serde_json::from_str(
            &std::fs::read_to_string(&self.config.storage_file).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        self.vault = Some(
            Vault::decrypt_storage(&self.display.password, &storage).map_err(|e| match e {
                VaultDecryptError::DecryptFailed => t!("wrong-password").to_string(),
                VaultDecryptError::Other(str) => str,
            })?,
        );
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
        ui.heading(t!("setup.title"));
        ui.add_space(ui.spacing().item_spacing.y);
        ui.strong(t!("setup.about-need"));
        ui.label(t!("setup.about-disk"));
        ui.label(t!("setup.about-vault"));
        ui.strong(t!("setup.remember"));
        ui.add_space(ui.spacing().item_spacing.y * 4f32);
        ui.label(format!("{}:", t!("setup.enter-password")));
        TextEdit::singleline(&mut setup_display.password)
            .hint_text(t!("password"))
            .password(true)
            .show(ui);
        if ui.button(t!("ok")).clicked() {
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
            AddMethod::OtpAuthUrl => "OTP Auth URL".to_string(),
            AddMethod::ManualInput => t!("add.manual-input").to_string(),
        };
        ComboBox::from_label(t!("add.method"))
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
                    ui.label(t!("account.issuer"));
                    TextEdit::singleline(&mut display.manual.issuer)
                        .hint_text(t!("account.issuer"))
                        .ui(ui);
                });
                ui.horizontal(|ui| {
                    ui.label(t!("account.name"));
                    TextEdit::singleline(&mut display.manual.account_name)
                        .hint_text(t!("account.name"))
                        .ui(ui);
                });
                ui.horizontal(|ui| {
                    ui.label(t!("account.secret"));
                    TextEdit::singleline(&mut display.manual.secret)
                        .hint_text(t!("account.secret"))
                        .ui(ui);
                });
                ui.checkbox(
                    &mut display.extra_input,
                    format!("{}...", t!("add.additional")),
                );
                if display.extra_input {
                    let mut manual_extra = display.manual_extra.get_or_insert_default();
                    if ui.button(t!("add.restore-defaults")).clicked() {
                        manual_extra = display.manual_extra.insert(ManualInputExtra::default());
                    }
                    ui.horizontal(|ui| {
                        ui.label(t!("account.algorithm"));
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
                        ui.label(t!("account.digits"));
                        DragValue::new(&mut manual_extra.digits).range(6..=8).ui(ui);
                    });
                    ui.horizontal(|ui| {
                        ui.label(t!("account.period"));
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
        if ui.button(t!("add.add")).clicked() {
            actions.push(UiAction::Add);
        }
        actions
    }

    fn display_top_bar(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        ui.horizontal(|ui| {
            let filter = TextEdit::singleline(&mut self.display.filter_search)
                .hint_text(format!("{}...", t!("filter-search")))
                .ui(ui);
            if self.display.search_focus
                || ui.input(|i| i.key_pressed(Key::F) && i.modifiers.command)
            {
                filter.request_focus();
                self.display.search_focus = false;
            }
            if Self::toolbar_button(
                ui,
                self.config.toolbar_labels,
                phosphor::LOCK,
                t!("lock-vault"),
            )
            .clicked()
            {
                actions.push(UiAction::LockVault);
            }
            if Self::toolbar_button(
                ui,
                self.config.toolbar_labels,
                phosphor::PLUS,
                t!("add-code"),
            )
            .clicked()
            {
                self.display.add_ui = true;
            }
            if Self::toolbar_button(
                ui,
                self.config.toolbar_labels,
                phosphor::GEAR,
                t!("settings-label"),
            )
            .clicked()
            {
                self.display.settings_ui = true;
            }
        });
        actions
    }

    fn toolbar_button(
        ui: &mut Ui,
        show_label: bool,
        icon: impl AsRef<str>,
        label: impl AsRef<str>,
    ) -> Response {
        let btn = Button::new(if show_label {
            format!("{} {}", icon.as_ref(), label.as_ref())
        } else {
            icon.as_ref().to_string()
        })
        .ui(ui);
        if !show_label {
            Tooltip::for_enabled(&btn).show(|ui| ui.label(label.as_ref()));
        }
        btn
    }

    fn display_settings(settings: &mut SettingsDisplay, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        ui.vertical(|ui| {
            if ui
                .checkbox(
                    &mut settings.close_after_copy,
                    t!("settings.close-after-copy"),
                )
                .clicked()
            {
                actions.push(UiAction::UpdateConfiguration);
            }
            if ui
                .checkbox(&mut settings.always_on_top, t!("settings.always-on-top"))
                .clicked()
            {
                actions.push(UiAction::UpdateConfiguration);
            }
            if ui
                .checkbox(&mut settings.toolbar_labels, t!("settings.toolbar-labels"))
                .clicked()
            {
                actions.push(UiAction::UpdateConfiguration);
            }
        });
        actions
    }

    fn display_main(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();

        Window::new(t!("add-code"))
            .collapsible(false)
            .open(&mut self.display.add_ui)
            .show(ui.ctx(), |ui| {
                actions.extend(Self::display_add(
                    self.display.add_display.get_or_insert_default(),
                    ui,
                ));
            });
        Window::new(t!("settings-label"))
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
                        if ui.button(t!("delete")).clicked() {
                            actions.push(UiAction::Delete(i));
                        }
                    });
                });
            });
        } else {
            Frame::new().inner_margin(25.0).show(ui, |ui| {
                ui.heading(format!("{} {}", phosphor::VAULT, t!("vault-locked")));
                ui.add_space(ui.spacing().item_spacing.y);
                TextEdit::singleline(&mut self.display.password)
                    .hint_text(t!("enter-password"))
                    .password(true)
                    .show(ui)
                    .response
                    .request_focus();
                ui.add_space(ui.spacing().item_spacing.y);
                if Button::new(RichText::new(t!("unlock-vault")).strong())
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
                self.display.search_focus = true;
            }
            UiAction::LockVault => {
                self.error = self.lock_vault().err();
            }
            UiAction::Setup => {
                self.finish_setup();
            }
            UiAction::Add => {
                let display = self.display.add_display.as_mut().expect("No Add Input");
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
                    self.display.add_ui = false;
                    self.display.add_display = None;
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
                    self.config.toolbar_labels = settings_display.toolbar_labels;

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
                ui.label(
                    RichText::new(t!("error-label"))
                        .heading()
                        .color(Color32::LIGHT_RED),
                );
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
