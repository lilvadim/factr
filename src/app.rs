use crate::config;
use crate::encrypted_storage::Storage;
use crate::phosphor;
use crate::vault::VaultDecryptError;
use crate::view::model::{
    AccountDisplay, AddDisplay, AddMethod, AppDisplay, SettingsDisplay, SetupDisplay, VaultDisplay,
};
use crate::view::widget;
use std::{path::Path, sync::Arc};

use egui::Button;
use egui::Frame;
use egui::Id;
use egui::Key;
use egui::Response;
use egui::ThemePreference;
use egui::Tooltip;
use egui::Ui;
use egui::ViewportCommand;
use egui::Widget;
use egui::Window;
use egui::WindowLevel;
use egui::{Color32, ComboBox, RichText, Stroke, TextEdit};
use rust_i18n::t;

use crate::{
    config::Config,
    vault::{Account, Password, Vault},
};

#[cfg(target_os = "macos")]
const TRAFFIC_LIGHTS_HEIGHT: f32 = 24.0;

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
            #[cfg(target_os = "macos")]
            ui.add_space(TRAFFIC_LIGHTS_HEIGHT);
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
        ui.add(widget::AccountAddForm::new(display));
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
        let button_group_width = self.toolbar_button_group_width(ui);
        let min_search_width = 120.0;
        let single_row = ui.available_width()
            >= min_search_width + ui.spacing().item_spacing.x + button_group_width;

        if single_row {
            let search_width =
                ui.available_width() - ui.spacing().item_spacing.x - button_group_width;
            ui.horizontal(|ui| {
                self.display_search(ui, search_width);
                self.display_toolbar_buttons(ui, &mut actions);
            });
        } else {
            self.display_search(ui, ui.available_width());
            ui.horizontal_wrapped(|ui| {
                self.display_toolbar_buttons(ui, &mut actions);
            });
        }
        actions
    }

    fn display_search(&mut self, ui: &mut Ui, width: f32) {
        // These are TextEdit's default margins. `desired_width` excludes them.
        let margin = egui::Margin::symmetric(4, 2);
        let filter = TextEdit::singleline(&mut self.display.filter_search)
            .hint_text(format!("{}...", t!("filter-search")))
            .margin(margin)
            .desired_width((width - margin.sum().x).max(0.0))
            .ui(ui);
        if self.display.search_focus || ui.input(|i| i.key_pressed(Key::F) && i.modifiers.command) {
            filter.request_focus();
            self.display.search_focus = false;
        }
    }

    fn display_toolbar_buttons(&mut self, ui: &mut Ui, actions: &mut Vec<UiAction>) {
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
    }

    fn toolbar_button_group_width(&self, ui: &Ui) -> f32 {
        let cache_id =
            ui.make_persistent_id(("toolbar-button-group-width", self.config.toolbar_labels));
        if let Some(width) = ui.data(|data| data.get_temp::<f32>(cache_id)) {
            return width;
        }

        let button_width =
            |icon, label| Self::toolbar_button_width(ui, self.config.toolbar_labels, icon, label);
        let width = button_width(phosphor::LOCK, t!("lock-vault"))
            + button_width(phosphor::PLUS, t!("add-code"))
            + button_width(phosphor::GEAR, t!("settings-label"))
            + 2.0 * ui.spacing().item_spacing.x;

        ui.data_mut(|data| data.insert_temp(cache_id, width));

        width
    }

    fn toolbar_button_width(
        ui: &Ui,
        show_label: bool,
        icon: impl AsRef<str>,
        label: impl AsRef<str>,
    ) -> f32 {
        let text = if show_label {
            format!("{} {}", icon.as_ref(), label.as_ref())
        } else {
            icon.as_ref().to_owned()
        };
        let text_width = ui
            .painter()
            .layout_no_wrap(
                text,
                egui::TextStyle::Button.resolve(ui.style()),
                ui.visuals().text_color(),
            )
            .size()
            .x;
        (text_width + 2.0 * ui.spacing().button_padding.x).max(ui.spacing().interact_size.x)
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
            ui.horizontal(|ui| {
                ui.label(t!("settings.theme"));
                let theme_text = |theme: &ThemePreference| match theme {
                    ThemePreference::Dark => t!("settings.themes.dark"),
                    ThemePreference::Light => t!("settings.themes.light"),
                    ThemePreference::System => t!("settings.themes.system"),
                };
                let before = settings.theme;
                ComboBox::from_id_salt(Id::new("settings.theme"))
                    .selected_text(theme_text(&settings.theme))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut settings.theme,
                            ThemePreference::System,
                            theme_text(&ThemePreference::System),
                        );
                        ui.selectable_value(
                            &mut settings.theme,
                            ThemePreference::Light,
                            theme_text(&ThemePreference::Light),
                        );
                        ui.selectable_value(
                            &mut settings.theme,
                            ThemePreference::Dark,
                            theme_text(&ThemePreference::Dark),
                        );
                    });
                if before != settings.theme {
                    actions.push(UiAction::UpdateConfiguration);
                }
            })
        });
        actions
    }

    fn display_main(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();

        if self.is_vault_unlocked() {
            #[cfg(not(target_os = "macos"))]
            let content_rect = ui.ctx().content_rect();

            #[cfg(target_os = "macos")]
            let content_rect = {
                let min_y = ui.ctx().content_rect().min.y;
                ui.ctx()
                    .content_rect()
                    .with_min_y(min_y + TRAFFIC_LIGHTS_HEIGHT)
            };
            Window::new(t!("add-code"))
                .collapsible(false)
                .open(&mut self.display.add_ui)
                .constrain_to(content_rect)
                .show(ui.ctx(), |ui| {
                    actions.extend(Self::display_add(
                        self.display.add_display.get_or_insert_default(),
                        ui,
                    ));
                });
            Window::new(t!("settings-label"))
                .collapsible(false)
                .open(&mut self.display.settings_ui)
                .constrain_to(content_rect)
                .show(ui.ctx(), |ui| {
                    actions.extend(Self::display_settings(
                        self.display
                            .settings_display
                            .get_or_insert(SettingsDisplay::from_config(&self.config)),
                        ui,
                    ));
                });

            if let Some(error) = &self.error {
                Self::display_error(ui, error);
            }
            actions.extend(self.display_top_bar(ui));
            ui.add_space(ui.spacing().item_spacing.y);

            let item_spacing = ui.spacing().item_spacing;
            egui::ScrollArea::vertical().show(ui, |ui| {
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

                let available_width = ui.available_width();
                let max_columns = accounts.len().max(1);
                let column_count = (((available_width + item_spacing.x)
                    / (widget::AccountCodeCard::MIN_WIDTH + item_spacing.x))
                    .floor() as usize)
                    .clamp(1, max_columns);
                let card_width = (available_width
                    - item_spacing.x * (column_count.saturating_sub(1) as f32))
                    / column_count as f32;
                let card_width = card_width.min(widget::AccountCodeCard::MAX_WIDTH);
                egui::Grid::new("account-codes-grid")
                    .num_columns(column_count)
                    .min_col_width(widget::AccountCodeCard::MIN_WIDTH)
                    .max_col_width(card_width)
                    .min_row_height(widget::AccountCodeCard::HEIGHT)
                    .spacing(item_spacing)
                    .show(ui, |ui| {
                        for (position, (i, _, acc)) in accounts.into_iter().enumerate() {
                            let response = ui.add(widget::AccountCodeCard::new(&acc, card_width));
                            if response.clicked() {
                                ui.ctx().copy_text(acc.code.to_owned());
                                if self.config.close_after_copy {
                                    ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                                }
                            }
                            response.context_menu(|ui| {
                                // if ui.button(t!("edit")).clicked() { /* TODO */ }
                                if ui.button(t!("delete")).clicked() {
                                    actions.push(UiAction::Delete(i));
                                }
                            });
                            if (position + 1) % column_count == 0 {
                                ui.end_row();
                            }
                        }
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
                    self.config.theme = settings_display.theme;

                    ctx.set_theme(self.config.theme);

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

enum UiAction {
    UnlockVault,
    LockVault,
    Setup,
    Add,
    Delete(usize),
    UpdateConfiguration,
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
