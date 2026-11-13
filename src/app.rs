use crate::config;
use crate::phosphor;
use crate::view::model::{
    AccountDisplay, AccountFieldsDisplay, AppDisplay, EditDisplay, SettingsDisplay, VaultDisplay,
};
use crate::view::widget;
use factr_storage::{ProtectedStorageV2, Storage};
use std::sync::Arc;
use uuid::Uuid;

use egui::Button;
use egui::Frame;
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

use crate::{config::Config, vault_access::VaultAccess};
use factr_core::vault::Vault;

#[cfg(target_os = "macos")]
const TRAFFIC_LIGHTS_HEIGHT: f32 = 24.0;

pub struct FactrApp {
    config: Config,
    display: AppDisplay,
    access: VaultAccess,
    vault: Option<Vault>,
    error: Option<String>,
}

impl eframe::App for FactrApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            #[cfg(target_os = "macos")]
            ui.add_space(TRAFFIC_LIGHTS_HEIGHT);
            self.ui(ui);
        });
        #[cfg(target_os = "macos")]
        {
            let ctx = ui.ctx();
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
        let access = VaultAccess::new(&config.storage_file);
        Self {
            access,
            vault: None,
            error: None,
            display: AppDisplay::default(),
            config,
        }
    }

    fn lock_vault(&mut self) -> Result<(), String> {
        self.save_storage()?;
        let _ = self.vault.take();
        self.display.edit_display = None;
        self.display.add_display = None;
        self.access.reload(&self.config.storage_file);
        self.display.need_default_focus = true;
        Ok(())
    }

    fn is_vault_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    fn ui(&mut self, ui: &mut Ui) {
        if self
            .access
            .update(ui.ctx(), &self.config.storage_file, &mut self.vault)
        {
            self.display.need_default_focus = true;
        }
        let actions = self.display_main(ui);
        self.handle_actions(ui.ctx(), actions);
        if self.access.display.action.is_some() {
            ui.ctx().request_repaint();
        }
    }

    fn display_add(display: &mut AccountFieldsDisplay, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        ui.add(widget::AccountAddForm::new(display));
        if let Some(error) = &display.error {
            Self::display_error(ui, error);
        }
        ui.horizontal(|ui| {
            if ui.button(t!("cancel")).clicked() || widget::form_key(ui, Key::Escape) {
                actions.push(UiAction::CancelAdd);
            }
            if ui.add(Button::new(t!("save")).selected(true)).clicked()
                || widget::form_key(ui, Key::Enter)
            {
                actions.push(UiAction::Add);
            }
        });
        actions
    }

    fn display_top_bar(&mut self, ui: &mut Ui) -> Vec<UiAction> {
        let mut actions = Vec::new();
        let button_group_width = self.toolbar_button_group_width(ui);
        let sort_width = widget::AccountSortControl(&mut self.display.sort).width(ui);
        let controls_width = sort_width + button_group_width + 2.0 * ui.spacing().item_spacing.x;
        let min_search_width = 120.0;
        let search_width = ui.available_width() - controls_width;
        let single_row = search_width >= min_search_width;

        if single_row {
            ui.horizontal(|ui| {
                self.display_search(ui, search_width);
                if ui
                    .add(widget::AccountSortControl(&mut self.display.sort))
                    .changed()
                {
                    actions.push(UiAction::UpdateConfiguration);
                }
                self.display_toolbar_buttons(ui, &mut actions);
            });
        } else {
            self.display_search(ui, ui.available_width());
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add(widget::AccountSortControl(&mut self.display.sort))
                    .changed()
                {
                    actions.push(UiAction::UpdateConfiguration);
                }
                self.display_toolbar_buttons(ui, &mut actions);
            });
        }
        actions
    }

    fn display_search(&mut self, ui: &mut Ui, width: f32) {
        let filter = ui.add_sized(
            [width, ui.spacing().interact_size.y],
            TextEdit::singleline(&mut self.display.filter_search)
                .id(egui::Id::unique("account-search"))
                .hint_text(format!("{}...", t!("filter-search"))),
        );
        if self.display.need_default_focus
            || ui.input(|i| i.key_pressed(Key::F) && i.modifiers.command)
        {
            filter.request_focus();
            self.display.need_default_focus = false;
        }
    }

    fn display_toolbar_buttons(&mut self, ui: &mut Ui, actions: &mut Vec<UiAction>) {
        let buttons = [
            (phosphor::LOCK, t!("lock-vault")),
            (phosphor::PLUS, t!("add-code")),
            (phosphor::GEAR, t!("settings-label")),
        ];
        for (icon, label) in buttons {
            if Self::toolbar_button(ui, self.config.toolbar_labels, icon, label).clicked() {
                match icon {
                    phosphor::LOCK => actions.push(UiAction::LockVault),
                    phosphor::PLUS => self.display.add_ui = true,
                    phosphor::GEAR => self.display.settings_ui = true,
                    _ => unreachable!(),
                }
            }
        }
    }

    fn toolbar_button_group_width(&self, ui: &mut Ui) -> f32 {
        let cache_id =
            ui.make_persistent_id(("toolbar-button-group-width", self.config.toolbar_labels));
        if let Some(width) = ui.data(|data| data.get_temp::<f32>(cache_id)) {
            return width;
        }

        let mut sizing_ui = ui.new_child(
            egui::UiBuilder::new()
                .id_salt("toolbar-buttons-size")
                .layout(egui::Layout::left_to_right(egui::Align::Center))
                .sizing_pass()
                .invisible(),
        );
        let width = sizing_ui
            .horizontal(|ui| {
                for (icon, label) in [
                    (phosphor::LOCK, t!("lock-vault")),
                    (phosphor::PLUS, t!("add-code")),
                    (phosphor::GEAR, t!("settings-label")),
                ] {
                    Self::toolbar_button(ui, self.config.toolbar_labels, icon, label);
                }
            })
            .response
            .rect
            .width();

        ui.data_mut(|data| data.insert_temp(cache_id, width));

        width
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
                ComboBox::from_id_salt("settings.theme")
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
            let mut close_add = false;
            Window::new(t!("add-code"))
                .title_bar(false)
                .open(&mut self.display.add_ui)
                .constrain_to(content_rect)
                .show(ui.ctx(), |ui| {
                    close_add = ui
                        .add(widget::InnerWindowHeader::new(&t!("add-code")))
                        .clicked();
                    actions.extend(Self::display_add(
                        self.display.add_display.get_or_insert_default(),
                        ui,
                    ));
                });
            if close_add {
                self.display.add_ui = false;
            }
            let mut close_settings = false;
            Window::new(t!("settings-label"))
                .title_bar(false)
                .open(&mut self.display.settings_ui)
                .constrain_to(content_rect)
                .show(ui.ctx(), |ui| {
                    close_settings = ui
                        .add(widget::InnerWindowHeader::new(&t!("settings-label")))
                        .clicked();
                    actions.extend(Self::display_settings(
                        self.display
                            .settings_display
                            .get_or_insert(SettingsDisplay::from_config(&self.config)),
                        ui,
                    ));
                    ui.add(widget::SystemProtectionControl(&mut self.access.display));
                    close_settings |= widget::form_key(ui, Key::Escape);
                });
            if close_settings {
                self.display.settings_ui = false;
            }

            if let Some(edit) = &mut self.display.edit_display {
                let mut open = true;
                let mut close_edit = false;
                Window::new(t!("edit"))
                    .title_bar(false)
                    .open(&mut open)
                    .constrain_to(content_rect)
                    .show(ui.ctx(), |ui| {
                        close_edit = ui
                            .add(widget::InnerWindowHeader::new(&t!("edit")))
                            .clicked();
                        ui.add(widget::AccountInputForm::new(
                            &mut edit.input.manual,
                            &mut edit.input.extra_input,
                            &mut edit.input.manual_extra,
                        ));
                        if let Some(error) = &edit.input.error {
                            Self::display_error(ui, error);
                        }
                        ui.horizontal(|ui| {
                            if ui.button(t!("cancel")).clicked()
                                || widget::form_key(ui, Key::Escape)
                            {
                                actions.push(UiAction::CancelEdit);
                            }
                            if ui.add(Button::new(t!("save")).selected(true)).clicked()
                                || widget::form_key(ui, Key::Enter)
                            {
                                actions.push(UiAction::SaveEdit);
                            }
                        });
                    });
                if !open || close_edit {
                    self.display.edit_display = None;
                }
            }

            if let Some(error) = &self.error {
                Self::display_error(ui, error);
            }
            actions.extend(self.display_top_bar(ui));
            ui.add_space(ui.spacing().item_spacing.y);

            let item_spacing = egui::Vec2::splat(ui.spacing().item_spacing.x);
            egui::ScrollArea::vertical().show(ui, |ui| {
                let mut accounts: Vec<_> = self
                    .vault
                    .as_ref()
                    .map(VaultDisplay::from_vault)
                    .unwrap()
                    .expect("Cannot display")
                    .accounts
                    .into_iter()
                    .map(|account| (account.id, account))
                    .collect();
                if self.display.sort.enabled {
                    use crate::config::SortField;
                    let query = self.display.filter_search.to_lowercase();
                    if !query.is_empty() {
                        accounts.retain(|(_, account)| {
                            account
                                .issuer
                                .as_ref()
                                .is_some_and(|issuer| issuer.to_lowercase().contains(&query))
                                || account.account_name.to_lowercase().contains(&query)
                        });
                    }
                    accounts.sort_by(|(_, a), (_, b)| {
                        let order = match self.display.sort.field {
                            SortField::Name => a.issuer.cmp(&b.issuer),
                            SortField::Username => a.account_name.cmp(&b.account_name),
                            SortField::FirstAdded => a.created_at.cmp(&b.created_at),
                            SortField::LastModified => a.modified_at.cmp(&b.modified_at),
                        };
                        if self.display.sort.descending {
                            order.reverse()
                        } else {
                            order
                        }
                    });
                } else if !self.display.filter_search.is_empty() {
                    let mut ranked: Vec<_> = accounts
                        .into_iter()
                        .map(|(i, account)| {
                            let rate =
                                Self::filter_search_rate(&account, &self.display.filter_search);
                            (i, rate, account)
                        })
                        .filter(|(_, rate, _)| *rate > 0)
                        .collect();
                    ranked.sort_by(|(_, a_rate, _), (_, b_rate, _)| b_rate.cmp(a_rate));
                    accounts = ranked
                        .into_iter()
                        .map(|(i, _, account)| (i, account))
                        .collect();
                } else {
                    accounts.sort_by_key(|(_, acc)| acc.custom_position);
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
                        for (position, (i, acc)) in accounts.into_iter().enumerate() {
                            let editing = self
                                .display
                                .edit_display
                                .as_ref()
                                .is_some_and(|edit| edit.id == i);
                            let draggable = !editing
                                && !self.display.sort.enabled
                                && self.display.filter_search.is_empty();
                            let response = ui
                                .push_id(i, |ui| {
                                    if draggable {
                                        let id = ui.make_persistent_id("account-drag");
                                        let source = ui.dnd_drag_source(id, i, |ui| {
                                            ui.add(widget::AccountCodeCard::new(
                                                &acc,
                                                card_width,
                                                Some(id),
                                            ))
                                        });
                                        let response = ui.interact(
                                            source.response.rect,
                                            id,
                                            egui::Sense::click_and_drag(),
                                        );
                                        source.inner | response
                                    } else {
                                        ui.add_enabled(
                                            !editing,
                                            widget::AccountCodeCard::new(&acc, card_width, None),
                                        )
                                    }
                                })
                                .inner
                                .on_hover_cursor(egui::CursorIcon::PointingHand);
                            if draggable {
                                if let Some(source) = response.dnd_hover_payload::<Uuid>()
                                    && *source != i
                                {
                                    let rect = response.rect.shrink(1.0);
                                    let outline = [
                                        rect.left_top(),
                                        rect.right_top(),
                                        rect.right_bottom(),
                                        rect.left_bottom(),
                                        rect.left_top(),
                                    ];
                                    ui.painter().extend(egui::Shape::dashed_line(
                                        &outline,
                                        egui::Stroke::new(2.0_f32, ui.visuals().selection.bg_fill),
                                        6.0,
                                        4.0,
                                    ));
                                }
                                if let Some(source) = response.dnd_release_payload::<Uuid>() {
                                    actions.push(UiAction::MoveAccount(*source, i));
                                }
                            }
                            if response.clicked() {
                                ui.ctx().copy_text(acc.code.to_owned());
                                if self.config.close_after_copy {
                                    ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                                }
                            }
                            response.context_menu(|ui| {
                                if ui.button(t!("edit")).clicked() {
                                    actions.push(UiAction::Edit(i));
                                    ui.close();
                                }
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
            ui.add(widget::VaultAccessForm(&mut self.access.display));
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
            UiAction::LockVault => {
                self.error = self.lock_vault().err();
            }
            UiAction::Add => {
                let display = self.display.add_display.as_mut().expect("No Add Input");
                let result = self
                    .vault
                    .as_mut()
                    .ok_or("No Vault".to_string())
                    .and_then(|vault| {
                        let account = display.to_account(vault.accounts.len())?;
                        vault.accounts.push(account);
                        Ok(())
                    });

                if result.is_ok() {
                    self.error = self.save_storage().err();
                    self.display.add_ui = false;
                    self.display.add_display = None;
                } else {
                    display.error = result.err();
                }
            }
            UiAction::CancelAdd => {
                self.display.add_ui = false;
                self.display.add_display = None;
            }
            UiAction::Edit(id) => {
                if let Some(account) = self
                    .vault
                    .as_ref()
                    .and_then(|vault| vault.accounts.iter().find(|account| account.id == id))
                {
                    self.display.edit_display = Some(EditDisplay::from_account(account));
                }
            }
            UiAction::CancelEdit => self.display.edit_display = None,
            UiAction::SaveEdit => {
                let Some(edit) = &self.display.edit_display else {
                    return;
                };
                let id = edit.id;
                let result = self
                    .vault
                    .as_ref()
                    .ok_or("No Vault".to_string())
                    .and_then(|vault| {
                        vault
                            .accounts
                            .iter()
                            .find(|account| account.id == id)
                            .ok_or("No Account".to_string())
                    })
                    .and_then(|account| edit.input.to_account(account.custom_position))
                    .and_then(|mut edited_account| {
                        let vault = self.vault.as_mut().ok_or("No Vault".to_string())?;
                        let index = vault
                            .accounts
                            .iter()
                            .position(|account| account.id == id)
                            .ok_or("No Account".to_string())?;
                        let editable = &mut vault.accounts[index];
                        edited_account.id = editable.id;
                        edited_account.created_at = editable.created_at;
                        edited_account.modified_at = if edited_account.totp == editable.totp {
                            editable.modified_at
                        } else {
                            chrono::Utc::now().timestamp_millis()
                        };
                        let old = std::mem::replace(editable, edited_account);
                        if let Err(error) = self.save_storage() {
                            self.vault.as_mut().unwrap().accounts[index] = old;
                            return Err(error);
                        }
                        Ok(())
                    });
                match result {
                    Ok(()) => self.display.edit_display = None,
                    Err(error) => {
                        self.display.edit_display.as_mut().unwrap().input.error = Some(error)
                    }
                }
            }
            UiAction::MoveAccount(source, target) => {
                let move_unavailable = self.display.sort.enabled
                    || !self.display.filter_search.is_empty()
                    || source == target;
                if move_unavailable {
                    return;
                }
                let Some(vault) = &mut self.vault else {
                    return;
                };
                let original_layout_positions: Vec<_> =
                    vault.accounts.iter().map(|a| a.custom_position).collect();
                let Some(from) = vault
                    .accounts
                    .iter()
                    .find(|account| account.id == source)
                    .map(|account| account.custom_position)
                else {
                    return;
                };
                let Some(to) = vault
                    .accounts
                    .iter()
                    .find(|account| account.id == target)
                    .map(|account| account.custom_position)
                else {
                    return;
                };
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
                if let Err(error) = self.save_storage() {
                    for (account, position) in self
                        .vault
                        .as_mut()
                        .unwrap()
                        .accounts
                        .iter_mut()
                        .zip(original_layout_positions)
                    {
                        account.custom_position = position;
                    }
                    self.error = Some(error);
                }
            }
            UiAction::Delete(id) => {
                if self
                    .display
                    .edit_display
                    .as_ref()
                    .is_some_and(|edit| edit.id == id)
                {
                    self.display.edit_display = None;
                }
                self.error = self
                    .vault
                    .as_mut()
                    .ok_or("No Vault".to_string())
                    .and_then(|vault| {
                        let idx = vault
                            .accounts
                            .iter()
                            .position(|account| account.id == id)
                            .ok_or("No Account".to_string())?;
                        let removed = vault.accounts.remove(idx);
                        for account in &mut vault.accounts {
                            if account.custom_position > removed.custom_position {
                                account.custom_position -= 1;
                            }
                        }
                        Ok(())
                    })
                    .and_then(|_| self.save_storage())
                    .err();
            }
            UiAction::UpdateConfiguration => {
                self.config.sort = self.display.sort;
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
                }
                self.error = config::save_to_dot_config(&self.config).err();
            }
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
        let vault = self.vault.as_ref().ok_or("No Vault")?;
        Storage::V2(ProtectedStorageV2::from_vault(vault)?).write(&self.config.storage_file)
    }
}

enum UiAction {
    MoveAccount(Uuid, Uuid),
    Edit(Uuid),
    SaveEdit,
    CancelEdit,
    LockVault,
    Add,
    CancelAdd,
    Delete(Uuid),
    UpdateConfiguration,
}
