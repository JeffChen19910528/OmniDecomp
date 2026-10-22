//! File bar and View menu (theme, font, language).

use crate::i18n::{tr, trf};
use crate::i18n::Lang;
use crate::App;
use eframe::egui::{self, Color32, RichText};
use omnidecomp_viewmodel::{
    AddressFormat, Theme, MAX_FONT, MAX_SPACING, MIN_FONT,
};
use std::path::PathBuf;

impl App {
    pub(crate) fn top_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let lang = self.lang;
        ui.horizontal_wrapped(|ui| {
            ui.label(tr(lang, "File:"));
            let edit = ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(420.0).hint_text(tr(lang, "path, use Open file..., or drop a file here")));
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.add_enabled(self.pending_pick.is_none(), egui::Button::new(tr(lang, "Open file..."))).clicked() {
                self.pick_file(ctx);
            }
            if (ui.button(tr(lang, "Open")).clicked() || enter) && !self.path_input.trim().is_empty() {
                let p = PathBuf::from(self.path_input.trim());
                self.open(&p, ctx);
            }
            if let Some(t) = &self.task {
                if ui.button(tr(lang, "Cancel")).clicked() {
                    t.cancel();
                }
                ui.spinner();
                ui.label(trf(lang, "engine working: {}", &[tr(lang, &t.status())]));
            }
            ui.separator();
            ui.menu_button(tr(lang, "View"), |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.settings.theme, Theme::Dark, tr(lang, "Dark"));
                    ui.selectable_value(&mut self.settings.theme, Theme::Light, tr(lang, "Light"));
                });
                ui.add(egui::Slider::new(&mut self.settings.font_size, MIN_FONT..=MAX_FONT).text(tr(lang, "font size")));
                ui.add(egui::Slider::new(&mut self.settings.line_spacing, 0.0..=MAX_SPACING).text(tr(lang, "line spacing")));
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.settings.address_format, AddressFormat::Padded, tr(lang, "padded addresses"));
                    ui.selectable_value(&mut self.settings.address_format, AddressFormat::Short, tr(lang, "short"));
                });
                ui.checkbox(&mut self.settings.colored_mnemonics, tr(lang, "color mnemonics"));
                ui.separator();
                ui.label(tr(lang, "Language"));
                let mut chosen = self.lang;
                ui.horizontal(|ui| {
                    for l in [Lang::En, Lang::ZhTw] {
                        ui.add_enabled_ui(l == Lang::En || self.cjk.is_some(), |ui| ui.selectable_value(&mut chosen, l, l.native_name()));
                    }
                });
                if self.cjk.is_none() {
                    ui.label(RichText::new(tr(lang, "A Chinese font was not found on this system, so Traditional Chinese is unavailable.")).weak().small());
                }
                if chosen != self.lang {
                    self.set_language(chosen);
                }
            });
            if let Some(e) = &self.error {
                ui.colored_label(Color32::from_rgb(220, 70, 70), e);
            }
        });
    }
}
