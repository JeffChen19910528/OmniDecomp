//! Interface language, fonts, theme and the colors derived from them.

use crate::i18n::trf;
use crate::cjk;
use crate::i18n::{self, Lang};
use crate::App;
use eframe::egui::{self, Color32};
use omnidecomp_viewmodel::{
    MnemonicClass, Theme,
};

impl App {
    /// Installs the fonts for the current language (a CJK fallback only when Chinese is shown).
    pub(crate) fn apply_language(&mut self, ctx: &egui::Context) {
        if self.applied_lang == Some(self.lang) {
            return;
        }
        let font = if self.lang == Lang::ZhTw { self.cjk.clone() } else { None };
        if self.applied_lang.is_some() || font.is_some() {
            if let Err(e) = cjk::install(ctx, font.as_ref()) {
                self.log.push(e);
                self.lang = Lang::En;
                let _ = cjk::install(ctx, None);
            }
        }
        self.applied_lang = Some(self.lang);
    }

    /// Switches the interface language and remembers the choice.
    pub fn set_language(&mut self, lang: Lang) {
        if lang == Lang::ZhTw && self.cjk.is_none() {
            return;
        }
        self.lang = lang;
        self.graph = None;
        if let Err(e) = i18n::save_pref(self.prefs_path.as_deref(), lang) {
            let msg = trf(lang, "Could not save the language choice: {}", &[&e]);
            self.log.push(msg);
        }
    }

    pub(crate) fn apply_settings(&mut self, ctx: &egui::Context) {
        self.settings = self.settings.sanitized();
        if self.applied == Some(self.settings) {
            return;
        }
        ctx.set_visuals(match self.settings.theme {
            Theme::Dark => egui::Visuals::dark(),
            Theme::Light => egui::Visuals::light(),
        });
        ctx.set_zoom_factor(1.0);
        self.applied = Some(self.settings);
    }

    pub(crate) fn color(&self, class: MnemonicClass) -> Color32 {
        let dark = self.settings.theme == Theme::Dark;
        match (class, dark) {
            (MnemonicClass::Call, true) => Color32::from_rgb(120, 200, 255),
            (MnemonicClass::Call, false) => Color32::from_rgb(0, 90, 170),
            (MnemonicClass::Jump | MnemonicClass::Branch, true) => Color32::from_rgb(255, 190, 90),
            (MnemonicClass::Jump | MnemonicClass::Branch, false) => Color32::from_rgb(170, 90, 0),
            (MnemonicClass::Return, true) => Color32::from_rgb(255, 120, 120),
            (MnemonicClass::Return, false) => Color32::from_rgb(170, 20, 20),
            (MnemonicClass::Nop, true) => Color32::GRAY,
            (MnemonicClass::Nop, false) => Color32::DARK_GRAY,
            (MnemonicClass::Invalid, _) => Color32::from_rgb(220, 60, 60),
            (MnemonicClass::Other, true) => Color32::from_rgb(220, 220, 220),
            (MnemonicClass::Other, false) => Color32::from_rgb(30, 30, 30),
        }
    }
}
