//! Disassembly list.

use crate::i18n::{tr, trf};
use crate::widgets::{double_clicked, sorted_rows};
use crate::{App, BottomTab};
use eframe::egui::{self, Color32, FontId, RichText, TextFormat};
use omnidecomp_viewmodel::{
    mnemonic_class, Theme,
};

impl App {
    pub(crate) fn disasm_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        let Some(l) = self.loaded.as_ref() else {
            ui.centered_and_justified(|ui| {
                ui.label(tr(lang, "Disassembly (not decompilation) appears here once a file is loaded."));
            });
            return;
        };
        let Some(d) = &l.disasm else {
            ui.label(tr(lang, "Disassembly unavailable for this file; see the Log tab. No output is guessed."));
            return;
        };
        let bits = l.analysis.info.bits;
        let order = sorted_rows(l);
        let header = trf(lang, "{} {} - {} - {} instructions{}", &[&d.engine, &d.engine_version, d.arch.as_str(), &order.len().to_string(), if d.truncated { tr(lang, " (truncated by limit)") } else { "" }]);
        ui.label(RichText::new(header).weak());
        let font = FontId::monospace(self.settings.font_size);
        ui.spacing_mut().item_spacing.y = self.settings.line_spacing;
        let row_h = ui.fonts_mut(|f| f.row_height(&font));
        let mut clicked: Option<u64> = None;
        let mut follow: Option<u64> = None;
        let mut area = egui::ScrollArea::both().auto_shrink([false, false]);
        if let Some(row) = self.jump_row.take() {
            area = area.vertical_scroll_offset((row as f32 * (row_h + self.settings.line_spacing) - 40.0).max(0.0));
        }
        let ins = l.instructions();
        area.show_rows(ui, row_h, order.len(), |ui, range| {
            for r in range {
                let x = &ins[order[r]];
                let mut job = egui::text::LayoutJob::default();
                let plain = if self.settings.theme == Theme::Dark { Color32::LIGHT_GRAY } else { Color32::DARK_GRAY };
                let mut put = |t: String, c: Color32| job.append(&t, 0.0, TextFormat { font_id: font.clone(), color: c, ..Default::default() });
                put(format!("{}  ", self.settings.format_address(x.address, bits)), Color32::from_rgb(130, 150, 190));
                put(format!("{:<24}  ", x.bytes), Color32::GRAY);
                let mc = if self.settings.colored_mnemonics { self.color(mnemonic_class(x)) } else { plain };
                put(format!("{:<8}", x.mnemonic), mc);
                put(format!(" {}", x.operands), plain);
                if let Some(t) = x.target {
                    let label = l.name_at(t).map_or(format!("-> {t:#x}"), |n| format!("-> {n}"));
                    put(format!("   ; {label}"), Color32::from_rgb(110, 170, 110));
                }
                let resp = ui.selectable_label(self.selected == Some(x.address), job);
                if resp.clicked() {
                    clicked = Some(x.address);
                }
                if double_clicked(&resp) {
                    follow = x.target;
                }
            }
        });
        if let Some(a) = clicked {
            self.select(a);
            self.bottom = BottomTab::Xrefs;
        }
        if let Some(t) = follow {
            self.goto(t);
        }
    }
}
