//! Hex view synced to the selection.

use crate::i18n::tr;
use crate::App;
use eframe::egui::{self, Color32, FontId, RichText, TextFormat};

impl App {
    pub(crate) fn hex_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        ui.label(RichText::new(tr(lang, "Hex (synced to selection)")).weak());
        let Some(l) = self.loaded.as_ref() else { return };
        let font = FontId::monospace(self.settings.font_size);
        let width = 16usize;
        let rows = l.hex_rows(width);
        let target_row = (self.hex_offset as usize) / width;
        let sel_off = self.selected.and_then(|a| l.file_offset_of(a));
        let sel_len = self.selected.and_then(|a| l.instruction_at(a)).map_or(0, |i| l.instructions()[i].bytes.len() as u64 / 2);
        let row_h = ui.fonts_mut(|f| f.row_height(&font));
        ui.spacing_mut().item_spacing.y = self.settings.line_spacing;
        let mut area = egui::ScrollArea::vertical().id_salt("hexscroll").auto_shrink([false, false]);
        if ui.memory(|m| m.data.get_temp::<u64>(egui::Id::new("hex_seen")) != Some(self.hex_offset)) {
            area = area.vertical_scroll_offset((target_row as f32 * (row_h + self.settings.line_spacing) - 40.0).max(0.0));
            ui.memory_mut(|m| m.data.insert_temp(egui::Id::new("hex_seen"), self.hex_offset));
        }
        area.show_rows(ui, row_h, rows, |ui, range| {
            for r in range {
                let base = (r * width) as u64;
                let bytes = l.hex_row(base, width);
                let mut job = egui::text::LayoutJob::default();
                let mut put = |t: String, c: Color32, bg: Color32| {
                    job.append(&t, 0.0, TextFormat { font_id: font.clone(), color: c, background: bg, ..Default::default() })
                };
                let dim = Color32::GRAY;
                put(format!("{base:08x}  "), dim, Color32::TRANSPARENT);
                for (k, b) in bytes.iter().enumerate() {
                    let off = base + k as u64;
                    let hit = sel_off.is_some_and(|s| off >= s && off < s + sel_len.max(1));
                    let (fg, bg) = if hit { (Color32::BLACK, Color32::from_rgb(240, 200, 80)) } else { (ui.visuals().text_color(), Color32::TRANSPARENT) };
                    put(format!("{b:02x}"), fg, bg);
                    put(" ".to_string(), dim, Color32::TRANSPARENT);
                }
                put(" ".repeat((width - bytes.len()) * 3 + 1), dim, Color32::TRANSPARENT);
                // ASCII column: control and non-ASCII bytes are shown as '.', never interpreted.
                let ascii: String = bytes.iter().map(|b| if (0x20..0x7f).contains(b) { *b as char } else { '.' }).collect();
                put(ascii, dim, Color32::TRANSPARENT);
                ui.add(egui::Label::new(job).wrap_mode(egui::TextWrapMode::Extend));
            }
        });
    }
}
