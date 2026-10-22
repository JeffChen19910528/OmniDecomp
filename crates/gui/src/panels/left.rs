//! Left panel: info, functions, symbols and strings.

use crate::i18n::{tr, trf};
use crate::{App, LeftTab};
use eframe::egui::{self, Color32, FontId, RichText};

impl App {
    pub(crate) fn left_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        ui.horizontal(|ui| {
            for (tab, name) in [(LeftTab::Info, tr(lang, "Info")), (LeftTab::Functions, tr(lang, "Functions")), (LeftTab::Symbols, tr(lang, "Symbols")), (LeftTab::Strings, tr(lang, "Strings"))] {
                ui.selectable_value(&mut self.left, tab, name);
            }
        });
        let Some(l) = self.loaded.as_ref() else {
            ui.label(tr(lang, "No file loaded. Enter a path or drop a PE / ELF / Mach-O file on this window."));
            return;
        };
        let bits = l.analysis.info.bits;
        let mut jump: Option<u64> = None;
        let font = FontId::monospace(self.settings.font_size);
        match self.left {
            LeftTab::Info => {
                let i = &l.analysis.info;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let row = |ui: &mut egui::Ui, k: &str, v: String| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(k).strong());
                            ui.label(v);
                        });
                    };
                    row(ui, tr(lang, "name"), l.name.clone());
                    row(ui, tr(lang, "format"), format!("{:?}", i.format));
                    row(ui, tr(lang, "architecture"), format!("{} ({}-bit)", i.arch.as_str(), i.bits));
                    row(ui, tr(lang, "entry point"), i.entry_point.map_or(tr(lang, "none").to_string(), |e| format!("{e:#x}")));
                    row(ui, tr(lang, "size"), trf(lang, "{} bytes", &[&l.analysis.artifact.size.to_string()]));
                    row(ui, tr(lang, "sha-256"), l.analysis.artifact.sha256.clone());
                    if let Some(d) = &l.debug {
                        row(ui, tr(lang, "pdb"), trf(lang, "{} (guid {}, age {})", &[&d.pdb_path, &d.guid, &d.age.to_string()]));
                    }
                    if let Some(d) = &l.dotnet {
                        row(ui, tr(lang, ".net"), trf(lang, "{} types, {} methods ({} metadata only; see the Decompile tab)", &[&d.type_count.to_string(), &d.method_count.to_string(), &d.runtime_version]));
                    }
                    ui.separator();
                    ui.label(RichText::new(tr(lang, "Sections")).strong());
                    for s in &i.sections {
                        let text = format!("{}  {} {:#x}  {} {:#x}{}", s.name, tr(lang, "va"), s.virtual_address, tr(lang, "size"), s.file_size, if s.executable { format!("  {}", tr(lang, "[exec]")) } else { String::new() });
                        if ui.selectable_label(false, RichText::new(text).font(font.clone())).clicked() && s.file_size > 0 {
                            self.hex_offset = s.file_offset;
                        }
                    }
                    if !l.notes.is_empty() {
                        ui.separator();
                        for n in &l.notes {
                            ui.colored_label(Color32::from_rgb(220, 160, 60), n);
                        }
                    }
                });
            }
            LeftTab::Functions => {
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text(tr(lang, "filter by name or address")));
                let f = self.filter.to_lowercase();
                let rows: Vec<&omnidecomp_core::FunctionInfo> = l.functions.as_ref().map_or(Vec::new(), |r| {
                    r.functions.iter().filter(|x| f.is_empty() || x.name.as_deref().unwrap_or("").to_lowercase().contains(&f) || format!("{:x}", x.address).contains(&f)).collect()
                });
                if l.functions.is_none() {
                    ui.label(tr(lang, "Functions unavailable for this file (see Log)."));
                }
                let h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().show_rows(ui, h, rows.len(), |ui, range| {
                    for x in &rows[range] {
                        let size = x.size.map_or("?".to_string(), |s| format!("{s:#x}"));
                        let text = format!("{}  {:<8} {} {}  {} [{}/{}]", self.settings.format_address(x.address, bits), "", tr(lang, "size"), size, x.name.as_deref().unwrap_or("sub_unnamed"), x.source, x.confidence);
                        if ui.selectable_label(self.selected == Some(x.address), RichText::new(text).font(font.clone())).clicked() {
                            jump = Some(x.address);
                        }
                    }
                });
            }
            LeftTab::Symbols => {
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text(tr(lang, "filter by name")));
                let f = self.filter.to_lowercase();
                let rows: Vec<&omnidecomp_core::Symbol> = l.symbols.iter().filter(|s| f.is_empty() || s.name.to_lowercase().contains(&f)).collect();
                let h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().show_rows(ui, h, rows.len(), |ui, range| {
                    for s in &rows[range] {
                        let addr = s.address.map_or(tr(lang, "(import)").to_string(), |a| self.settings.format_address(a, bits));
                        let text = format!("{addr}  {}  [{}]", s.name, s.kind);
                        if ui.selectable_label(false, RichText::new(text).font(font.clone())).clicked() {
                            jump = s.address;
                        }
                    }
                });
            }
            LeftTab::Strings => {
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text(tr(lang, "filter text")));
                let f = self.filter.to_lowercase();
                let rows: Vec<&omnidecomp_core::StringHit> = l.strings.strings.iter().filter(|s| f.is_empty() || s.text.to_lowercase().contains(&f)).collect();
                let h = ui.text_style_height(&egui::TextStyle::Monospace);
                let mut hex_jump = None;
                egui::ScrollArea::vertical().show_rows(ui, h, rows.len(), |ui, range| {
                    for s in &rows[range] {
                        let text = format!("{:#08x}  {}", s.offset, s.text);
                        if ui.selectable_label(false, RichText::new(text).font(font.clone())).clicked() {
                            hex_jump = Some(s.offset);
                        }
                    }
                });
                if let Some(o) = hex_jump {
                    self.hex_offset = o;
                }
            }
        }
        if let Some(a) = jump {
            self.goto(a);
        }
    }
}
