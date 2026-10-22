//! Bottom panel: search, cross-references and the log.

use crate::i18n::{tr, trf};
use crate::{App, BottomTab};
use eframe::egui::{self, RichText};
use omnidecomp_viewmodel::{
    parse_address, HitKind, Scope,
};

impl App {
    pub(crate) fn bottom_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        ui.horizontal(|ui| {
            for (tab, name) in [(BottomTab::Search, tr(lang, "Search")), (BottomTab::Xrefs, tr(lang, "Cross-references")), (BottomTab::Log, tr(lang, "Log"))] {
                ui.selectable_value(&mut self.bottom, tab, name);
            }
        });
        match self.bottom {
            BottomTab::Search => {
                let mut run = false;
                ui.horizontal(|ui| {
                    let e = ui.add(egui::TextEdit::singleline(&mut self.query).desired_width(300.0).hint_text(tr(lang, "name, text, mnemonic, or hex address")));
                    run |= e.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    egui::ComboBox::from_id_salt("scope")
                        .selected_text(match self.scope {
                            Scope::All => tr(lang, "all"),
                            Scope::Functions => tr(lang, "functions"),
                            Scope::Symbols => tr(lang, "symbols"),
                            Scope::Strings => tr(lang, "strings"),
                            Scope::Instructions => tr(lang, "instructions"),
                        })
                        .show_ui(ui, |ui| {
                            for (s, n) in [(Scope::All, tr(lang, "all")), (Scope::Functions, tr(lang, "functions")), (Scope::Symbols, tr(lang, "symbols")), (Scope::Strings, tr(lang, "strings")), (Scope::Instructions, tr(lang, "instructions"))] {
                                ui.selectable_value(&mut self.scope, s, n);
                            }
                        });
                    run |= ui.button(tr(lang, "Search")).clicked();
                });
                if run {
                    if let Some(l) = &self.loaded {
                        self.results = l.search(&self.query, self.scope, 5000);
                    }
                }
                let mut go: Option<(Option<u64>, Option<u64>)> = None;
                let h = ui.text_style_height(&egui::TextStyle::Monospace);
                ui.label(trf(lang, "{} result(s){}", &[&self.results.len().to_string(), if self.results.len() >= 5000 { tr(lang, " (limit reached)") } else { "" }]));
                egui::ScrollArea::vertical().id_salt("results").show_rows(ui, h, self.results.len(), |ui, range| {
                    for hit in &self.results[range] {
                        let kind = match hit.kind {
                            HitKind::Address => "addr",
                            HitKind::Function => "func",
                            HitKind::Symbol => "sym",
                            HitKind::String => "str",
                            HitKind::Instruction => "insn",
                        };
                        if ui.selectable_label(false, RichText::new(format!("[{kind}] {}", hit.label)).monospace()).clicked() {
                            go = Some((hit.address, hit.offset));
                        }
                    }
                });
                if let Some((addr, off)) = go {
                    match (addr, off) {
                        (Some(a), _) => self.goto(a),
                        (None, Some(o)) => self.hex_offset = o,
                        _ => {}
                    }
                }
            }
            BottomTab::Xrefs => {
                let Some(l) = &self.loaded else { return };
                let Some(a) = self.selected else {
                    ui.label(tr(lang, "Select an instruction or function to see references to and from it."));
                    return;
                };
                let mut go = None;
                ui.label(RichText::new(trf(lang, "references to {}", &[&format!("{a:#x}")])).strong());
                for x in l.xrefs_to(a) {
                    if ui.selectable_label(false, RichText::new(trf(lang, "{} {} -> here  ({} confidence)", &[&format!("{:#x}", x.from), x.kind, x.confidence])).monospace()).clicked() {
                        go = Some(x.from);
                    }
                }
                ui.label(RichText::new(trf(lang, "references from {}", &[&format!("{a:#x}")])).strong());
                for x in l.xrefs_from(a) {
                    if ui.selectable_label(false, RichText::new(trf(lang, "here {} -> {}  ({} confidence)", &[x.kind, &format!("{:#x}", x.to), x.confidence])).monospace()).clicked() {
                        go = Some(x.to);
                    }
                }
                if let Some(t) = go {
                    self.goto(t);
                }
            }
            BottomTab::Log => {
                egui::ScrollArea::vertical().id_salt("log").stick_to_bottom(true).show(ui, |ui| {
                    for line in &self.log {
                        ui.label(RichText::new(line).monospace());
                    }
                });
                if ui.button(tr(lang, "Clear log")).clicked() {
                    self.log.clear();
                }
            }
        }
        let _ = parse_address;
    }
}
