//! Drawing helpers that do not touch application state.

use crate::i18n::{trf, Lang};
use eframe::egui::{self, Color32, FontId, RichText};
use omnidecomp_viewmodel::graph::GraphLayout;
use omnidecomp_viewmodel::Loaded;

/// egui reports the second of two quick clicks as a *triple* click when another click happened less than
/// 0.6 s before them (for example a tab click right before), so both count as a double click here.
pub(crate) fn double_clicked(r: &egui::Response) -> bool {
    r.double_clicked() || r.triple_clicked()
}

/// Draws `layout` and returns the node that was clicked (`true` = double click). Nodes are buttons so
/// they are reachable by keyboard and by accessibility tools; edges are painted underneath.
pub(crate) fn draw_graph(ui: &mut egui::Ui, layout: &GraphLayout, selected: Option<u64>, font_size: f32, dark: bool, lang: Lang) -> Option<(u64, bool)> {
    let font = FontId::monospace(font_size);
    let row_h = ui.fonts_mut(|f| f.row_height(&font));
    let (node_w, node_h) = (row_h * 11.0, row_h * 2.0 + 12.0);
    let (gap_x, gap_y) = (node_w * 0.25 + 30.0, node_h * 0.6 + 24.0);
    let size = egui::vec2(layout.width.max(1) as f32 * (node_w + gap_x) + gap_x, layout.layers.max(1) as f32 * (node_h + gap_y) + gap_y);
    let mut result = None;
    egui::ScrollArea::both().id_salt("graph").auto_shrink([false, false]).show(ui, |ui| {
        let (area, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        let rect_of = |i: usize| {
            let n = &layout.nodes[i];
            let min = area.min + egui::vec2(gap_x / 2.0 + n.x * (node_w + gap_x), gap_y / 2.0 + n.layer as f32 * (node_h + gap_y));
            egui::Rect::from_min_size(min, egui::vec2(node_w, node_h))
        };
        let painter = ui.painter().clone();
        for e in &layout.edges {
            let (a, b) = (rect_of(e.from), rect_of(e.to));
            let color = match (e.kind, dark) {
                ("taken", true) => Color32::from_rgb(110, 200, 120),
                ("taken", false) => Color32::from_rgb(20, 130, 40),
                ("jump", true) => Color32::from_rgb(255, 190, 90),
                ("jump", false) => Color32::from_rgb(170, 90, 0),
                ("call", true) => Color32::from_rgb(120, 200, 255),
                ("call", false) => Color32::from_rgb(0, 90, 170),
                (_, true) => Color32::from_rgb(170, 170, 190),
                (_, false) => Color32::from_rgb(90, 90, 110),
            };
            let stroke = egui::Stroke::new(if e.back { 1.5 } else { 1.2 }, if e.back { Color32::from_rgb(220, 90, 90) } else { color });
            let (from, to, dir) = if e.back {
                // Loops leave and re-enter on the right-hand side so they do not run through other nodes.
                let (p0, p3) = (a.right_center(), b.right_center());
                let bulge = egui::vec2(gap_x * 0.8, 0.0);
                painter.add(egui::epaint::CubicBezierShape::from_points_stroke([p0, p0 + bulge, p3 + bulge, p3], false, Color32::TRANSPARENT, stroke));
                (p0, p3, egui::vec2(-1.0, 0.0))
            } else {
                let (p0, p3) = (a.center_bottom(), b.center_top());
                painter.line_segment([p0, p3], stroke);
                let d = (p3 - p0).normalized();
                (p0, p3, if d.x.is_finite() && d.y.is_finite() { d } else { egui::vec2(0.0, 1.0) })
            };
            let side = egui::vec2(-dir.y, dir.x) * 4.0;
            painter.add(egui::Shape::convex_polygon(vec![to, to - dir * 9.0 + side, to - dir * 9.0 - side], stroke.color, egui::Stroke::NONE));
            if e.count > 1 {
                painter.text(from.lerp(to, 0.5), egui::Align2::LEFT_CENTER, format!("x{}", e.count), FontId::proportional(font_size * 0.8), stroke.color);
            }
        }
        for (i, n) in layout.nodes.iter().enumerate() {
            let is_selected = selected == Some(n.id);
            let fill = match (is_selected, dark) {
                (true, _) => Color32::from_rgb(240, 200, 80),
                (false, true) => Color32::from_rgb(45, 50, 62),
                (false, false) => Color32::from_rgb(232, 236, 245),
            };
            let text_color = if is_selected { Color32::BLACK } else { ui.visuals().text_color() };
            let label = if n.exits { trf(lang, "{}\n(leaves graph)", &[&n.label]) } else { n.label.clone() };
            let button = egui::Button::new(RichText::new(label).font(FontId::monospace(font_size * 0.85)).color(text_color))
                .fill(fill)
                .stroke(egui::Stroke::new(if n.exits { 1.5 } else { 1.0 }, if n.exits { Color32::from_rgb(220, 160, 60) } else { Color32::GRAY }))
                .truncate();
            let resp = ui.put(rect_of(i), button);
            if double_clicked(&resp) {
                result = Some((n.id, true));
            } else if resp.clicked() && result.is_none() {
                result = Some((n.id, false));
            }
        }
    });
    result
}

/// Instruction indices in address order (cheap: the view model already keeps them sorted internally,
/// and linear sweeps are almost always ascending, so the identity order is returned when it is sorted).
pub(crate) fn sorted_rows(l: &Loaded) -> Vec<usize> {
    let ins = l.instructions();
    let mut v: Vec<usize> = (0..ins.len()).collect();
    if !ins.windows(2).all(|w| w[0].address <= w[1].address) {
        v.sort_by_key(|i| ins[*i].address);
    }
    v
}
