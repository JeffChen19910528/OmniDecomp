//! Finds a Traditional Chinese capable font on the system. egui's built-in fonts have no CJK glyphs and no
//! font is bundled (size and licensing), so the interface in Chinese needs one that is already installed.
//! The font is only read when Traditional Chinese is selected. `OMNIDECOMP_CJK_FONT=<path>[,<face index>]`
//! overrides the search.

use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;

/// Refuse absurdly large files instead of loading them into memory.
const MAX_FONT_BYTES: u64 = 128 * 1024 * 1024;

pub fn candidates() -> Vec<(PathBuf, u32)> {
    let mut v: Vec<(PathBuf, u32)> = Vec::new();
    if let Some(s) = std::env::var_os("OMNIDECOMP_CJK_FONT") {
        let s = s.to_string_lossy().to_string();
        let (path, idx) = match s.rsplit_once(',') {
            Some((p, i)) if i.trim().parse::<u32>().is_ok() => (p.to_string(), i.trim().parse().unwrap_or(0)),
            _ => (s, 0),
        };
        v.push((PathBuf::from(path), idx));
    }
    if cfg!(windows) {
        let win = std::env::var_os("WINDIR").or_else(|| std::env::var_os("SystemRoot")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        for f in ["msjh.ttc", "mingliu.ttc", "kaiu.ttf"] {
            v.push((win.join("Fonts").join(f), 0));
        }
    } else if cfg!(target_os = "macos") {
        for f in ["/System/Library/Fonts/PingFang.ttc", "/System/Library/Fonts/STHeiti Medium.ttc", "/Library/Fonts/Arial Unicode.ttf"] {
            v.push((PathBuf::from(f), 0));
        }
    } else {
        // Noto Sans CJK collections list JP, KR, SC, TC, HK in that order, so TC is face 3.
        for f in [
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/google-noto/NotoSansCJK-Regular.ttc",
        ] {
            v.push((PathBuf::from(f), 3));
        }
        for f in [
            "/usr/share/fonts/truetype/noto/NotoSansTC-Regular.otf",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/wenquanyi/wqy-microhei/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        ] {
            v.push((PathBuf::from(f), 0));
        }
    }
    v
}

/// First candidate that exists as a regular file of a sane size.
pub fn find() -> Option<(PathBuf, u32)> {
    candidates().into_iter().find(|(p, _)| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() <= MAX_FONT_BYTES))
}

/// Replaces the fonts: egui's defaults, plus the CJK font as a fallback for both families when given.
pub fn install(ctx: &egui::Context, font: Option<&(PathBuf, u32)>) -> Result<(), String> {
    let mut defs = egui::FontDefinitions::default();
    if let Some((path, index)) = font {
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut data = egui::FontData::from_owned(bytes);
        data.index = *index;
        defs.font_data.insert("cjk".to_string(), Arc::new(data));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            defs.families.entry(family).or_default().push("cjk".to_string());
        }
    }
    ctx.set_fonts(defs);
    Ok(())
}
