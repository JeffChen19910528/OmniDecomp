//! Report export: JSON, text, CSV and HTML renderings of one analysis.
//! Names and paths come from untrusted files, so CSV cells are guarded against spreadsheet formulas
//! and HTML output is fully escaped and carries a CSP that forbids scripts.

use crate::{build_report, functions, symbols, Analysis};
use omnidecomp_core::{Context, ErrorCode, FunctionInfo, Result, Symbol};
use serde_json::Value;
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Text,
    Csv,
    Html,
}

impl ExportFormat {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            "csv" => Some(Self::Csv),
            "html" => Some(Self::Html),
            _ => None,
        }
    }
}

struct Tables {
    symbols: Vec<Symbol>,
    functions: Vec<FunctionInfo>,
    notes: Vec<String>,
}

/// Symbols and functions for the detail tables. A malformed or unsupported part becomes a note,
/// never guessed rows.
fn tables(a: &Analysis, ctx: &Context) -> Result<Tables> {
    let mut t = Tables { symbols: Vec::new(), functions: Vec::new(), notes: Vec::new() };
    match symbols(a, ctx) {
        Ok(s) => t.symbols = s.symbols,
        Err(e) if matches!(e.code, ErrorCode::Malformed | ErrorCode::Truncated) => {
            t.notes.push(format!("symbols unavailable: {}", e.message));
        }
        Err(e) => return Err(e),
    }
    match functions(a, ctx) {
        Ok(f) => t.functions = f.functions,
        Err(e) if matches!(e.code, ErrorCode::UnsupportedArch | ErrorCode::Malformed) => {
            t.notes.push(format!("functions unavailable: {}", e.message));
        }
        Err(e) => return Err(e),
    }
    Ok(t)
}

pub fn export_report(a: &Analysis, ctx: &Context, format: ExportFormat) -> Result<String> {
    let report = build_report(a, ctx)?;
    if format == ExportFormat::Json {
        return Ok(serde_json::to_string_pretty(&report).unwrap_or_default());
    }
    let t = tables(a, ctx)?;
    Ok(match format {
        ExportFormat::Text => text(a, &report, &t),
        ExportFormat::Csv => csv(a, &t),
        _ => html(a, &report, &t),
    })
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

fn opt_hex(v: Option<u64>) -> String {
    v.map(hex).unwrap_or_default()
}

fn field<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |v, k| &v[*k])
}

fn show(v: &Value) -> String {
    match v {
        Value::Null => "none".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Summary lines shared by the text and HTML renderings.
fn summary(a: &Analysis, report: &Value) -> Vec<(&'static str, String)> {
    let i = &a.info;
    let mut rows = vec![
        ("Format", format!("{:?}", i.format)),
        ("Architecture", format!("{} ({}-bit)", i.arch.as_str(), i.bits)),
        ("Entry point", i.entry_point.map_or("none".into(), hex)),
        ("Size", format!("{} bytes", a.artifact.size)),
        ("SHA-256", a.artifact.sha256.clone()),
        ("Tool version", show(field(report, &["tool", "version"]))),
        ("Strings", show(field(report, &["strings", "count"]))),
        ("Symbols", show(field(report, &["symbols", "count"]))),
        ("Instructions", show(field(report, &["disassembly", "instruction_count"]))),
        ("Engine", format!("{} {}", show(field(report, &["disassembly", "engine"])), show(field(report, &["disassembly", "engine_version"])))),
        ("Functions", show(field(report, &["functions", "count"]))),
        ("Cross-references", show(field(report, &["functions", "xref_count"]))),
    ];
    let debug = field(report, &["debug"]);
    if !debug.is_null() {
        rows.push(("PDB", format!("{} (guid {}, age {})", show(&debug["pdb_path"]), show(&debug["guid"]), show(&debug["age"]))));
    }
    for part in ["strings", "symbols", "disassembly", "functions"] {
        let limit = field(report, &[part, "limit"]);
        if !limit.is_null() {
            rows.push(("Truncated", format!("{part} output was cut by {}", show(limit))));
        }
    }
    rows
}

fn text(a: &Analysis, report: &Value, t: &Tables) -> String {
    let mut out = String::from("OmniDecomp report (static analysis only)\n");
    for (k, v) in summary(a, report) {
        let _ = writeln!(out, "{k:<17}{v}");
    }
    let _ = writeln!(out, "Sections:");
    for s in &a.info.sections {
        let _ = writeln!(out, "  {:<12} va={} vsize={} size={}{}", s.name, hex(s.virtual_address), hex(s.virtual_size), hex(s.file_size), if s.executable { " [exec]" } else { "" });
    }
    let _ = writeln!(out, "Functions ({}):", t.functions.len());
    for f in &t.functions {
        let _ = writeln!(out, "  {:016x} size={} {} {}", f.address, f.size.map_or("?".into(), hex), f.source, f.name.as_deref().unwrap_or(""));
    }
    for n in &t.notes {
        let _ = writeln!(out, "note: {n}");
    }
    out
}

/// A cell that starts with a formula character is prefixed with `'` so spreadsheets treat it as text.
fn csv_cell(raw: &str) -> String {
    let mut s = raw.to_string();
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        s.insert(0, '\'');
    }
    if s.contains([',', '"', '\n', '\r']) {
        s = format!("\"{}\"", s.replace('"', "\"\""));
    }
    s
}

fn csv(a: &Analysis, t: &Tables) -> String {
    let mut out = String::from("kind,name,address,size,detail\n");
    let mut row = |cells: [String; 5]| {
        let line: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    };
    for s in &a.info.sections {
        row([
            "section".into(),
            s.name.clone(),
            hex(s.virtual_address),
            hex(s.virtual_size),
            format!("file_offset={};file_size={}{}", hex(s.file_offset), hex(s.file_size), if s.executable { ";exec" } else { "" }),
        ]);
    }
    for s in &t.symbols {
        row(["symbol".into(), s.name.clone(), opt_hex(s.address), String::new(), format!("{};{}", s.kind, s.source)]);
    }
    for f in &t.functions {
        row([
            "function".into(),
            f.name.clone().unwrap_or_default(),
            hex(f.address),
            opt_hex(f.size),
            format!("{};{};callers={}", f.source, f.confidence, f.callers),
        ]);
    }
    out
}

fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn html(a: &Analysis, report: &Value, t: &Tables) -> String {
    let mut o = String::from(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>OmniDecomp report</title>\n\
         <style>body{font:14px system-ui,sans-serif;margin:2em;color:#222}table{border-collapse:collapse;margin:1em 0}\
         td,th{border:1px solid #ccc;padding:3px 8px;text-align:left}code{font-family:ui-monospace,monospace}</style>\n\
         </head><body>\n<h1>OmniDecomp report</h1>\n<p>Static analysis only; disassembly is not decompilation.</p>\n<table>\n",
    );
    for (k, v) in summary(a, report) {
        let _ = writeln!(o, "<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(&v));
    }
    o.push_str("</table>\n<h2>Sections</h2>\n<table><tr><th>Name</th><th>VA</th><th>VSize</th><th>File offset</th><th>File size</th><th>Exec</th></tr>\n");
    for s in &a.info.sections {
        let _ = writeln!(
            o,
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&s.name), hex(s.virtual_address), hex(s.virtual_size), hex(s.file_offset), hex(s.file_size), if s.executable { "yes" } else { "" }
        );
    }
    let _ = writeln!(o, "</table>\n<h2>Functions ({})</h2>\n<table><tr><th>Address</th><th>Name</th><th>Size</th><th>Source</th><th>Confidence</th><th>Callers</th></tr>", t.functions.len());
    for f in &t.functions {
        let _ = writeln!(
            o,
            "<tr><td><code>{:016x}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            f.address, esc(f.name.as_deref().unwrap_or("")), opt_hex(f.size), f.source, f.confidence, f.callers
        );
    }
    let _ = writeln!(o, "</table>\n<h2>Symbols ({})</h2>\n<table><tr><th>Name</th><th>Address</th><th>Kind</th><th>Source</th></tr>", t.symbols.len());
    for s in &t.symbols {
        let _ = writeln!(o, "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>", esc(&s.name), opt_hex(s.address), s.kind, s.source);
    }
    o.push_str("</table>\n");
    for n in &t.notes {
        let _ = writeln!(o, "<p>Note: {}</p>", esc(n));
    }
    o.push_str("</body></html>\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_guard_formulas_and_quote_specials() {
        assert_eq!(csv_cell("=1+1"), "'=1+1");
        assert_eq!(csv_cell("@x"), "'@x");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("plain"), "plain");
    }

    #[test]
    fn html_escaping() {
        assert_eq!(esc("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }
}
