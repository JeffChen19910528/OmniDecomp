//! The combined analysis report.

use omnidecomp_core::{
    Context, ErrorCode, Result,
};
use serde_json::{json, Value};
use crate::analysis::{debug_info, symbols, Analysis};
use crate::disasm::{disassemble, DisasmOptions};
use crate::functions::{functions_from, soft_ranges};
use crate::strings::extract_strings;

/// Name of the limit that cut the output short, or null; lets a reader know which flag to raise.
fn limit_name(truncated: bool, name: &'static str) -> Value {
    if truncated { json!(name) } else { Value::Null }
}

pub fn build_report(a: &Analysis, ctx: &Context) -> Result<Value> {
    let strings = extract_strings(&a.data, 4, ctx)?;
    let opts = DisasmOptions {
        engine: "auto",
        arch: None,
        section: None,
        max_instructions: ctx.limits.max_instructions,
    };
    let ranges = soft_ranges(a, ctx)?;
    let (symbols_json, syms) = match symbols(a, ctx) {
        Ok(s) => (json!({ "status": "ok", "count": s.symbols.len(), "truncated": s.truncated, "limit": limit_name(s.truncated, "max_symbols") }), s.symbols),
        Err(e) if matches!(e.code, ErrorCode::Malformed | ErrorCode::Truncated) => {
            (json!({ "status": "unavailable", "error": e.code.as_str(), "reason": e.message }), Vec::new())
        }
        Err(e) => return Err(e),
    };
    let (disassembly, functions_json) = match disassemble(a, &opts, ctx) {
        Ok(d) => {
            let f = functions_from(a, &d, &syms, &ranges, ctx)?;
            (
                json!({
                    "status": "ok",
                    "engine": d.engine,
                    "engine_version": d.engine_version,
                    "instruction_count": d.instructions.len(),
                    "truncated": d.truncated,
                    "limit": limit_name(d.truncated, "max_instructions"),
                }),
                json!({
                    "status": "ok",
                    "count": f.functions.len(),
                    "with_size": f.functions.iter().filter(|x| x.size.is_some()).count(),
                    "xref_count": f.xrefs.len(),
                    "truncated": f.truncated,
                    "limit": limit_name(f.truncated, "max_instructions"),
                }),
            )
        }
        Err(e) if matches!(e.code, ErrorCode::UnsupportedArch | ErrorCode::Malformed) => {
            let v = json!({ "status": "unavailable", "error": e.code.as_str(), "reason": e.message });
            (v.clone(), v)
        }
        Err(e) => return Err(e),
    };
    Ok(json!({
        "tool": { "name": "omnidecomp", "version": env!("CARGO_PKG_VERSION") },
        "artifact": a.artifact,
        "info": a.info,
        "strings": {
            "count": strings.strings.len(),
            "truncated": strings.truncated,
            "limit": limit_name(strings.truncated, "max_strings"),
        },
        "debug": debug_info(a, ctx)?,
        "dotnet": omnidecomp_formats::dotnet_info(&a.data, &a.info, ctx)?.map(|d| json!({
            "runtime_version": d.runtime_version,
            "assembly": d.assembly,
            "type_count": d.type_count,
            "method_count": d.method_count,
            "decompilation": "not available: no .NET decompiler engine is installed",
        })),
        "symbols": symbols_json,
        "disassembly": disassembly,
        "functions": functions_json,
    }))
}
