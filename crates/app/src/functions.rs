//! Function recovery and cross-references from a disassembly.

use omnidecomp_core::{
    Instruction, Context, Disassembly, ErrorCode, Format,
    CrossReference, FunctionInfo, FunctionsResult, Result, Symbol,
};
use crate::analysis::{symbols, Analysis};
use crate::disasm::{code_len, disassemble, rva_base, DisasmOptions};

/// Functions are the union of the entry point, defined function symbols and direct call targets
/// inside executable sections. Sizes are unknown, so none are reported.
pub(crate) fn functions_from(
    a: &Analysis,
    d: &Disassembly,
    syms: &[Symbol],
    ranges: &[(u64, u64)],
    ctx: &Context,
) -> Result<FunctionsResult> {
    let base = rva_base(&a.info);
    let code_ranges: Vec<(u64, u64)> = a
        .info
        .sections
        .iter()
        .filter(|s| s.executable && s.file_size > 0)
        .map(|s| {
            let start = base.wrapping_add(s.virtual_address);
            (start, start.saturating_add(code_len(a.info.format, s)))
        })
        .collect();
    let in_code = |addr: u64| code_ranges.iter().any(|(lo, hi)| addr >= *lo && addr < *hi);

    let mut xrefs = Vec::new();
    for (n, i) in d.instructions.iter().enumerate() {
        if n % 4096 == 0 {
            ctx.check()?;
        }
        if let (Some(kind), Some(to)) = (i.flow, i.target) {
            xrefs.push(CrossReference { from: i.address, to, kind, confidence: "medium" });
        }
    }

    let rank = |source: &str| match source {
        "symbol" => 3,
        "pdata" | "eh_frame" => 2,
        "entry" => 1,
        _ => 0,
    };
    let mut map: std::collections::BTreeMap<u64, FunctionInfo> = std::collections::BTreeMap::new();
    let mut add = |address: u64, name: Option<String>, source: &'static str| {
        let confidence = if source == "call_target" { "medium" } else { "high" };
        let f = map.entry(address).or_insert(FunctionInfo { address, name: None, source, confidence, size: None, callers: 0 });
        if rank(source) > rank(f.source) {
            f.source = source;
            f.confidence = confidence;
        }
        if f.name.is_none() {
            f.name = name;
        }
    };
    if let Some(entry) = a.info.entry_point.filter(|e| in_code(*e)) {
        add(entry, None, "entry");
    }
    let range_source = if a.info.format == Format::Pe { "pdata" } else { "eh_frame" };
    for (lo, _) in ranges.iter().filter(|(lo, _)| in_code(*lo)) {
        add(*lo, None, range_source);
    }
    for s in syms {
        if let Some(addr) = s.address.filter(|x| in_code(*x)) {
            if matches!(s.kind, "function" | "export") {
                add(addr, Some(s.name.clone()), "symbol");
            }
        }
    }
    // With exact ranges, a call into the middle of a known function is not a new function.
    let mid_range = |t: u64| {
        let i = ranges.partition_point(|r| r.0 <= t);
        i.checked_sub(1).is_some_and(|i| t > ranges[i].0 && t < ranges[i].1)
    };
    for x in xrefs.iter().filter(|x| x.kind == "call" && in_code(x.to) && !mid_range(x.to)) {
        add(x.to, None, "call_target");
    }
    for x in xrefs.iter().filter(|x| x.kind == "call") {
        if let Some(f) = map.get_mut(&x.to) {
            f.callers += 1;
        }
    }
    let mut functions: Vec<FunctionInfo> = map.into_values().collect();
    for f in &mut functions {
        if let Ok(i) = ranges.binary_search_by_key(&f.address, |r| r.0) {
            f.size = Some(ranges[i].1 - ranges[i].0);
        }
    }
    let size_note = if ranges.is_empty() {
        "function sizes are unknown"
    } else if a.info.format == Format::Elf {
        "function sizes come from the ELF unwind table (.eh_frame); functions without an FDE have no size"
    } else {
        "function sizes come from the PE exception table (.pdata); functions without a .pdata entry have no size"
    };
    Ok(FunctionsResult {
        functions,
        xrefs,
        truncated: d.truncated,
        notes: vec![
            size_note,
            "derived from linear-sweep disassembly; indirect calls and jump tables are not resolved",
        ],
    })
}

/// Function ranges from the binary; an unreadable table just means "no ranges".
pub fn soft_ranges(a: &Analysis, ctx: &Context) -> Result<Vec<(u64, u64)>> {
    match omnidecomp_formats::function_ranges(&a.data, &a.info, ctx) {
        Ok(r) => Ok(r),
        Err(e) if matches!(e.code, ErrorCode::Malformed | ErrorCode::Truncated) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

type CodeModel = (Disassembly, Vec<Symbol>, Vec<(u64, u64)>);

pub(crate) fn code_model(a: &Analysis, ctx: &Context) -> Result<CodeModel> {
    let opts = DisasmOptions {
        engine: "auto",
        arch: None,
        section: None,
        max_instructions: ctx.limits.max_instructions,
    };
    let d = disassemble(a, &opts, ctx)?;
    let syms = match symbols(a, ctx) {
        Ok(s) => s.symbols,
        Err(e) if matches!(e.code, ErrorCode::Malformed | ErrorCode::Truncated) => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok((d, syms, soft_ranges(a, ctx)?))
}

pub fn functions(a: &Analysis, ctx: &Context) -> Result<FunctionsResult> {
    let (d, syms, ranges) = code_model(a, ctx)?;
    functions_from(a, &d, &syms, &ranges, ctx)
}

/// Like `functions`, but reuses a disassembly and symbols the caller already has (no second sweep).
pub fn functions_for(a: &Analysis, d: &Disassembly, symbols: &[Symbol], ctx: &Context) -> Result<FunctionsResult> {
    functions_from(a, d, symbols, &soft_ranges(a, ctx)?, ctx)
}

pub(crate) fn ins_len(i: &Instruction) -> u64 {
    (i.bytes.len() / 2) as u64
}
