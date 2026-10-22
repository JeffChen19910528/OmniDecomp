//! The loaded model of one file: what the views show, and address / offset / xref lookups on it.

use omnidecomp_app::{self as app, Analysis, DisasmOptions};
use omnidecomp_core::{
    CallGraph, CfgResult, Context, DebugInfo, Disassembly, DotnetInfo, Error, ErrorCode, Format, FunctionsResult, Limits, Symbol,
    StringsResult,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};

/// Everything the front end shows for one file. Parts that the file or the engines cannot provide are
/// `None`/empty and explained in `notes`; nothing is faked.
pub struct Loaded {
    pub name: String,
    pub analysis: Analysis,
    pub disasm: Option<Disassembly>,
    pub functions: Option<FunctionsResult>,
    pub symbols: Vec<Symbol>,
    pub strings: StringsResult,
    pub debug: Option<DebugInfo>,
    pub dotnet: Option<DotnetInfo>,
    pub notes: Vec<String>,
    /// Indices into `disasm.instructions` sorted by address, for binary search.
    pub(crate) by_addr: Vec<usize>,
    pub(crate) xrefs_to: HashMap<u64, Vec<usize>>,
    pub(crate) xrefs_from: HashMap<u64, Vec<usize>>,
    pub(crate) call_graph: OnceLock<CallGraph>,
}

/// Loads `path` with `limits`. `cancel` aborts at the next check; `progress` receives phase names.
pub fn load(path: &Path, limits: Limits, cancel: &Arc<AtomicBool>, progress: &dyn Fn(&str)) -> Result<Loaded, Error> {
    load_gated(path, limits, cancel, progress, None)
}

/// Like `load`, but refuses files whose format or architecture belongs to a disabled built-in plugin
/// when `plugins` is given (the same check the CLI makes).
pub fn load_gated(
    path: &Path,
    limits: Limits,
    cancel: &Arc<AtomicBool>,
    progress: &dyn Fn(&str),
    plugins: Option<&omnidecomp_plugins::Locations>,
) -> Result<Loaded, Error> {
    let ctx = Context::with_cancel(limits, Arc::clone(cancel));
    let ctx_ref = &ctx;

    progress("reading and parsing");
    let analysis = app::analyze(path, ctx_ref)?;
    if let Some(loc) = plugins {
        loc.registry()?.check_analysis(analysis.info.format, analysis.info.arch)?;
    }
    let mut notes = Vec::new();

    progress("disassembling");
    let opts = DisasmOptions { engine: "auto", arch: None, section: None, max_instructions: ctx.limits.max_instructions };
    let disasm = match app::disassemble(&analysis, &opts, ctx_ref) {
        Ok(d) => Some(d),
        Err(e) if is_soft(&e) => {
            notes.push(format!("disassembly unavailable: {}", e.message));
            None
        }
        Err(e) => return Err(e),
    };
    progress("symbols");
    let symbols = match app::symbols(&analysis, ctx_ref) {
        Ok(s) => s.symbols,
        Err(e) if is_soft(&e) => {
            notes.push(format!("symbols unavailable: {}", e.message));
            Vec::new()
        }
        Err(e) => return Err(e),
    };
    progress("recovering functions");
    let functions = match &disasm {
        Some(d) => match app::functions_for(&analysis, d, &symbols, ctx_ref) {
            Ok(f) => Some(f),
            Err(e) if is_soft(&e) => {
                notes.push(format!("functions unavailable: {}", e.message));
                None
            }
            Err(e) => return Err(e),
        },
        None => None,
    };
    progress("strings");
    let strings = app::extract_strings(&analysis.data, 4, ctx_ref)?;
    let debug = app::debug_info(&analysis, ctx_ref).unwrap_or(None);
    let dotnet = app::dotnet(&analysis, ctx_ref).ok();
    for (what, truncated) in [
        ("disassembly", disasm.as_ref().is_some_and(|d| d.truncated)),
        ("strings", strings.truncated),
        ("functions", functions.as_ref().is_some_and(|f| f.truncated)),
    ] {
        if truncated {
            notes.push(format!("{what} output was cut by a configured limit"));
        }
    }

    let mut by_addr: Vec<usize> = disasm.as_ref().map_or(Vec::new(), |d| (0..d.instructions.len()).collect());
    if let Some(d) = &disasm {
        by_addr.sort_by_key(|i| d.instructions[*i].address);
    }
    let (mut xrefs_to, mut xrefs_from): (HashMap<u64, Vec<usize>>, HashMap<u64, Vec<usize>>) = Default::default();
    if let Some(f) = &functions {
        for (i, x) in f.xrefs.iter().enumerate() {
            xrefs_to.entry(x.to).or_default().push(i);
            xrefs_from.entry(x.from).or_default().push(i);
        }
    }
    let name = path.file_name().map_or_else(|| "(unnamed)".to_string(), |n| n.to_string_lossy().into_owned());
    Ok(Loaded { name, analysis, disasm, functions, symbols, strings, debug, dotnet, notes, by_addr, xrefs_to, xrefs_from, call_graph: OnceLock::new() })
}

/// Errors that mean "this capability is not available for this file" rather than a failed load.
fn is_soft(e: &Error) -> bool {
    matches!(e.code, ErrorCode::UnsupportedArch | ErrorCode::Malformed | ErrorCode::Truncated)
}

impl Loaded {
    /// Start of the recovered function that contains `addr`: the nearest start at or below it, rejected
    /// when the exception table gives a size that ends before `addr`.
    pub fn function_containing(&self, addr: u64) -> Option<u64> {
        let f = &self.functions.as_ref()?.functions;
        let i = f.partition_point(|x| x.address <= addr).checked_sub(1)?;
        let c = &f[i];
        (c.size.is_none_or(|s| addr < c.address + s)).then_some(c.address)
    }

    /// Control-flow graph of `function`, built from the disassembly already in memory.
    pub fn cfg(&self, function: u64, limits: Limits) -> Result<CfgResult, Error> {
        let (Some(d), Some(f)) = (self.disasm.as_ref(), self.functions.as_ref()) else {
            return Err(Error::new(ErrorCode::UnsupportedArch, "no disassembly available for this file"));
        };
        let ctx = Context::new(limits);
        let ranges = app::soft_ranges(&self.analysis, &ctx)?;
        app::cfg_for(d, f, &ranges, function, &ctx)
    }

    /// Whole-program call graph, computed once on first use.
    pub fn call_graph(&self) -> Option<&CallGraph> {
        let f = self.functions.as_ref()?;
        Some(self.call_graph.get_or_init(|| app::call_graph_for(f)))
    }

    pub fn instructions(&self) -> &[omnidecomp_core::Instruction] {
        self.disasm.as_ref().map_or(&[], |d| &d.instructions)
    }

    /// Index (in `instructions()`) of the instruction starting exactly at `addr`.
    pub fn instruction_at(&self, addr: u64) -> Option<usize> {
        let ins = self.instructions();
        let pos = self.by_addr.partition_point(|i| ins[*i].address < addr);
        self.by_addr.get(pos).copied().filter(|i| ins[*i].address == addr)
    }

    /// Index of the instruction at `addr` or the closest one after it (for "go to address").
    pub fn instruction_at_or_after(&self, addr: u64) -> Option<usize> {
        let ins = self.instructions();
        let pos = self.by_addr.partition_point(|i| ins[*i].address < addr);
        self.by_addr.get(pos).copied()
    }

    fn base(&self) -> u64 {
        let i = &self.analysis.info;
        if i.format == Format::Pe {
            i.image_base.unwrap_or(0)
        } else {
            0
        }
    }

    /// File offset of a virtual address, if a section with file data maps it.
    pub fn file_offset_of(&self, addr: u64) -> Option<u64> {
        let base = self.base();
        self.analysis.info.sections.iter().find_map(|s| {
            let start = base.wrapping_add(s.virtual_address);
            let delta = addr.checked_sub(start)?;
            (delta < s.file_size).then(|| s.file_offset + delta)
        })
    }

    /// Virtual address that a file offset maps to, if a section covers it.
    pub fn address_of_offset(&self, off: u64) -> Option<u64> {
        let base = self.base();
        self.analysis.info.sections.iter().find_map(|s| {
            let delta = off.checked_sub(s.file_offset)?;
            (s.file_size > 0 && delta < s.file_size).then(|| base.wrapping_add(s.virtual_address).wrapping_add(delta))
        })
    }

    /// Up to `width` bytes of the file starting at `offset` (empty past the end).
    pub fn hex_row(&self, offset: u64, width: usize) -> &[u8] {
        let data = &self.analysis.data;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
        &data[start..start.saturating_add(width).min(data.len())]
    }

    pub fn hex_rows(&self, width: usize) -> usize {
        self.analysis.data.len().div_ceil(width.max(1))
    }

    /// Cross-references pointing at / leaving `addr`.
    pub fn xrefs_to(&self, addr: u64) -> Vec<&omnidecomp_core::CrossReference> {
        self.collect_xrefs(self.xrefs_to.get(&addr))
    }

    pub fn xrefs_from(&self, addr: u64) -> Vec<&omnidecomp_core::CrossReference> {
        self.collect_xrefs(self.xrefs_from.get(&addr))
    }

    fn collect_xrefs(&self, idx: Option<&Vec<usize>>) -> Vec<&omnidecomp_core::CrossReference> {
        match (&self.functions, idx) {
            (Some(f), Some(idx)) => idx.iter().map(|i| &f.xrefs[*i]).collect(),
            _ => Vec::new(),
        }
    }

    /// Name of the symbol or function that starts at `addr`, if one is known.
    pub fn name_at(&self, addr: u64) -> Option<&str> {
        self.functions
            .as_ref()
            .and_then(|f| f.functions.iter().find(|x| x.address == addr))
            .and_then(|x| x.name.as_deref())
            .or_else(|| self.symbols.iter().find(|s| s.address == Some(addr)).map(|s| s.name.as_str()))
    }
}
