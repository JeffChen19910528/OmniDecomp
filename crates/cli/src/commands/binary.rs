//! Commands that inspect a native executable: info, disasm, strings, symbols, functions, xrefs.

use crate::args::Fmt;
use crate::output::{json_out, notes, warn_if};
use crate::session::Session;
use omnidecomp_app as app;
use omnidecomp_core::Error;
use serde_json::json;
use std::path::Path;

pub(super) fn info(s: &Session, file: &Path, format: Fmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let debug = app::debug_info(&a, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&json!({ "artifact": a.artifact, "info": a.info, "debug": debug })),
        Fmt::Text => print_info(&a, debug.as_ref()),
    }
    Ok(())
}

pub(super) fn disasm(
    s: &Session,
    file: &Path,
    arch: Option<&str>,
    engine: &str,
    section: Option<&str>,
    max_instructions: usize,
    format: Fmt,
) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let opts = app::DisasmOptions { engine, arch, section, max_instructions };
    let d = app::disassemble(&a, &opts, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&d),
        Fmt::Text => {
            println!("; engine {} {} ({}), disassembly (not decompilation)", d.engine, d.engine_version, d.arch.as_str());
            for i in &d.instructions {
                println!("{:016x}  {:<24}  {}", i.address, i.bytes, format!("{} {}", i.mnemonic, i.operands).trim_end());
            }
            if d.truncated {
                println!("; output truncated at {} instructions", d.instructions.len());
            }
        }
    }
    Ok(())
}

pub(super) fn strings(s: &Session, file: &Path, min_length: usize, format: Fmt) -> Result<(), Error> {
    let data = app::read_input(file, &s.ctx)?;
    let r = app::extract_strings(&data, min_length, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&r),
        Fmt::Text => {
            for x in &r.strings {
                println!("{:08x}  {}", x.offset, x.text);
            }
            warn_if(r.truncated, "string limit reached; output truncated");
        }
    }
    Ok(())
}

pub(super) fn symbols(s: &Session, file: &Path, format: Fmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let r = app::symbols(&a, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&r),
        Fmt::Text => {
            for x in &r.symbols {
                let addr = x.address.map_or("-".to_string(), |v| format!("{v:016x}"));
                println!("{:<16}  {:<8}  {:<10}  {}", addr, x.kind, x.source, x.name);
            }
            warn_if(r.truncated, "symbol limit reached; output truncated");
        }
    }
    Ok(())
}

pub(super) fn functions(s: &Session, file: &Path, format: Fmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let r = app::functions(&a, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&r),
        Fmt::Text => {
            for f in &r.functions {
                println!(
                    "{:016x}  {:<11}  {:<6}  callers={:<4} size={:<6} {}",
                    f.address,
                    f.source,
                    f.confidence,
                    f.callers,
                    f.size.map_or("?".to_string(), |v| format!("{v:#x}")),
                    f.name.as_deref().unwrap_or("-")
                );
            }
            notes(&r.notes);
            warn_if(r.truncated, "disassembly limit reached; results are partial");
        }
    }
    Ok(())
}

pub(super) fn xrefs(s: &Session, file: &Path, to: Option<u64>, from: Option<u64>, format: Fmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let mut r = app::functions(&a, &s.ctx)?;
    r.xrefs.retain(|x| to.is_none_or(|t| x.to == t) && from.is_none_or(|f| x.from == f));
    match format {
        Fmt::Json => json_out(&json!({ "xrefs": r.xrefs, "truncated": r.truncated, "notes": r.notes })),
        Fmt::Text => {
            for x in &r.xrefs {
                println!("{:016x} -> {:016x}  {}", x.from, x.to, x.kind);
            }
            warn_if(r.truncated, "disassembly limit reached; results are partial");
        }
    }
    Ok(())
}

fn print_info(a: &app::Analysis, debug: Option<&omnidecomp_core::DebugInfo>) {
    let i = &a.info;
    let hex = |v: Option<u64>| v.map_or("none".to_string(), |x| format!("{x:#x}"));
    println!("Format:      {:?}", i.format);
    println!("Arch:        {} (machine {:#x})", i.arch.as_str(), i.machine);
    println!("Bits:        {}", i.bits);
    println!("Endianness:  {:?}", i.endianness);
    println!("Entry point: {}", hex(i.entry_point));
    println!("Image base:  {}", hex(i.image_base));
    println!("Size:        {} bytes", a.artifact.size);
    println!("SHA-256:     {}", a.artifact.sha256);
    if let Some(d) = debug {
        println!("PDB:         {} (guid {}, age {})", d.pdb_path, d.guid, d.age);
    }
    println!("Sections:");
    for s in &i.sections {
        println!(
            "  {:<12} va={:#x} vsize={:#x} offset={:#x} size={:#x}{}",
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.file_offset,
            s.file_size,
            if s.executable { " [exec]" } else { "" }
        );
    }
}
