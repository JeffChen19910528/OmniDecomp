//! Control-flow graph and call graph.

use crate::args::GraphFmt;
use crate::output::{json_out, notes, warn_if};
use crate::session::Session;
use omnidecomp_app as app;
use omnidecomp_core::Error;
use std::path::Path;

pub(super) fn cfg(s: &Session, file: &Path, function: u64, format: GraphFmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let r = app::cfg(&a, function, &s.ctx)?;
    match format {
        GraphFmt::Json => json_out(&r),
        GraphFmt::Dot => print!("{}", app::cfg_to_dot(&r)),
        GraphFmt::Text => {
            for b in &r.blocks {
                let succ: Vec<_> = b.successors.iter().map(|e| format!("{:x} [{}]", e.to, e.kind)).collect();
                println!(
                    "block {:x}-{:x} ({} instr){} -> {}",
                    b.start,
                    b.end,
                    b.instruction_count,
                    if b.exits_graph { " exits" } else { "" },
                    if succ.is_empty() { "-".to_string() } else { succ.join(", ") }
                );
            }
            warn_if(r.truncated, "limit reached; graph is partial");
        }
    }
    Ok(())
}

pub(super) fn callgraph(s: &Session, file: &Path, format: GraphFmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    let g = app::call_graph(&a, &s.ctx)?;
    match format {
        GraphFmt::Json => json_out(&g),
        GraphFmt::Dot => print!("{}", app::call_graph_to_dot(&g)),
        GraphFmt::Text => {
            for e in &g.edges {
                println!("{:016x} -> {:016x}  x{}", e.from, e.to, e.count);
            }
            notes(&g.notes);
            warn_if(g.truncated, "disassembly limit reached; graph is partial");
        }
    }
    Ok(())
}
