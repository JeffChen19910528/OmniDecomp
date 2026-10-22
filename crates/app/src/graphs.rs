//! Control-flow graph, call graph and their DOT rendering.

use omnidecomp_core::{
    BasicBlock, CallEdge, CallGraph, CfgEdge, CfgResult, Instruction, Context, Disassembly, Error, ErrorCode, FunctionsResult, Result,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use crate::analysis::Analysis;
use crate::functions::{code_model, functions, functions_from, ins_len};

/// Control-flow graph of the code reachable from `function`, split into basic blocks.
/// Calls fall through; direct jumps to other known function starts are treated as tail calls
/// and not followed; indirect jumps end the path.
pub fn cfg(a: &Analysis, function: u64, ctx: &Context) -> Result<CfgResult> {
    let (d, syms, ranges) = code_model(a, ctx)?;
    let known = functions_from(a, &d, &syms, &ranges, ctx)?;
    cfg_for(&d, &known, &ranges, function, ctx)
}

/// Like `cfg`, but reuses a disassembly and function list the caller already has (no second sweep).
pub fn cfg_for(d: &Disassembly, known: &FunctionsResult, ranges: &[(u64, u64)], function: u64, ctx: &Context) -> Result<CfgResult> {
    let fn_starts: HashSet<u64> = known.functions.iter().map(|f| f.address).collect();
    let map: HashMap<u64, &Instruction> = d.instructions.iter().map(|i| (i.address, i)).collect();
    if !map.contains_key(&function) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("no decoded instruction at address {function:#x}"),
        ));
    }

    let limit = ctx.limits.max_instructions;
    let mut visited = BTreeSet::new();
    let mut leaders = BTreeSet::from([function]);
    let mut stack = vec![function];
    let mut truncated = false;
    // Exact range when .pdata knows this function; otherwise treat jumps to other known starts as tail calls.
    let range = ranges.binary_search_by_key(&function, |r| r.0).ok().map(|i| ranges[i]);
    let follow = |t: u64| {
        map.contains_key(&t)
            && match range {
                Some((lo, hi)) => t >= lo && t < hi,
                None => t == function || !fn_starts.contains(&t),
            }
    };
    while let Some(addr) = stack.pop() {
        let Some(ins) = map.get(&addr) else { continue };
        if visited.contains(&addr) {
            continue;
        }
        if visited.len() >= limit {
            truncated = true;
            break;
        }
        if visited.len() % 1024 == 0 {
            ctx.check()?;
        }
        visited.insert(addr);
        let next = addr + ins_len(ins);
        if ins.mnemonic == "(bad)" {
            continue;
        }
        match ins.flow {
            Some("return") => {}
            Some("jump") => {
                if let Some(t) = ins.target.filter(|t| follow(*t)) {
                    leaders.insert(t);
                    stack.push(t);
                }
            }
            Some("branch") => {
                if let Some(t) = ins.target.filter(|t| follow(*t)) {
                    leaders.insert(t);
                    stack.push(t);
                }
                leaders.insert(next);
                stack.push(next);
            }
            _ => stack.push(next),
        }
    }

    let addrs: Vec<u64> = visited.iter().copied().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < addrs.len() {
        let start = addrs[i];
        let mut count = 0;
        let last = loop {
            let ins = map[&addrs[i]];
            let cur = addrs[i];
            count += 1;
            i += 1;
            let next = cur + ins_len(ins);
            let terminator = matches!(ins.flow, Some("return" | "jump" | "branch")) || ins.mnemonic == "(bad)";
            if terminator || i >= addrs.len() || addrs[i] != next || leaders.contains(&next) {
                break cur;
            }
        };
        let ins = map[&last];
        let next = last + ins_len(ins);
        let mut successors = Vec::new();
        let mut exits_graph = false;
        let mut edge = |to: u64, kind: &'static str, exits: &mut bool| {
            if visited.contains(&to) {
                successors.push(CfgEdge { to, kind });
            } else {
                *exits = true;
            }
        };
        match ins.flow {
            Some("return") => {}
            Some("jump") => match ins.target {
                Some(t) => edge(t, "jump", &mut exits_graph),
                None => exits_graph = true,
            },
            Some("branch") => {
                match ins.target {
                    Some(t) => edge(t, "taken", &mut exits_graph),
                    None => exits_graph = true,
                }
                edge(next, "fallthrough", &mut exits_graph);
            }
            _ if ins.mnemonic == "(bad)" => exits_graph = true,
            _ => edge(next, "fallthrough", &mut exits_graph),
        }
        blocks.push(BasicBlock { start, end: next, instruction_count: count, successors, exits_graph });
    }
    Ok(CfgResult {
        function,
        blocks,
        truncated: truncated || d.truncated,
        notes: vec!["derived from linear-sweep disassembly; indirect jumps and jump tables are not resolved"],
    })
}

/// Function-to-function call edges. A call is attributed to the nearest function start at or
/// below the call site, because function sizes are unknown.
pub fn call_graph(a: &Analysis, ctx: &Context) -> Result<CallGraph> {
    Ok(call_graph_for(&functions(a, ctx)?))
}

/// Call graph from an already recovered function list.
pub fn call_graph_for(f: &FunctionsResult) -> CallGraph {
    let mut counts: BTreeMap<(u64, u64), usize> = BTreeMap::new();
    for x in f.xrefs.iter().filter(|x| x.kind == "call") {
        let idx = f.functions.partition_point(|n| n.address <= x.from);
        let Some(cand) = idx.checked_sub(1).map(|i| &f.functions[i]) else { continue };
        if cand.size.is_some_and(|sz| x.from >= cand.address + sz) {
            continue; // the exception table says this address is outside the nearest function
        }
        let caller = cand.address;
        if f.functions.binary_search_by_key(&x.to, |n| n.address).is_ok() {
            *counts.entry((caller, x.to)).or_insert(0) += 1;
        }
    }
    CallGraph {
        nodes: f.functions.clone(),
        edges: counts.into_iter().map(|((from, to), count)| CallEdge { from, to, count }).collect(),
        truncated: f.truncated,
        notes: vec![
            "callers are attributed by function size when known, otherwise to the nearest preceding function start",
            "indirect calls are not resolved",
        ],
    }
}

fn dot_escape(s: &str) -> String {
    s.chars().flat_map(|c| if c == '"' || c == '\\' { vec!['\\', c] } else { vec![c] }).collect()
}

pub fn cfg_to_dot(r: &CfgResult) -> String {
    let mut out = String::from("digraph cfg {\n  node [shape=box, fontname=\"monospace\"];\n");
    for b in &r.blocks {
        let exit = if b.exits_graph { " (exits)" } else { "" };
        out.push_str(&format!(
            "  \"{:x}\" [label=\"{:#x}\\n{} instr{}\"];\n",
            b.start, b.start, b.instruction_count, exit
        ));
        for e in &b.successors {
            out.push_str(&format!("  \"{:x}\" -> \"{:x}\" [label=\"{}\"];\n", b.start, e.to, e.kind));
        }
    }
    out.push_str("}\n");
    out
}

pub fn call_graph_to_dot(g: &CallGraph) -> String {
    let mut out = String::from("digraph callgraph {\n  node [shape=box, fontname=\"monospace\"];\n");
    for n in &g.nodes {
        let label = match &n.name {
            Some(name) => format!("{}\\n{:#x}", dot_escape(name), n.address),
            None => format!("{:#x}", n.address),
        };
        out.push_str(&format!("  \"{:x}\" [label=\"{}\"];\n", n.address, label));
    }
    for e in &g.edges {
        let label = if e.count > 1 { format!(" [label=\"x{}\"]", e.count) } else { String::new() };
        out.push_str(&format!("  \"{:x}\" -> \"{:x}\"{};\n", e.from, e.to, label));
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_escape_handles_quotes() {
        assert_eq!(dot_escape("a\"b\\c"), "a\\\"b\\\\c");
    }
}
