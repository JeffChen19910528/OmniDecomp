//! Layered graph layout for the CFG and call-graph views. Pure data in, pure data out, so the layout is
//! tested without a window. Nodes get a layer (row) and a horizontal slot; the front end maps these grid
//! units to pixels. Loops are handled by marking back edges instead of recursing, and every pass is
//! iterative so a deep graph cannot overflow the stack.

use omnidecomp_core::{CallGraph, CfgResult};
use std::collections::{HashMap, HashSet};

/// Upper bound on nodes drawn at once; larger graphs are cut and flagged `truncated`.
pub const MAX_GRAPH_NODES: usize = 400;

#[derive(Debug, Clone, PartialEq)]
pub struct GraphNode {
    pub id: u64,
    pub label: String,
    /// Row from the top (0 = roots).
    pub layer: usize,
    /// Horizontal slot, centred on 0 for the widest layer.
    pub x: f32,
    /// Control can leave the graph from here (shown with a marker).
    pub exits: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdge {
    pub from: usize,
    pub to: usize,
    pub kind: &'static str,
    /// Points upwards or sideways in the layering (a loop or recursion).
    pub back: bool,
    pub count: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GraphLayout {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub layers: usize,
    /// Slots used by the widest layer.
    pub width: usize,
    pub truncated: bool,
}

impl GraphLayout {
    pub fn node_index(&self, id: u64) -> Option<usize> {
        self.nodes.iter().position(|n| n.id == id)
    }
}

pub struct NodeSpec {
    pub id: u64,
    pub label: String,
    pub exits: bool,
}

pub struct EdgeSpec {
    pub from: u64,
    pub to: u64,
    pub kind: &'static str,
    pub count: usize,
}

/// Lays out `nodes`/`edges`. `root` (when present) starts the first layer; nodes without incoming edges
/// follow, then anything still unplaced. Edges to unknown ids are dropped; duplicate ids are merged.
pub fn layout(nodes: Vec<NodeSpec>, edges: Vec<EdgeSpec>, root: Option<u64>, max_nodes: usize) -> GraphLayout {
    let mut truncated = false;
    let mut specs: Vec<NodeSpec> = Vec::new();
    let mut index: HashMap<u64, usize> = HashMap::new();
    for n in nodes {
        if index.contains_key(&n.id) {
            continue;
        }
        if specs.len() >= max_nodes {
            truncated = true;
            continue;
        }
        index.insert(n.id, specs.len());
        specs.push(n);
    }
    let n = specs.len();
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); n]; // adjacency by edge index
    let mut raw: Vec<(usize, usize, &'static str, usize)> = Vec::new();
    let mut seen_pair: HashSet<(usize, usize, &'static str)> = HashSet::new();
    for e in edges {
        let (Some(&f), Some(&t)) = (index.get(&e.from), index.get(&e.to)) else { continue };
        if seen_pair.insert((f, t, e.kind)) {
            out[f].push(raw.len());
            raw.push((f, t, e.kind, e.count));
        }
    }
    let mut indeg = vec![0usize; n];
    for r in &raw {
        indeg[r.1] += 1;
    }

    // Depth-first search for a spanning order and back edges.
    let mut starts: Vec<usize> = Vec::new();
    if let Some(r) = root.and_then(|r| index.get(&r)) {
        starts.push(*r);
    }
    starts.extend((0..n).filter(|i| indeg[*i] == 0));
    starts.extend(0..n);
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        New,
        Open,
        Done,
    }
    let mut mark = vec![Mark::New; n];
    let mut back = vec![false; raw.len()];
    let mut post: Vec<usize> = Vec::with_capacity(n);
    let mut discovery: Vec<usize> = vec![usize::MAX; n];
    let mut counter = 0;
    for s in starts {
        if mark[s] != Mark::New {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(s, 0)];
        mark[s] = Mark::Open;
        discovery[s] = counter;
        counter += 1;
        while let Some(&(v, i)) = stack.last() {
            if let Some(&ei) = out[v].get(i) {
                stack.last_mut().unwrap().1 += 1;
                let t = raw[ei].1;
                match mark[t] {
                    Mark::New => {
                        mark[t] = Mark::Open;
                        discovery[t] = counter;
                        counter += 1;
                        stack.push((t, 0));
                    }
                    Mark::Open => back[ei] = true,
                    Mark::Done => {}
                }
            } else {
                mark[v] = Mark::Done;
                post.push(v);
                stack.pop();
            }
        }
    }

    // Longest-path layering over the acyclic part, in reverse post-order.
    let mut layer = vec![0usize; n];
    for &v in post.iter().rev() {
        for &ei in &out[v] {
            if !back[ei] {
                let t = raw[ei].1;
                layer[t] = layer[t].max(layer[v] + 1);
            }
        }
    }
    let layers = layer.iter().copied().max().map_or(0, |m| m + 1);
    let mut rows: Vec<Vec<usize>> = vec![Vec::new(); layers];
    let mut by_discovery: Vec<usize> = (0..n).collect();
    by_discovery.sort_by_key(|i| discovery[*i]);
    for v in by_discovery {
        rows[layer[v]].push(v);
    }

    // Barycentre sweeps reduce crossings; ties keep the previous order, so the result is deterministic.
    let mut pos = vec![0f32; n];
    let set_pos = |rows: &Vec<Vec<usize>>, pos: &mut Vec<f32>| {
        for r in rows {
            for (i, v) in r.iter().enumerate() {
                pos[*v] = i as f32;
            }
        }
    };
    set_pos(&rows, &mut pos);
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (ei, r) in raw.iter().enumerate() {
        if !back[ei] {
            preds[r.1].push(r.0);
            succs[r.0].push(r.1);
        }
    }
    for sweep in 0..4 {
        let down = sweep % 2 == 0;
        let order: Vec<usize> = if down { (1..layers).collect() } else { (0..layers.saturating_sub(1)).rev().collect() };
        for li in order {
            let neighbours = if down { &preds } else { &succs };
            let key = |v: usize| -> f32 {
                let ns = &neighbours[v];
                if ns.is_empty() {
                    pos[v]
                } else {
                    ns.iter().map(|u| pos[*u]).sum::<f32>() / ns.len() as f32
                }
            };
            let mut keyed: Vec<(f32, f32, usize)> = rows[li].iter().map(|v| (key(*v), pos[*v], *v)).collect();
            keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.total_cmp(&b.1)));
            rows[li] = keyed.into_iter().map(|k| k.2).collect();
            for (i, v) in rows[li].iter().enumerate() {
                pos[*v] = i as f32;
            }
        }
    }

    let width = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut x = vec![0f32; n];
    for r in &rows {
        let offset = (width - r.len()) as f32 / 2.0;
        for (i, v) in r.iter().enumerate() {
            x[*v] = offset + i as f32;
        }
    }
    let out_nodes: Vec<GraphNode> = specs
        .into_iter()
        .enumerate()
        .map(|(i, s)| GraphNode { id: s.id, label: s.label, layer: layer[i], x: x[i], exits: s.exits })
        .collect();
    let out_edges = raw
        .into_iter()
        .enumerate()
        .map(|(ei, (f, t, kind, count))| GraphEdge { from: f, to: t, kind, back: back[ei] || layer[t] <= layer[f], count })
        .collect();
    GraphLayout { nodes: out_nodes, edges: out_edges, layers, width, truncated }
}

/// Layout of one function's basic blocks.
pub fn cfg_layout(r: &CfgResult) -> GraphLayout {
    let nodes = r
        .blocks
        .iter()
        .map(|b| NodeSpec { id: b.start, label: format!("{:#x}\n{} insn", b.start, b.instruction_count), exits: b.exits_graph })
        .collect();
    let edges = r
        .blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |s| EdgeSpec { from: b.start, to: s.to, kind: s.kind, count: 1 }))
        .collect();
    let mut l = layout(nodes, edges, Some(r.function), MAX_GRAPH_NODES);
    l.truncated |= r.truncated;
    l
}

/// Layout of the functions within `depth` call edges (either direction) of `center`, at most `cap` nodes.
/// The whole graph is not drawn: real programs have thousands of functions and the picture would be noise.
pub fn call_layout(g: &CallGraph, center: u64, depth: usize, cap: usize) -> GraphLayout {
    let cap = cap.min(MAX_GRAPH_NODES);
    let mut adj: HashMap<u64, Vec<u64>> = HashMap::new();
    for e in &g.edges {
        adj.entry(e.from).or_default().push(e.to);
        adj.entry(e.to).or_default().push(e.from);
    }
    let mut keep: Vec<u64> = vec![center];
    let mut seen: HashSet<u64> = HashSet::from([center]);
    let mut frontier = vec![center];
    let mut truncated = false;
    'outer: for _ in 0..depth {
        let mut next = Vec::new();
        for v in frontier {
            let mut ns = adj.get(&v).cloned().unwrap_or_default();
            ns.sort_unstable();
            for u in ns {
                if seen.insert(u) {
                    if keep.len() >= cap {
                        truncated = true;
                        break 'outer;
                    }
                    keep.push(u);
                    next.push(u);
                }
            }
        }
        frontier = next;
    }
    let names: HashMap<u64, Option<&str>> = g.nodes.iter().map(|n| (n.address, n.name.as_deref())).collect();
    let nodes = keep
        .iter()
        .filter(|a| names.contains_key(a))
        .map(|a| NodeSpec {
            id: *a,
            label: match names[a] {
                Some(n) => format!("{n}\n{a:#x}"),
                None => format!("sub_{a:x}\n{a:#x}"),
            },
            exits: false,
        })
        .collect();
    let edges = g.edges.iter().map(|e| EdgeSpec { from: e.from, to: e.to, kind: "call", count: e.count }).collect();
    let mut l = layout(nodes, edges, Some(center), cap);
    l.truncated |= truncated || g.truncated;
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: u64) -> NodeSpec {
        NodeSpec { id, label: format!("n{id}"), exits: false }
    }
    fn e(from: u64, to: u64) -> EdgeSpec {
        EdgeSpec { from, to, kind: "jump", count: 1 }
    }

    #[test]
    fn diamond_gets_three_layers_and_no_back_edges() {
        let l = layout(vec![n(1), n(2), n(3), n(4)], vec![e(1, 2), e(1, 3), e(2, 4), e(3, 4)], Some(1), 100);
        let layer = |id| l.nodes[l.node_index(id).unwrap()].layer;
        assert_eq!((layer(1), layer(2), layer(3), layer(4)), (0, 1, 1, 2));
        assert_eq!(l.layers, 3);
        assert_eq!(l.width, 2);
        assert!(l.edges.iter().all(|e| !e.back));
    }

    #[test]
    fn loops_and_self_loops_are_back_edges_and_do_not_hang() {
        let l = layout(vec![n(1), n(2), n(3)], vec![e(1, 2), e(2, 3), e(3, 2), e(3, 3)], Some(1), 100);
        let back: Vec<_> = l.edges.iter().filter(|e| e.back).map(|e| (l.nodes[e.from].id, l.nodes[e.to].id)).collect();
        assert_eq!(back, vec![(3, 2), (3, 3)]);
        let layer = |id| l.nodes[l.node_index(id).unwrap()].layer;
        assert_eq!((layer(1), layer(2), layer(3)), (0, 1, 2));
    }

    #[test]
    fn same_layer_nodes_do_not_overlap_and_layout_is_deterministic() {
        let nodes = || (1..=9).map(n).collect::<Vec<_>>();
        let edges = || vec![e(1, 2), e(1, 3), e(1, 4), e(2, 5), e(3, 6), e(4, 7), e(5, 8), e(6, 8), e(7, 9), e(2, 9)];
        let a = layout(nodes(), edges(), Some(1), 100);
        let b = layout(nodes(), edges(), Some(1), 100);
        assert_eq!(a, b);
        for layer in 0..a.layers {
            let mut xs: Vec<f32> = a.nodes.iter().filter(|n| n.layer == layer).map(|n| n.x).collect();
            xs.sort_by(f32::total_cmp);
            assert!(xs.windows(2).all(|w| w[1] - w[0] >= 1.0 - 1e-6), "layer {layer} overlaps: {xs:?}");
            assert!(xs.iter().all(|x| *x >= 0.0 && *x <= a.width as f32 - 1.0 + 1e-6));
        }
    }

    #[test]
    fn unknown_edges_duplicates_and_disconnected_nodes_are_handled() {
        let l = layout(vec![n(1), n(1), n(2), n(7)], vec![e(1, 2), e(1, 2), e(1, 99), e(98, 1)], Some(1), 100);
        assert_eq!(l.nodes.len(), 3);
        assert_eq!(l.edges.len(), 1);
        assert!(l.nodes.iter().all(|n| n.layer < l.layers));
    }

    #[test]
    fn node_cap_truncates_and_a_deep_chain_does_not_overflow_the_stack() {
        let nodes: Vec<_> = (0..50_000).map(n).collect();
        let edges: Vec<_> = (0..49_999).map(|i| e(i, i + 1)).collect();
        let l = layout(nodes, edges, Some(0), 40_000);
        assert!(l.truncated);
        assert_eq!(l.nodes.len(), 40_000);
        assert_eq!(l.layers, 40_000);
        assert!(layout(Vec::new(), Vec::new(), None, 10).nodes.is_empty());
    }

    #[test]
    fn call_layout_keeps_the_neighbourhood_only() {
        use omnidecomp_core::{CallEdge, FunctionInfo};
        let f = |address| FunctionInfo { address, name: None, source: "symbol", confidence: "high", size: None, callers: 0 };
        let g = CallGraph {
            nodes: (1..=6).map(f).collect(),
            edges: vec![
                CallEdge { from: 1, to: 2, count: 1 },
                CallEdge { from: 2, to: 3, count: 2 },
                CallEdge { from: 3, to: 4, count: 1 },
                CallEdge { from: 6, to: 2, count: 1 },
            ],
            truncated: false,
            notes: Vec::new(),
        };
        let l = call_layout(&g, 2, 1, 50);
        let mut ids: Vec<u64> = l.nodes.iter().map(|n| n.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2, 3, 6], "depth 1 = direct callers and callees");
        assert!(!l.truncated);
        let l2 = call_layout(&g, 2, 5, 3);
        assert_eq!(l2.nodes.len(), 3);
        assert!(l2.truncated, "cap cuts the neighbourhood and says so");
        assert!(l2.nodes[l2.node_index(2).unwrap()].label.contains("sub_2"));
    }
}
