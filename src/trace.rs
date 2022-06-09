use std::collections::{HashSet, VecDeque};

use crate::graph::{GraphInfo, Ref, RefType, Node};
use crate::il2cpp::Il2CppData;
use anyhow::{bail, Result};
use il2cpp_binary::Elf;
use indicatif::ProgressIterator;
use object::{Object, ObjectSymbol};
use petgraph::graph::{EdgeReference, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;
use serde::Serialize;

pub const SCRIPT_SOURCE: &str = include_str!("../resources/xrefgen.py");

#[derive(Serialize)]
struct SymbolTrace {
    symbol: String,
    start: String,
    trace: String,
}

#[derive(Serialize)]
pub struct Output {
    traces: Vec<SymbolTrace>,
}

pub fn trace<'obj>(
    obj_file: &Elf,
    graph_info: &'obj GraphInfo,
    node: NodeIndex,
    il2cpp_data: &'obj Option<Il2CppData>,
) -> Result<Vec<EdgeReference<'obj, Ref>>> {
    let graph = &graph_info.graph;
    let mut roots: HashSet<_> = obj_file
        .symbols()
        .filter_map(|s| s.is_global().then_some(s.address()))
        .collect();
    if let Some(il2cpp_data) = il2cpp_data {
        for method in &il2cpp_data.methods {
            roots.insert(method.addr);
        }
        for invoker in &il2cpp_data.invokers {
            roots.insert(invoker.addr);
        }
    }
    // let mut roots = HashSet::new();
    // roots.insert(obj_file.symbols().find(|s| s.name().unwrap() == "_ZN6il2cpp2vm7Runtime4InitEPKc").unwrap().address());

    // Instead of keeping track of the paths like this, I should be keeping track of node parents,
    // but whatever
    let mut queue: VecDeque<(NodeIndex, Vec<EdgeReference<_>>)> = VecDeque::new();
    queue.push_back((node, Vec::new()));
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    while !queue.is_empty() {
        let (n, mut path) = queue.pop_front().unwrap();
        visited.insert(n);

        for e in graph.edges_directed(n, EdgeDirection::Incoming) {
            let source = e.source();
            if roots.contains(&graph[source].addr()) {
                path.push(e);
                return Ok(path);
            } else if !visited.contains(&source) {
                visited.insert(source);
                let mut path = path.clone();
                path.push(e);
                queue.push_back((source, path));
            }
        }
    }

    bail!("no path was found")
}

pub fn gen_trace_data<'a>(
    obj_file: &Elf,
    graph_info: &'a GraphInfo,
    il2cpp_data: &'a Option<Il2CppData>,
) -> Output {
    let mut traces = Vec::new();

    let graph = &graph_info.graph;
    for node in graph_info.graph.node_indices().progress() {
        if let Ok(path) = trace(obj_file, graph_info, node, il2cpp_data) {
            if !matches!(&graph[node], Node::Symbol(_)) {
                continue;
            }
            let symbol = graph[node].name();
            let start = graph[path.last().unwrap().source()].name();

            let mut s = String::new();
            for e in path.iter().rev() {
                let r = &graph[e.id()];
                let (c, num) = match r.ty {
                    RefType::B => ('B', r.num),
                    RefType::Bl => ('L', r.num),
                    RefType::PcRel { adrp_num } => ('P', adrp_num),
                };
                s.push(c);
                s.push_str(&num.to_string());
            }

            traces.push(SymbolTrace {
                symbol,
                start,
                trace: s,
            });
        }
    }

    Output { traces }
}
