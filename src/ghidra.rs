use crate::graph::{search, GraphInfo, RefType};
use petgraph::visit::EdgeRef;
use serde::Serialize;
use indicatif::ProgressIterator;

pub const SCRIPT_SOURCE: &str = include_str!("../resources/xrefgen.py");

#[derive(Serialize)]
struct SymbolTrace<'a> {
    symbol: &'a str,
    start: &'a str,
    trace: String,
}

#[derive(Serialize)]
pub struct Output<'a> {
    traces: Vec<SymbolTrace<'a>>,
}

pub fn gen_ghidra_data<'a>(obj_file: &object::File, graph_info: &'a GraphInfo) -> Output<'a> {
    let mut traces = Vec::new();

    let graph = &graph_info.graph;
    for node in graph_info.graph.node_indices().progress() {
        if let Ok(path) = search(obj_file, graph_info, node) {
            let symbol = graph[node].name;
            let start = graph[path.last().unwrap().source()].name;

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
