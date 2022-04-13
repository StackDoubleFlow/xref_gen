#![feature(bool_to_option)]

mod graph;

use anyhow::{ensure, Context, Result};
use clap::Parser;
use graph::{gen_graph, search, Graph, Ref};
use object::Object;
use petgraph::dot::Dot;
use petgraph::graph::EdgeReference;
use petgraph::visit::EdgeRef;
use std::fs;

/// Xref trace generator
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The input ELF
    input: String,
    /// Name of the symbol to trace
    #[clap(short, long)]
    name: Option<String>,
    /// Comma seperated list of sections to ignore (ex: "il2cpp")
    #[clap(short, long, default_value_t)]
    ignore_sections: String,
    /// Create a graph from the xrefs, outputs to "./data/graph.dot"
    #[clap(short, long)]
    graph: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bin_data = fs::read(args.input)?;
    let obj_file = object::File::parse(&*bin_data)?;
    ensure!(obj_file.has_debug_symbols(), "no debug symbols were found");

    let ignored_sections = args
        .ignore_sections
        .split(',')
        .map(|s| s.to_string())
        .collect();
    let graph_info = gen_graph(&bin_data, &obj_file, ignored_sections)?;

    if args.graph {
        let dot = Dot::new(&graph_info.graph);
        fs::write("./data/graph.dot", format!("{:?}", dot))?;
    }

    if let Some(name) = args.name {
        let path = search(&obj_file, &graph_info, &name).context("could not find path")?;
        finish(&graph_info.graph, path);
    }

    Ok(())
}

fn finish(graph: &Graph, path: Vec<EdgeReference<Ref>>) {
    println!("start: {}", graph[path.last().unwrap().source()].demangled);
    for (i, e) in path.iter().rev().enumerate() {
        let target = &graph[e.target()];
        let r = &graph[e.id()];
        println!("{}: {:?}: {}", i, r, target.demangled);
    }
}
