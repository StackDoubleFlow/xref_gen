mod graph;
mod il2cpp;
mod trace;

use crate::trace::{gen_trace_data, trace};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use graph::{gen_graph, Graph, Ref};
use il2cpp_binary::Elf;
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
    /// Generate data to be imported into ghidra
    #[clap(long)]
    ghidra: bool,
    /// il2cpp metadata file path
    #[clap(long)]
    il2cpp_metadata: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bin_data = fs::read(args.input)?;
    let obj_file = Elf::parse(&*bin_data)?;
    ensure!(obj_file.has_debug_symbols(), "no debug symbols were found");

    let il2cpp_metadata = match args.il2cpp_metadata {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    let il2cpp_data = match &il2cpp_metadata {
        Some(metadata) => Some(il2cpp::process(metadata, &obj_file)?),
        None => None,
    };

    let ignored_sections = args
        .ignore_sections
        .split(',')
        .map(|s| s.to_string())
        .collect();
    let graph_info = gen_graph(&bin_data, &obj_file, ignored_sections, &il2cpp_data)?;

    if args.graph {
        let dot = Dot::new(&graph_info.graph);
        fs::write("./data/graph.dot", format!("{:?}", dot))?;
    }

    if args.ghidra {
        let out = gen_trace_data(&obj_file, &graph_info, &il2cpp_data);
        fs::write("./data/ghidra_data.json", serde_json::to_string(&out)?)?;
        fs::write("./data/xref_gen_ghidra.py", trace::SCRIPT_SOURCE)?;
    }

    if let Some(name) = args.name {
        let node = *graph_info
            .name_map
            .get(name.as_str())
            .context("could not find symbol")?;
        let path =
            trace(&obj_file, &graph_info, node, &il2cpp_data).context("could not find path")?;
        finish(&graph_info.graph, path);
    }

    Ok(())
}

fn finish(graph: &Graph, path: Vec<EdgeReference<Ref>>) {
    println!(
        "start: {}",
        graph[path.last().unwrap().source()].demangled()
    );
    for (i, e) in path.iter().rev().enumerate() {
        let target = &graph[e.target()];
        let r = &graph[e.id()];
        println!("{}: {:?}: {}", i, r, target.demangled());
    }
}
