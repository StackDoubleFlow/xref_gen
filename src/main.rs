#![feature(bool_to_option)]

use anyhow::{anyhow, bail, ensure, Result, Context};
use bad64::{disasm, Imm, Op, Operand};
use object::elf::{STT_FUNC, STT_OBJECT};
use object::{Object, ObjectSymbol, SymbolFlags};
use petgraph::EdgeDirection;
use petgraph::dot::Dot;
use petgraph::graph::{DiGraph, NodeIndex, EdgeReference};
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet, VecDeque};
use std::{fmt, fs};
use clap::Parser;

#[derive(Debug, PartialEq, Eq)]
enum SymbolType {
    Function,
    Data,
}

struct Symbol<'obj> {
    addr: u64,
    size: u64,
    name: &'obj str,
    demangled: String,
    ty: SymbolType,
}

impl fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.demangled)
    }
}

#[derive(Debug)]
enum RefType {
    B,
    Bl,
}

impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            RefType::B => "b",
            RefType::Bl => "bl",
        })
    }
}

struct Ref {
    ty: RefType,
    num: usize,
    offset: u64,
}

impl fmt::Debug for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({})", self.ty, self.num)
    }
}

type Graph<'obj> = DiGraph<Symbol<'obj>, Ref>;

struct GraphInfo<'obj> {
    graph: Graph<'obj>,
    name_map: HashMap<&'obj str, NodeIndex>,
    symbol_map: HashMap<u64, NodeIndex>,
}

fn gen_graph<'obj>(bin_data: &[u8], obj_file: &'obj object::File) -> Result<GraphInfo<'obj>> {
    let mut graph = Graph::new();
    let mut symbol_map = HashMap::new();
    let mut name_map = HashMap::new();

    for symbol in obj_file.symbols() {
        if !symbol.is_definition() {
            continue;
        }
        let ty = match symbol.flags() {
            SymbolFlags::Elf { st_info, .. } => match st_info & 0xf {
                STT_FUNC => SymbolType::Function,
                STT_OBJECT => SymbolType::Data,
                _ => continue,
            },
            _ => bail!("Symbol flags not elf format"),
        };
        let demangled = if let Ok(demangle) = cpp_demangle::Symbol::new(symbol.name_bytes()?) {
            demangle.to_string()
        } else {
            symbol.name()?.to_string()
        };
        let n = graph.add_node(Symbol {
            addr: symbol.address(),
            size: symbol.size(),
            name: symbol.name()?,
            demangled,
            ty,
        });
        symbol_map.insert(symbol.address(), n);
        name_map.insert(symbol.name()?, n);
    }

    for node_idx in graph.node_indices() {
        let n = &graph[node_idx];
        if n.ty != SymbolType::Function {
            continue;
        }

        let addr = n.addr;
        let code = &bin_data[addr as usize..(addr + n.size) as usize];
        let decoded = disasm(code, n.addr);
        let mut num_b = 0;
        let mut num_bl = 0;
        for ins in decoded {
            let ins = ins.map_err(|err| anyhow!("{}", err))?;

            let (op, num) = match ins.op() {
                Op::B => (RefType::B, &mut num_b),
                Op::BL => (RefType::Bl, &mut num_bl),
                _ => continue,
            };
            let target = match ins.operands()[0] {
                Operand::Label(Imm::Unsigned(addr)) => addr,
                _ => bail!("branch target not label"),
            };
            if let Some(&target) = symbol_map.get(&target) {
                graph.add_edge(
                    node_idx,
                    target,
                    Ref {
                        ty: op,
                        num: *num,
                        offset: ins.address() - addr,
                    },
                );
            }
            *num += 1;
        }
    }

    Ok(GraphInfo { graph, name_map, symbol_map })
}

fn search<'obj>(obj_file: &object::File, graph_info: &'obj GraphInfo, name: &str) -> Option<Vec<EdgeReference<'obj, Ref>>> {
    let graph = &graph_info.graph;
    let roots: HashSet<_> = obj_file.symbols().filter_map(|s| s.is_global().then_some(s.address())).collect();

    let mut queue: VecDeque<(NodeIndex, Vec<EdgeReference<_>>)> = VecDeque::new();
    queue.push_back((graph_info.name_map[name], Vec::new()));
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    while !queue.is_empty() {
        let (n, mut path) = queue.pop_front().unwrap();
        visited.insert(n);
        for e in graph.edges_directed(n, EdgeDirection::Incoming) {
            let source = e.source();
            if roots.contains(&graph[source].addr) {
                path.push(e);
                return Some(path);
            } else if !visited.contains(&source) {
                visited.insert(source);
                let mut path = path.clone();
                path.push(e);
                queue.push_back((source, path));
            }
            
        }
    }

    None
}

/// Xref trace generator
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of the symbol to trace
    #[clap(short, long)]
    name: String,
}

fn main() -> Result<()> {
    let bin_data = fs::read("./data/libil2cpp.dbg.so")?;
    let obj_file = object::File::parse(&*bin_data)?;
    ensure!(obj_file.has_debug_symbols(), "no debug symbols were found");

    let args = Args::parse();
    let graph_info = gen_graph(&bin_data, &obj_file)?;

    let dot = Dot::new(&graph_info.graph);
    fs::write("./data/graph.dot", format!("{:?}", dot))?;

    let path = search(&obj_file, &graph_info, &args.name).context("could not find path")?;
    finish(&graph_info.graph, path);

    Ok(())
}

fn finish(graph: &Graph, path: Vec<EdgeReference<Ref>>) {
    println!("start: {}", graph[path.last().unwrap().source()].demangled);
    for (i, e) in path.iter().rev().enumerate() {
        let target = &graph[e.target()];
        let r = &graph[e.id()];
        println!("{}: {}({}): {}", i, r.ty, r.num, target.demangled);
    }
}
