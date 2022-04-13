#![feature(bool_to_option)]

use anyhow::{anyhow, bail, ensure, Context, Result};
use bad64::{disasm, Imm, Op, Operand, Reg};
use clap::Parser;
use object::elf::{STT_FUNC, STT_OBJECT};
use object::{Object, ObjectSection, ObjectSymbol, SymbolFlags};
use petgraph::dot::Dot;
use petgraph::graph::{DiGraph, EdgeReference, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::EdgeDirection;
use std::collections::{HashMap, HashSet, VecDeque};
use std::{fmt, fs};

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
    PcRel { adrp_num: usize },
}

impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RefType::B => "b",
                RefType::Bl => "bl",
                RefType::PcRel { .. } => "pcRelData",
            }
        )
    }
}

struct Ref {
    ty: RefType,
    num: usize,
    offset: u64,
}

impl fmt::Debug for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ty)?;
        match self.ty {
            RefType::B | RefType::Bl => write!(f, "(num: {})", self.num),
            RefType::PcRel { adrp_num } => {
                write!(f, "(num_adrp: {}, ldr_num_offset: {})", adrp_num, self.num)
            }
        }
    }
}

type Graph<'obj> = DiGraph<Symbol<'obj>, Ref>;

struct GraphInfo<'obj> {
    graph: Graph<'obj>,
    name_map: HashMap<&'obj str, NodeIndex>,
    symbol_map: HashMap<u64, NodeIndex>,
}

fn gen_graph<'obj>(
    bin_data: &[u8],
    obj_file: &'obj object::File,
    ignore_sections: HashSet<String>,
) -> Result<GraphInfo<'obj>> {
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
        if let Some(section_idx) = symbol.section_index() {
            if ignore_sections.contains(obj_file.section_by_index(section_idx)?.name()?) {
                continue;
            }
        }
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
        let mut num_adrp = 0;
        let mut num_ldr: HashMap<Reg, usize> = HashMap::new();
        let mut adrp_map = HashMap::new();
        for ins in decoded {
            let ins = ins.map_err(|err| anyhow!("{}", err))?;

            let (op, num, target) = match ins.op() {
                op @ (Op::B | Op::BL) => {
                    let (op, num) = match op {
                        Op::B => (RefType::B, &mut num_b),
                        Op::BL => (RefType::Bl, &mut num_bl),
                        _ => unreachable!(),
                    };
                    let target = match ins.operands()[0] {
                        Operand::Label(Imm::Unsigned(addr)) => addr,
                        _ => bail!("branch target not label"),
                    };
                    let this_num = *num;
                    *num += 1;
                    (op, this_num, target)
                }
                Op::ADRP => {
                    let (reg, imm) = match ins.operands() {
                        &[Operand::Reg { reg, .. }, Operand::Label(Imm::Unsigned(imm))] => {
                            (reg, imm)
                        }
                        _ => bail!("adrp operand not reg"),
                    };
                    adrp_map.insert(reg, (num_adrp, imm, *num_ldr.entry(reg).or_default()));
                    num_adrp += 1;
                    continue;
                }
                Op::LDR => {
                    let (reg, imm) = match ins.operands()[1] {
                        Operand::MemOffset {
                            reg,
                            offset: Imm::Signed(imm),
                            ..
                        } => (reg, imm),
                        _ => continue,
                    };
                    let adrp = match adrp_map.get(&reg) {
                        Some(adrp) => *adrp,
                        None => continue,
                    };
                    adrp_map.remove(&reg);
                    let ty = RefType::PcRel { adrp_num: adrp.0 };
                    let target = (adrp.1 as i64 + imm) as u64;
                    let num_ldr = num_ldr.get_mut(&reg).unwrap();
                    // TODO: will this always be 0 anyways?
                    let this_num = *num_ldr - adrp.2;
                    *num_ldr += 1;
                    (ty, this_num, target)
                }
                _ => continue,
            };
            if let Some(&target) = symbol_map.get(&target) {
                graph.add_edge(
                    node_idx,
                    target,
                    Ref {
                        ty: op,
                        num,
                        offset: ins.address() - addr,
                    },
                );
            }
        }
    }

    Ok(GraphInfo {
        graph,
        name_map,
        symbol_map,
    })
}

fn search<'obj>(
    obj_file: &object::File,
    graph_info: &'obj GraphInfo,
    name: &str,
) -> Option<Vec<EdgeReference<'obj, Ref>>> {
    let graph = &graph_info.graph;
    let roots: HashSet<_> = obj_file
        .symbols()
        .filter_map(|s| s.is_global().then_some(s.address()))
        .collect();

    // Instead of keeping track of the paths like this, I should be keeping track of node parents,
    // but whatever
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
    /// Comma seperated list of sections to ignore (ex: "il2cpp")
    #[clap(short, long, default_value_t)]
    ignore_sections: String,
}

fn main() -> Result<()> {
    let bin_data = fs::read("./data/libil2cpp.dbg.so")?;
    let obj_file = object::File::parse(&*bin_data)?;
    ensure!(obj_file.has_debug_symbols(), "no debug symbols were found");

    let args = Args::parse();
    let ignored_sections = args
        .ignore_sections
        .split(',')
        .map(|s| s.to_string())
        .collect();
    let graph_info = gen_graph(&bin_data, &obj_file, ignored_sections)?;

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
        println!("{}: {:?}: {}", i, r, target.demangled);
    }
}
