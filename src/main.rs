use anyhow::{anyhow, bail, ensure, Result};
use bad64::{disasm, Imm, Op, Operand};
use object::elf::{STT_FUNC, STT_OBJECT};
use object::{Object, ObjectSymbol, SymbolFlags};
use petgraph::dot::Dot;
use petgraph::graph::DiGraph;
use std::collections::HashMap;
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
}

struct Ref {
    ty: RefType,
    num: usize,
}

impl fmt::Debug for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({})", self.ty, self.num)
    }
}

type Graph<'obj> = DiGraph<Symbol<'obj>, Ref>;

fn search(bin_data: &[u8], obj_file: &object::File) -> anyhow::Result<()> {
    let mut graph = Graph::new();
    let mut symbol_map = HashMap::new();

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
            continue;
        };
        let n = graph.add_node(Symbol {
            addr: symbol.address(),
            size: symbol.size(),
            name: symbol.name()?,
            demangled,
            ty,
        });
        symbol_map.insert(symbol.address(), n);
    }

    for node_idx in graph.node_indices() {
        let n = &graph[node_idx];
        if n.ty != SymbolType::Function {
            continue;
        }

        let code = &bin_data[n.addr as usize..(n.addr + n.size) as usize];
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
                graph.add_edge(node_idx, target, Ref { ty: op, num: *num });
            }
            *num += 1;
        }
    }

    let dot = Dot::new(&graph);
    fs::write("./data/graph.dot", format!("{:?}", dot))?;

    Ok(())
}

fn main() -> Result<()> {
    let bin_data = fs::read("./data/libil2cpp.dbg.so")?;
    let obj_file = object::File::parse(&*bin_data)?;
    ensure!(obj_file.has_debug_symbols(), "no debug symbols were found");

    search(&bin_data, &obj_file)?;

    Ok(())
}
