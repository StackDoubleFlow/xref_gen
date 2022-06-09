use anyhow::{anyhow, bail, Result};
use bad64::{disasm, Imm, Op, Operand, Reg};
use il2cpp_binary::Elf;
use object::elf::{STT_FUNC, STT_OBJECT};
use object::{Object, ObjectSection, ObjectSymbol, SymbolFlags};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::il2cpp::{Il2CppData, Il2CppMethod};

#[derive(Debug, PartialEq, Eq)]
pub enum SymbolType {
    Function,
    Data,
}

pub struct Symbol<'obj> {
    pub addr: u64,
    pub size: u64,
    pub name: &'obj str,
    pub demangled: String,
    pub ty: SymbolType,
}

impl fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.demangled())
    }
}

pub enum Node<'obj> {
    Symbol(Symbol<'obj>),
    Il2CppMethod(&'obj Il2CppMethod<'obj>),
    Invoker(&'obj Il2CppMethod<'obj>, u64, u64),
}

impl<'obj> Node<'obj> {
    fn is_function(&self) -> bool {
        match self {
            Node::Symbol(symbol) => symbol.ty == SymbolType::Function,
            Node::Il2CppMethod(_) => true,
            Node::Invoker(_, _, _) => true,
        }
    }

    fn size(&self) -> u64 {
        match self {
            Node::Symbol(symbol) => symbol.size,
            Node::Il2CppMethod(method) => method.size,
            Node::Invoker(_, _, size) => *size,
        }
    }

    pub fn addr(&self) -> u64 {
        match self {
            Node::Symbol(symbol) => symbol.addr,
            Node::Il2CppMethod(method) => method.addr,
            Node::Invoker(_, addr, _) => *addr,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Node::Symbol(symbol) => symbol.name.to_string(),
            Node::Il2CppMethod(method) => format!(
                "il2cpp:{}:{}:{}",
                method.namespace, method.class, method.method_idx
            ),
            Node::Invoker(method, _, _) => format!(
                "invoker:{}:{}:{}",
                method.namespace, method.class, method.method_idx
            ),
        }
    }

    pub fn demangled(&self) -> String {
        match self {
            Node::Symbol(symbol) => symbol.demangled.to_string(),
            Node::Il2CppMethod(method) => format!(
                "{}.{}::{}",
                method.namespace, method.class, method.method_idx
            ),
            Node::Invoker(method, _, _) => format!(
                "Invoker for {}.{}::{}",
                method.namespace, method.class, method.method_idx
            ),
        }
    }
}

#[derive(Debug)]
pub enum RefType {
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

pub struct Ref {
    pub ty: RefType,
    pub num: usize,
    pub offset: u64,
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

pub type Graph<'obj> = DiGraph<Node<'obj>, Ref>;

pub struct GraphInfo<'obj> {
    pub graph: Graph<'obj>,
    pub name_map: HashMap<&'obj str, NodeIndex>,
    pub symbol_map: HashMap<u64, NodeIndex>,
}

pub fn gen_graph<'obj>(
    bin_data: &[u8],
    obj_file: &'obj Elf,
    ignore_sections: HashSet<String>,
    il2cpp_data: &'obj Option<Il2CppData>,
) -> Result<GraphInfo<'obj>> {
    let mut graph = Graph::new();
    let mut symbol_map = HashMap::new();
    let mut name_map = HashMap::new();

    let mut ignore_set_size = HashMap::new();
    if let Some(il2cpp_data) = il2cpp_data {
        for method in &il2cpp_data.methods {
            let n = graph.add_node(Node::Il2CppMethod(method));
            symbol_map.insert(method.addr, n);
        }

        for invoker in &il2cpp_data.invokers {
            let n = graph.add_node(Node::Invoker(
                &il2cpp_data.methods[invoker.method_idx],
                invoker.addr,
                0,
            ));
            ignore_set_size.insert(invoker.addr, n);
            symbol_map.insert(invoker.addr, n);
        }
    }

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
        if let Some(&n) = ignore_set_size.get(&symbol.address()) {
            match &mut graph[n] {
                Node::Invoker(_, _, size) => *size = symbol.size(),
                _ => bail!("cannot set size of this node"),
            }
            continue;
        }
        let demangled = if let Ok(demangle) = cpp_demangle::Symbol::new(symbol.name_bytes()?) {
            demangle.to_string()
        } else {
            symbol.name()?.to_string()
        };
        let n = graph.add_node(Node::Symbol(Symbol {
            addr: symbol.address(),
            size: symbol.size(),
            name: symbol.name()?,
            demangled,
            ty,
        }));
        symbol_map.insert(symbol.address(), n);
        name_map.insert(symbol.name()?, n);
    }

    for node_idx in graph.node_indices() {
        let n = &graph[node_idx];
        if !n.is_function() {
            continue;
        }

        let addr = n.addr();
        let code = &bin_data[addr as usize..(addr + n.size()) as usize];
        let decoded = disasm(code, addr);
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
                op @ (Op::LDR | Op::ADD) => {
                    let (reg, imm) = match op {
                        Op::LDR => match ins.operands()[1] {
                            Operand::MemOffset {
                                reg,
                                offset: Imm::Signed(imm),
                                ..
                            } => (reg, imm),
                            _ => continue,
                        },
                        Op::ADD => match ins.operands() {
                            &[_, Operand::Reg { reg, .. }, Operand::Imm64 {
                                imm: Imm::Unsigned(imm),
                                ..
                            }] => (reg, imm as i64),
                            _ => continue,
                        },
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
