use anyhow::{Context, Result};
use il2cpp_binary::{get_str, registrations, Elf};
use std::collections::HashMap;

pub struct Il2CppMethod<'a> {
    pub name: &'a str,
    pub class: &'a str,
    pub namespace: &'a str,
    pub addr: u64,
    pub size: u64,
}

pub struct Invoker {
    pub method_idx: usize,
    pub addr: u64,
}

pub struct Il2CppData<'a> {
    pub methods: Vec<Il2CppMethod<'a>>,
    pub invokers: Vec<Invoker>,
}

pub fn process<'a>(metadata_data: &'a [u8], elf: &Elf) -> Result<Il2CppData<'a>> {
    let mut methods = Vec::new();
    let metadata = il2cpp_metadata_raw::deserialize(metadata_data)?;
    let (code_registration, _) = registrations(elf, &metadata)?;

    let mut invoker_uses = HashMap::new();

    for image in &metadata.images {
        let name = get_str(metadata.string, image.name_index as usize)?;
        let module = code_registration
            .code_gen_modules
            .iter()
            .find(|m| m.name == name);
        let module = module
            .with_context(|| format!("count not find code registration module '{}'", name))?;
        for type_def in &metadata.type_definitions
            [image.type_start as usize..image.type_start as usize + image.type_count as usize]
        {
            let class = get_str(metadata.string, type_def.name_index as usize)?;
            let namespace = get_str(metadata.string, type_def.namespace_index as usize)?;
            let method_start = if type_def.method_count > 0 {
                type_def.method_start
            } else {
                0
            };
            for method in &metadata.methods
                [method_start as usize..method_start as usize + type_def.method_count as usize]
            {
                let rid = method.token & 0x00FFFFFF;
                let offset = module.method_pointers[rid as usize - 1];
                if offset == 0 {
                    continue;
                }

                let invoker_idx = module.invoker_indices[rid as usize - 1];
                if invoker_idx != u32::MAX {
                    invoker_uses.entry(invoker_idx).or_insert(methods.len());
                }

                let method_name = get_str(metadata.string, method.name_index as usize)?;
                methods.push(Il2CppMethod {
                    name: method_name,
                    class,
                    namespace,
                    addr: offset,
                    size: 0,
                });
            }
        }
    }

    methods.sort_by_key(|m| m.addr);

    // let section = elf.section_by_name("il2cpp").unwrap();
    // let section_end = section.address() + section.size();

    for i in 0..methods.len() - 1 {
        methods[i].size = methods[i + 1].addr - methods[i].addr;
    }
    // Just don't use the last one for now
    // let last = methods.last_mut().unwrap();
    // last.size = section_end - last.addr;

    let invokers = invoker_uses
        .iter()
        .map(|(&invoker_idx, &method_idx)| Invoker {
            method_idx,
            addr: code_registration.invoker_pointers[invoker_idx as usize],
        })
        .collect();

    Ok(Il2CppData { methods, invokers })
}
