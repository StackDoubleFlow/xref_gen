use anyhow::{Context, Result};
use brocolib::Metadata;
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

pub fn process<'a>(metadata: &'a Metadata<'a, 'a>) -> Result<Il2CppData<'a>> {
    let mut methods = Vec::new();

    let mut invoker_uses = HashMap::new();

    for image in metadata.global_metadata.images.as_vec() {
        let name = image.name(&metadata);
        let module = metadata
            .runtime_metadata
            .code_registration
            .code_gen_modules
            .iter()
            .find(|m| m.name == name);
        let module = module
            .with_context(|| format!("count not find code registration module '{}'", name))?;
        for type_def in image.types(&metadata) {
            let class = type_def.name(&metadata);
            let namespace = type_def.namespace(&metadata);
            for method in type_def.methods(&metadata) {
                let rid = method.token.rid();
                let offset = module.method_pointers[rid as usize - 1];
                if offset == 0 {
                    continue;
                }

                let invoker_idx = module.invoker_indices[rid as usize - 1];
                if invoker_idx != u32::MAX {
                    invoker_uses.entry(invoker_idx).or_insert(methods.len());
                }

                let method_name = method.name(&metadata);
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
            addr: metadata.runtime_metadata.code_registration.invoker_pointers
                [invoker_idx as usize],
        })
        .collect();

    Ok(Il2CppData { methods, invokers })
}
