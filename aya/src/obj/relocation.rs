use std::{collections::HashMap, mem};

use log::debug;
use object::{SectionIndex, SymbolKind};
use thiserror::Error;

use crate::{
    generated::{
        bpf_insn, BPF_CALL, BPF_JMP, BPF_K, BPF_PSEUDO_CALL, BPF_PSEUDO_FUNC, BPF_PSEUDO_MAP_FD,
        BPF_PSEUDO_MAP_VALUE,
    },
    maps::Map,
    obj::{Function, Object, Program},
    BpfError,
};

pub(crate) const INS_SIZE: usize = mem::size_of::<bpf_insn>();

#[derive(Debug, Error)]
enum RelocationError {
    #[error("unknown symbol, index `{index}`")]
    UnknownSymbol { index: usize },

    #[error("section `{section_index}` not found, referenced by symbol `{}` #{symbol_index}",
            .symbol_name.clone().unwrap_or_else(|| "".to_string()))]
    SectionNotFound {
        section_index: usize,
        symbol_index: usize,
        symbol_name: Option<String>,
    },

    #[error("function {address:#x} not found while relocating `{caller_name}`")]
    UnknownFunction { address: u64, caller_name: String },

    #[error("the map `{name}` at section `{section_index}` has not been created")]
    MapNotCreated { section_index: usize, name: String },

    #[error("invalid offset `{offset}` applying relocation #{relocation_number}")]
    InvalidRelocationOffset {
        offset: u64,
        relocation_number: usize,
    },
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct Relocation {
    // byte offset of the instruction to be relocated
    pub(crate) offset: u64,
    // index of the symbol to relocate to
    pub(crate) symbol_index: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct Symbol {
    pub(crate) index: usize,
    pub(crate) section_index: Option<usize>,
    pub(crate) name: Option<String>,
    pub(crate) address: u64,
    pub(crate) size: u64,
    pub(crate) is_definition: bool,
    pub(crate) kind: SymbolKind,
}

impl Object {
    pub fn relocate_maps<'a>(
        &'a mut self,
        maps: impl Iterator<Item = (&'a str, &'a Map)>,
    ) -> Result<(), BpfError> {
        let maps_by_section = maps
            .map(|(name, map)| (map.obj.section_index, (name, map)))
            .collect::<HashMap<_, _>>();

        let functions = self
            .programs
            .values_mut()
            .map(|p| &mut p.function)
            .chain(self.functions.values_mut());

        for function in functions {
            if let Some(relocations) = self.relocations.get(&function.section_index) {
                relocate_maps(
                    function,
                    relocations.values(),
                    &maps_by_section,
                    &self.symbols_by_index,
                    self.text_section_index,
                )
                .map_err(|error| BpfError::RelocationError {
                    function: function.name.clone(),
                    error: Box::new(error),
                })?;
            }
        }

        Ok(())
    }

    pub fn relocate_calls(&mut self) -> Result<(), BpfError> {
        for (name, program) in self.programs.iter_mut() {
            let linker = FunctionLinker::new(
                self.text_section_index,
                &self.functions,
                &self.relocations,
                &self.symbols_by_index,
            );
            linker
                .link(program)
                .map_err(|error| BpfError::RelocationError {
                    function: name.clone(),
                    error: Box::new(error),
                })?;
        }

        Ok(())
    }
}

fn relocate_maps<'a, I: Iterator<Item = &'a Relocation>>(
    fun: &mut Function,
    relocations: I,
    maps_by_section: &HashMap<usize, (&str, &Map)>,
    symbol_table: &HashMap<usize, Symbol>,
    text_section_index: Option<usize>,
) -> Result<(), RelocationError> {
    let section_offset = fun.section_offset;
    let instructions = &mut fun.instructions;
    let function_size = instructions.len() * INS_SIZE;

    for (rel_n, rel) in relocations.enumerate() {
        let rel_offset = rel.offset as usize;
        if rel_offset < section_offset || rel_offset >= section_offset + function_size {
            // the relocation doesn't apply to this function
            continue;
        }

        // make sure that the relocation offset is properly aligned
        let ins_offset = rel_offset - section_offset;
        if ins_offset % INS_SIZE != 0 {
            return Err(RelocationError::InvalidRelocationOffset {
                offset: rel.offset,
                relocation_number: rel_n,
            });
        }
        let ins_index = ins_offset / INS_SIZE;

        // a map relocation points to the ELF section that contains the map
        let sym = symbol_table
            .get(&rel.symbol_index)
            .ok_or(RelocationError::UnknownSymbol {
                index: rel.symbol_index,
            })?;

        let section_index = match sym.section_index {
            Some(index) => index,
            // this is not a map relocation
            None => continue,
        };

        // calls and relocation to .text symbols are handled in a separate step
        if insn_is_call(&instructions[ins_index]) || sym.section_index == text_section_index {
            continue;
        }

        let (name, map) =
            maps_by_section
                .get(&section_index)
                .ok_or(RelocationError::SectionNotFound {
                    symbol_index: rel.symbol_index,
                    symbol_name: sym.name.clone(),
                    section_index,
                })?;

        let map_fd = map.fd.ok_or_else(|| RelocationError::MapNotCreated {
            name: (*name).into(),
            section_index,
        })?;

        if !map.obj.data.is_empty() {
            instructions[ins_index].set_src_reg(BPF_PSEUDO_MAP_VALUE as u8);
            instructions[ins_index + 1].imm = instructions[ins_index].imm + sym.address as i32;
        } else {
            instructions[ins_index].set_src_reg(BPF_PSEUDO_MAP_FD as u8);
        }
        instructions[ins_index].imm = map_fd;
    }

    Ok(())
}

struct FunctionLinker<'a> {
    text_section_index: Option<usize>,
    functions: &'a HashMap<u64, Function>,
    linked_functions: HashMap<u64, usize>,
    relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
    symbol_table: &'a HashMap<usize, Symbol>,
}

impl<'a> FunctionLinker<'a> {
    fn new(
        text_section_index: Option<usize>,
        functions: &'a HashMap<u64, Function>,
        relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
        symbol_table: &'a HashMap<usize, Symbol>,
    ) -> FunctionLinker<'a> {
        FunctionLinker {
            text_section_index,
            functions,
            linked_functions: HashMap::new(),
            relocations,
            symbol_table,
        }
    }

    fn link(mut self, program: &mut Program) -> Result<(), RelocationError> {
        let mut fun = program.function.clone();
        // relocate calls in the program's main function. As relocation happens,
        // it will trigger linking in all the callees.
        self.relocate(&mut fun, &program.function)?;

        // this now includes the program function plus all the other functions called during
        // execution
        program.function = fun;

        Ok(())
    }

    fn link_function(
        &mut self,
        program: &mut Function,
        fun: &Function,
    ) -> Result<usize, RelocationError> {
        if let Some(fun_ins_index) = self.linked_functions.get(&fun.address) {
            return Ok(*fun_ins_index);
        };

        // append fun.instructions to the program and record that `fun.address` has been inserted
        // at `start_ins`. We'll use `start_ins` to do pc-relative calls.
        let start_ins = program.instructions.len();
        program.instructions.extend(&fun.instructions);

        // link func and line info into the main program
        // the offset needs to be adjusted
        self.link_func_and_line_info(program, fun, start_ins)?;

        self.linked_functions.insert(fun.address, start_ins);

        // relocate `fun`, recursively linking in all the callees
        self.relocate(program, fun)?;

        Ok(start_ins)
    }

    fn relocate(&mut self, program: &mut Function, fun: &Function) -> Result<(), RelocationError> {
        let relocations = self.relocations.get(&fun.section_index);

        debug!("relocating program {} function {}", program.name, fun.name);

        let n_instructions = fun.instructions.len();
        let start_ins = program.instructions.len() - n_instructions;

        // process all the instructions. We can't only loop over relocations since we need to
        // patch pc-relative calls too.
        for ins_index in start_ins..start_ins + n_instructions {
            let ins = program.instructions[ins_index];
            let is_call = insn_is_call(&ins);

            // only resolve relocations for calls or for instructions that
            // reference symbols in the .text section (eg let callback =
            // &some_fun)
            let rel = if let Some(relocations) = relocations {
                self.text_relocation_info(
                    relocations,
                    (fun.section_offset + (ins_index - start_ins) * INS_SIZE) as u64,
                )?
                // if not a call and not a .text reference, ignore the
                // relocation (see relocate_maps())
                .and_then(|(_, sym)| {
                    if is_call {
                        return Some(sym.address);
                    }

                    match sym.kind {
                        SymbolKind::Text => Some(sym.address),
                        SymbolKind::Section if sym.section_index == self.text_section_index => {
                            Some(sym.address + ins.imm as u64)
                        }
                        _ => None,
                    }
                })
            } else {
                None
            };

            // some_fun() or let x = &some_fun trigger linking, everything else
            // can be ignored here
            if !is_call && rel.is_none() {
                continue;
            }

            let callee_address = if let Some(address) = rel {
                // We have a relocation entry for the instruction at `ins_index`, the address of
                // the callee is the address of the relocation's target symbol.
                address
            } else {
                // The caller and the callee are in the same ELF section and this is a pc-relative
                // call. Resolve the pc-relative imm to an absolute address.
                let ins_size = INS_SIZE as i64;
                (fun.section_offset as i64
                    + ((ins_index - start_ins) as i64) * ins_size
                    + (ins.imm + 1) as i64 * ins_size) as u64
            };

            debug!(
                "relocating {} to callee address {} ({})",
                if is_call { "call" } else { "reference" },
                callee_address,
                if rel.is_some() {
                    "relocation"
                } else {
                    "relative"
                },
            );

            // lookup and link the callee if it hasn't been linked already. `callee_ins_index` will
            // contain the instruction index of the callee inside the program.
            let callee =
                self.functions
                    .get(&callee_address)
                    .ok_or(RelocationError::UnknownFunction {
                        address: callee_address,
                        caller_name: fun.name.clone(),
                    })?;

            debug!("callee is {}", callee.name);

            let callee_ins_index = self.link_function(program, callee)?;

            let mut ins = &mut program.instructions[ins_index];
            ins.imm = if callee_ins_index < ins_index {
                -((ins_index - callee_ins_index + 1) as i32)
            } else {
                (callee_ins_index - ins_index - 1) as i32
            };
            if !is_call {
                ins.set_src_reg(BPF_PSEUDO_FUNC as u8);
            }
        }

        debug!(
            "finished relocating program {} function {}",
            program.name, fun.name
        );

        Ok(())
    }

    fn link_func_and_line_info(
        &mut self,
        program: &mut Function,
        fun: &Function,
        start: usize,
    ) -> Result<(), RelocationError> {
        let off_adj = start - (fun.section_offset as usize / INS_SIZE);
        let func_info = &fun.func_info.func_info;
        let func_info = func_info.iter().map(|f| {
            let mut new = *f;
            new.insn_off = f.insn_off + off_adj as u32;
            new
        });
        program.func_info.func_info.extend(func_info);
        program.func_info.num_info = program.func_info.func_info.len() as u32;

        let line_info = &fun.line_info.line_info;
        let line_info = line_info.iter().map(|l| {
            let mut new = *l;
            new.insn_off = start as u32 + l.insn_off;
            new
        });
        program.line_info.line_info.extend(line_info);
        program.line_info.num_info = program.func_info.func_info.len() as u32;
        Ok(())
    }

    fn text_relocation_info(
        &self,
        relocations: &HashMap<u64, Relocation>,
        offset: u64,
    ) -> Result<Option<(Relocation, Symbol)>, RelocationError> {
        if let Some(rel) = relocations.get(&offset) {
            let sym =
                self.symbol_table
                    .get(&rel.symbol_index)
                    .ok_or(RelocationError::UnknownSymbol {
                        index: rel.symbol_index,
                    })?;

            Ok(Some((*rel, sym.clone())))
        } else {
            Ok(None)
        }
    }
}

fn insn_is_call(ins: &bpf_insn) -> bool {
    let klass = (ins.code & 0x07) as u32;
    let op = (ins.code & 0xF0) as u32;
    let src = (ins.code & 0x08) as u32;

    klass == BPF_JMP
        && op == BPF_CALL
        && src == BPF_K
        && ins.src_reg() as u32 == BPF_PSEUDO_CALL
        && ins.dst_reg() == 0
        && ins.off == 0
}
