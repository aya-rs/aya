//! Program relocation handling.

use core::mem;

use alloc::{borrow::ToOwned, string::String};
use log::debug;
use object::{SectionIndex, SymbolKind};

use crate::{
    generated::{
        bpf_insn, BPF_CALL, BPF_JMP, BPF_K, BPF_PSEUDO_CALL, BPF_PSEUDO_FUNC, BPF_PSEUDO_MAP_FD,
        BPF_PSEUDO_MAP_VALUE,
    },
    maps::Map,
    obj::{Function, Object, Program},
    util::{HashMap, HashSet},
    BpfSectionKind,
};

#[cfg(not(feature = "std"))]
use crate::std;

pub(crate) const INS_SIZE: usize = mem::size_of::<bpf_insn>();

/// The error type returned by [`Object::relocate_maps`] and [`Object::relocate_calls`]
#[derive(thiserror::Error, Debug)]
#[error("error relocating `{function}`")]
pub struct BpfRelocationError {
    /// The function name
    function: String,
    #[source]
    /// The original error
    error: RelocationError,
}

/// Relocation failures
#[derive(Debug, thiserror::Error)]
pub enum RelocationError {
    /// Unknown symbol
    #[error("unknown symbol, index `{index}`")]
    UnknownSymbol {
        /// The symbol index
        index: usize,
    },

    /// Section not found
    #[error("section `{section_index}` not found, referenced by symbol `{}` #{symbol_index}",
            .symbol_name.clone().unwrap_or_default())]
    SectionNotFound {
        /// The section index
        section_index: usize,
        /// The symbol index
        symbol_index: usize,
        /// The symbol name
        symbol_name: Option<String>,
    },

    /// Unknown function
    #[error("function {address:#x} not found while relocating `{caller_name}`")]
    UnknownFunction {
        /// The function address
        address: u64,
        /// The caller name
        caller_name: String,
    },

    /// Referenced map not created yet
    #[error("the map `{name}` at section `{section_index}` has not been created")]
    MapNotCreated {
        /// The section index
        section_index: usize,
        /// The map name
        name: String,
    },

    /// Invalid relocation offset
    #[error("invalid offset `{offset}` applying relocation #{relocation_number}")]
    InvalidRelocationOffset {
        /// The relocation offset
        offset: u64,
        /// The relocation number
        relocation_number: usize,
    },
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct Relocation {
    // byte offset of the instruction to be relocated
    pub(crate) offset: u64,
    pub(crate) size: u8,
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
    /// Relocates the map references
    pub fn relocate_maps<'a, I: Iterator<Item = (&'a str, Option<i32>, &'a Map)>>(
        &mut self,
        maps: I,
        text_sections: &HashSet<usize>,
    ) -> Result<(), BpfRelocationError> {
        let mut maps_by_section = HashMap::new();
        let mut maps_by_symbol = HashMap::new();
        for (name, fd, map) in maps {
            maps_by_section.insert(map.section_index(), (name, fd, map));
            if let Some(index) = map.symbol_index() {
                maps_by_symbol.insert(index, (name, fd, map));
            }
        }

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
                    &maps_by_symbol,
                    &self.symbol_table,
                    text_sections,
                )
                .map_err(|error| BpfRelocationError {
                    function: function.name.clone(),
                    error,
                })?;
            }
        }

        Ok(())
    }

    /// Relocates function calls
    pub fn relocate_calls(
        &mut self,
        text_sections: &HashSet<usize>,
    ) -> Result<(), BpfRelocationError> {
        for (name, program) in self.programs.iter_mut() {
            let linker = FunctionLinker::new(
                &self.functions,
                &self.relocations,
                &self.symbol_table,
                text_sections,
            );
            linker.link(program).map_err(|error| BpfRelocationError {
                function: name.to_owned(),
                error,
            })?;
        }

        Ok(())
    }
}

fn relocate_maps<'a, I: Iterator<Item = &'a Relocation>>(
    fun: &mut Function,
    relocations: I,
    maps_by_section: &HashMap<usize, (&str, Option<i32>, &Map)>,
    maps_by_symbol: &HashMap<usize, (&str, Option<i32>, &Map)>,
    symbol_table: &HashMap<usize, Symbol>,
    text_sections: &HashSet<usize>,
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

        let Some(section_index) = sym.section_index else {
            // this is not a map relocation
            continue;
        };

        // calls and relocation to .text symbols are handled in a separate step
        if insn_is_call(&instructions[ins_index]) || text_sections.contains(&section_index) {
            continue;
        }

        let (name, fd, map) = if let Some(m) = maps_by_symbol.get(&rel.symbol_index) {
            let map = &m.2;
            debug!(
                "relocating map by symbol index {:?}, kind {:?} at insn {ins_index} in section {}",
                map.symbol_index(),
                map.section_kind(),
                fun.section_index.0
            );
            debug_assert_eq!(map.symbol_index().unwrap(), rel.symbol_index);
            m
        } else {
            let Some(m) = maps_by_section.get(&section_index) else {
                debug!(
                    "failed relocating map by section index {}",
                    section_index
                );
                return Err(RelocationError::SectionNotFound {
                    symbol_index: rel.symbol_index,
                    symbol_name: sym.name.clone(),
                    section_index,
                });
            };
            let map = &m.2;
            debug!(
                "relocating map by section index {}, kind {:?} at insn {ins_index} in section {}",
                map.section_index(),
                map.section_kind(),
                fun.section_index.0,
            );

            debug_assert_eq!(map.symbol_index(), None);
            debug_assert!(matches!(
                map.section_kind(),
                BpfSectionKind::Bss | BpfSectionKind::Data | BpfSectionKind::Rodata
            ),);
            m
        };
        debug_assert_eq!(map.section_index(), section_index);

        let map_fd = fd.ok_or_else(|| RelocationError::MapNotCreated {
            name: (*name).into(),
            section_index,
        })?;

        if !map.data().is_empty() {
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
    functions: &'a HashMap<(usize, u64), Function>,
    linked_functions: HashMap<u64, usize>,
    relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
    symbol_table: &'a HashMap<usize, Symbol>,
    text_sections: &'a HashSet<usize>,
}

impl<'a> FunctionLinker<'a> {
    fn new(
        functions: &'a HashMap<(usize, u64), Function>,
        relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
        symbol_table: &'a HashMap<usize, Symbol>,
        text_sections: &'a HashSet<usize>,
    ) -> FunctionLinker<'a> {
        FunctionLinker {
            functions,
            linked_functions: HashMap::new(),
            relocations,
            symbol_table,
            text_sections,
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
        debug!(
            "linked function `{}` at instruction {}",
            fun.name, start_ins
        );

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

        let n_instructions = fun.instructions.len();
        let start_ins = program.instructions.len() - n_instructions;

        debug!(
            "relocating program `{}` function `{}` size {}",
            program.name, fun.name, n_instructions
        );

        // process all the instructions. We can't only loop over relocations since we need to
        // patch pc-relative calls too.
        for ins_index in start_ins..start_ins + n_instructions {
            let ins = program.instructions[ins_index];
            let is_call = insn_is_call(&ins);

            let rel = relocations
                .and_then(|relocations| {
                    relocations
                        .get(&((fun.section_offset + (ins_index - start_ins) * INS_SIZE) as u64))
                })
                .and_then(|rel| {
                    // get the symbol for the relocation
                    self.symbol_table
                        .get(&rel.symbol_index)
                        .map(|sym| (rel, sym))
                })
                .filter(|(_rel, sym)| {
                    // only consider text relocations, data relocations are
                    // relocated in relocate_maps()
                    sym.kind == SymbolKind::Text
                        || sym
                            .section_index
                            .map(|section_index| self.text_sections.contains(&section_index))
                            .unwrap_or(false)
                });

            // not a call and not a text relocation, we don't need to do anything
            if !is_call && rel.is_none() {
                continue;
            }

            let (callee_section_index, callee_address) = if let Some((rel, sym)) = rel {
                let address = match sym.kind {
                    SymbolKind::Text => sym.address,
                    // R_BPF_64_32 this is a call
                    SymbolKind::Section if rel.size == 32 => {
                        sym.address + (ins.imm + 1) as u64 * INS_SIZE as u64
                    }
                    // R_BPF_64_64 this is a ld_imm64 text relocation
                    SymbolKind::Section if rel.size == 64 => sym.address + ins.imm as u64,
                    _ => todo!(), // FIXME: return an error here,
                };
                (sym.section_index.unwrap(), address)
            } else {
                // The caller and the callee are in the same ELF section and this is a pc-relative
                // call. Resolve the pc-relative imm to an absolute address.
                let ins_size = INS_SIZE as i64;
                (
                    fun.section_index.0,
                    (fun.section_offset as i64
                        + ((ins_index - start_ins) as i64) * ins_size
                        + (ins.imm + 1) as i64 * ins_size) as u64,
                )
            };

            debug!(
                "relocating {} to callee address {:#x} in section {} ({}) at instruction {ins_index}",
                if is_call { "call" } else { "reference" },
                callee_address,
                callee_section_index,
                if rel.is_some() {
                    "relocation"
                } else {
                    "pc-relative"
                },
            );

            // lookup and link the callee if it hasn't been linked already. `callee_ins_index` will
            // contain the instruction index of the callee inside the program.
            let callee = self
                .functions
                .get(&(callee_section_index, callee_address))
                .ok_or(RelocationError::UnknownFunction {
                    address: callee_address,
                    caller_name: fun.name.clone(),
                })?;

            debug!("callee is `{}`", callee.name);

            let callee_ins_index = self.link_function(program, callee)? as i32;

            let mut ins = &mut program.instructions[ins_index];
            let ins_index = ins_index as i32;
            ins.imm = callee_ins_index - ins_index - 1;
            debug!(
                "callee `{}` is at ins {callee_ins_index}, {} from current instruction {ins_index}",
                callee.name, ins.imm
            );
            if !is_call {
                ins.set_src_reg(BPF_PSEUDO_FUNC as u8);
            }
        }

        debug!(
            "finished relocating program `{}` function `{}`",
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
        let func_info = &fun.func_info.func_info;
        let func_info = func_info.iter().cloned().map(|mut info| {
            // `start` is the new instruction offset of `fun` within `program`
            info.insn_off = start as u32;
            info
        });
        program.func_info.func_info.extend(func_info);
        program.func_info.num_info = program.func_info.func_info.len() as u32;

        let line_info = &fun.line_info.line_info;
        if !line_info.is_empty() {
            // this is the original offset
            let original_start_off = line_info[0].insn_off;

            let line_info = line_info.iter().cloned().map(|mut info| {
                // rebase offsets on top of start, which is the offset of the
                // function in the program being linked
                info.insn_off = start as u32 + (info.insn_off - original_start_off);
                info
            });

            program.line_info.line_info.extend(line_info);
            program.line_info.num_info = program.func_info.func_info.len() as u32;
        }
        Ok(())
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

#[cfg(test)]
mod test {
    use alloc::{string::ToString, vec, vec::Vec};

    use crate::{
        maps::{BtfMap, LegacyMap, Map},
        BpfSectionKind,
    };

    use super::*;

    fn fake_sym(index: usize, section_index: usize, address: u64, name: &str, size: u64) -> Symbol {
        Symbol {
            index,
            section_index: Some(section_index),
            name: Some(name.to_string()),
            address,
            size,
            is_definition: false,
            kind: SymbolKind::Data,
        }
    }

    fn ins(bytes: &[u8]) -> bpf_insn {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) }
    }

    fn fake_legacy_map(symbol_index: usize) -> Map {
        Map::Legacy(LegacyMap {
            def: Default::default(),
            section_index: 0,
            section_kind: BpfSectionKind::Undefined,
            symbol_index: Some(symbol_index),
            data: Vec::new(),
        })
    }

    fn fake_btf_map(symbol_index: usize) -> Map {
        Map::Btf(BtfMap {
            def: Default::default(),
            section_index: 0,
            symbol_index,
            data: Vec::new(),
        })
    }

    fn fake_func(name: &str, instructions: Vec<bpf_insn>) -> Function {
        Function {
            address: Default::default(),
            name: name.to_string(),
            section_index: SectionIndex(0),
            section_offset: Default::default(),
            instructions,
            func_info: Default::default(),
            line_info: Default::default(),
            func_info_rec_size: Default::default(),
            line_info_rec_size: Default::default(),
        }
    }

    #[test]
    fn test_single_legacy_map_relocation() {
        let mut fun = fake_func(
            "test",
            vec![ins(&[
                0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ])],
        );

        let symbol_table = HashMap::from([(1, fake_sym(1, 0, 0, "test_map", 0))]);

        let relocations = vec![Relocation {
            offset: 0x0,
            symbol_index: 1,
            size: 64,
        }];
        let maps_by_section = HashMap::new();

        let map = fake_legacy_map(1);
        let maps_by_symbol = HashMap::from([(1, ("test_map", Some(1), &map))]);

        relocate_maps(
            &mut fun,
            relocations.iter(),
            &maps_by_section,
            &maps_by_symbol,
            &symbol_table,
            &HashSet::new(),
        )
        .unwrap();

        assert_eq!(fun.instructions[0].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[0].imm, 1);

        mem::forget(map);
    }

    #[test]
    fn test_multiple_legacy_map_relocation() {
        let mut fun = fake_func(
            "test",
            vec![
                ins(&[
                    0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
                ins(&[
                    0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
            ],
        );

        let symbol_table = HashMap::from([
            (1, fake_sym(1, 0, 0, "test_map_1", 0)),
            (2, fake_sym(2, 0, 0, "test_map_2", 0)),
        ]);

        let relocations = vec![
            Relocation {
                offset: 0x0,
                symbol_index: 1,
                size: 64,
            },
            Relocation {
                offset: mem::size_of::<bpf_insn>() as u64,
                symbol_index: 2,
                size: 64,
            },
        ];
        let maps_by_section = HashMap::new();

        let map_1 = fake_legacy_map(1);
        let map_2 = fake_legacy_map(2);
        let maps_by_symbol = HashMap::from([
            (1, ("test_map_1", Some(1), &map_1)),
            (2, ("test_map_2", Some(2), &map_2)),
        ]);

        relocate_maps(
            &mut fun,
            relocations.iter(),
            &maps_by_section,
            &maps_by_symbol,
            &symbol_table,
            &HashSet::new(),
        )
        .unwrap();

        assert_eq!(fun.instructions[0].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[0].imm, 1);

        assert_eq!(fun.instructions[1].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[1].imm, 2);

        mem::forget(map_1);
        mem::forget(map_2);
    }

    #[test]
    fn test_single_btf_map_relocation() {
        let mut fun = fake_func(
            "test",
            vec![ins(&[
                0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ])],
        );

        let symbol_table = HashMap::from([(1, fake_sym(1, 0, 0, "test_map", 0))]);

        let relocations = vec![Relocation {
            offset: 0x0,
            symbol_index: 1,
            size: 64,
        }];
        let maps_by_section = HashMap::new();

        let map = fake_btf_map(1);
        let maps_by_symbol = HashMap::from([(1, ("test_map", Some(1), &map))]);

        relocate_maps(
            &mut fun,
            relocations.iter(),
            &maps_by_section,
            &maps_by_symbol,
            &symbol_table,
            &HashSet::new(),
        )
        .unwrap();

        assert_eq!(fun.instructions[0].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[0].imm, 1);

        mem::forget(map);
    }

    #[test]
    fn test_multiple_btf_map_relocation() {
        let mut fun = fake_func(
            "test",
            vec![
                ins(&[
                    0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
                ins(&[
                    0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
            ],
        );

        let symbol_table = HashMap::from([
            (1, fake_sym(1, 0, 0, "test_map_1", 0)),
            (2, fake_sym(2, 0, 0, "test_map_2", 0)),
        ]);

        let relocations = vec![
            Relocation {
                offset: 0x0,
                symbol_index: 1,
                size: 64,
            },
            Relocation {
                offset: mem::size_of::<bpf_insn>() as u64,
                symbol_index: 2,
                size: 64,
            },
        ];
        let maps_by_section = HashMap::new();

        let map_1 = fake_btf_map(1);
        let map_2 = fake_btf_map(2);
        let maps_by_symbol = HashMap::from([
            (1, ("test_map_1", Some(1), &map_1)),
            (2, ("test_map_2", Some(2), &map_2)),
        ]);

        relocate_maps(
            &mut fun,
            relocations.iter(),
            &maps_by_section,
            &maps_by_symbol,
            &symbol_table,
            &HashSet::new(),
        )
        .unwrap();

        assert_eq!(fun.instructions[0].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[0].imm, 1);

        assert_eq!(fun.instructions[1].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[1].imm, 2);

        mem::forget(map_1);
        mem::forget(map_2);
    }
}
