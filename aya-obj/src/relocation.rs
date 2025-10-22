//! Program relocation handling.

use alloc::{borrow::ToOwned as _, collections::BTreeMap, string::String};

use log::debug;
use object::{SectionIndex, SymbolKind};

use crate::{
    EbpfSectionKind,
    extern_types::ExternDesc,
    generated::{
        BPF_CALL, BPF_JMP, BPF_K, BPF_PSEUDO_CALL, BPF_PSEUDO_FUNC, BPF_PSEUDO_MAP_FD,
        BPF_PSEUDO_MAP_VALUE, bpf_insn,
    },
    maps::Map,
    obj::{Function, Object},
    util::{HashMap, HashSet},
};

#[cfg(feature = "std")]
type RawFd = std::os::fd::RawFd;
#[cfg(not(feature = "std"))]
type RawFd = core::ffi::c_int;

pub(crate) const INS_SIZE: usize = size_of::<bpf_insn>();
pub(crate) const BPF_PSEUDO_KFUNC_CALL: u32 = 2;
pub(crate) const BPF_PSEUDO_BTF_ID: u32 = 3;

/// The error type returned by [`Object::relocate_maps`] and [`Object::relocate_calls`]
#[derive(thiserror::Error, Debug)]
#[error("error relocating `{function}`")]
pub struct EbpfRelocationError {
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

    /// Unknown function
    #[error(
        "program at section {section_index} and address {address:#x} was not found while relocating"
    )]
    UnknownProgram {
        /// The function section index
        section_index: usize,
        /// The function address
        address: u64,
    },

    /// Invalid relocation offset
    #[error("invalid offset `{offset}` applying relocation #{relocation_number}")]
    InvalidRelocationOffset {
        /// The relocation offset
        offset: u64,
        /// The relocation number
        relocation_number: usize,
    },
    /// Extern not found
    #[error("extern `{name}` not found")]
    ExternNotFound {
        /// Name of the extern symbol
        name: String,
    },

    /// Unresolved extern
    #[error("extern `{name}` was not resolved against kernel BTF")]
    UnresolvedExtern {
        /// Name of the extern symbol
        name: String,
    },

    /// Missing kernel BTF ID
    #[error("extern `{name}` is missing kernel BTF ID")]
    MissingKallsymsAddr {
        /// Name of the extern symbol
        name: String,
    },

    /// Strong symbol not found anywhere (neither BTF nor kallsyms)
    #[error("strong extern `{name}` not resolvable (not in kernel BTF or kallsyms)")]
    UnresolvableSymbol {
        /// Name of the extern symbol
        name: String,
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
    pub(crate) is_weak: bool,
}

impl Symbol {
    /// Returns true if this symbol is an extern (undefined) symbol
    pub(crate) fn is_extern(&self) -> bool {
        self.section_index.is_none()
            && self.name.is_some()
            && !self.is_definition
            && self.kind == SymbolKind::Unknown
    }
}

impl Object {
    /// Relocates the map references
    pub fn relocate_maps<'a, I: Iterator<Item = (&'a str, RawFd, &'a Map)>>(
        &mut self,
        maps: I,
        text_sections: &HashSet<usize>,
    ) -> Result<(), EbpfRelocationError> {
        let mut maps_by_section = HashMap::new();
        let mut maps_by_symbol = HashMap::new();
        for (name, fd, map) in maps {
            maps_by_section.insert(map.section_index(), (name, fd, map));
            if let Some(index) = map.symbol_index() {
                maps_by_symbol.insert(index, (name, fd, map));
            }
        }

        for function in self.functions.values_mut() {
            if let Some(relocations) = self.relocations.get(&function.section_index) {
                relocate_maps(
                    function,
                    relocations.values(),
                    &maps_by_section,
                    &maps_by_symbol,
                    &self.symbol_table,
                    text_sections,
                )
                .map_err(|error| EbpfRelocationError {
                    function: function.name.clone(),
                    error,
                })?;
            }
        }

        Ok(())
    }

    /// Relocates extern ksym references after BTF resolution
    pub fn relocate_externs(&mut self) -> Result<(), EbpfRelocationError> {
        if let Some(obj_btf) = self.btf.as_mut() {
            for (name, extern_desc) in &obj_btf.externs.externs {
                debug!(
                    "[DEBUG] Extern '{}': resolved={}, btf_id={:?}",
                    name, extern_desc.is_resolved, extern_desc.kernel_btf_id
                );
            }

            for function in self.functions.values_mut() {
                if let Some(relocations) = self.relocations.get(&function.section_index) {
                    relocate_externs(
                        function,
                        relocations.values(),
                        &obj_btf.externs.externs,
                        &self.symbol_table,
                    )
                    .map_err(|error| EbpfRelocationError {
                        function: function.name.clone(),
                        error,
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Relocates function calls
    pub fn relocate_calls(
        &mut self,
        text_sections: &HashSet<usize>,
    ) -> Result<(), EbpfRelocationError> {
        for (name, program) in &self.programs {
            let linker = FunctionLinker::new(
                &self.functions,
                &self.relocations,
                &self.symbol_table,
                text_sections,
            );

            let func_orig =
                self.functions
                    .get(&program.function_key())
                    .ok_or_else(|| EbpfRelocationError {
                        function: name.clone(),
                        error: RelocationError::UnknownProgram {
                            section_index: program.section_index,
                            address: program.address,
                        },
                    })?;

            let func = linker
                .link(func_orig)
                .map_err(|error| EbpfRelocationError {
                    function: name.to_owned(),
                    error,
                })?;

            self.functions.insert(program.function_key(), func);
        }

        Ok(())
    }
}

fn relocate_externs<'a, I: Iterator<Item = &'a Relocation>>(
    fun: &mut Function,
    relocations: I,
    externs: &HashMap<String, ExternDesc>,
    symbol_table: &HashMap<usize, Symbol>,
) -> Result<(), RelocationError> {
    let section_offset = fun.section_offset;
    let instructions = &mut fun.instructions;
    let function_size = instructions.len() * INS_SIZE;

    for (rel_n, rel) in relocations.enumerate() {
        let rel_offset = rel.offset as usize;
        if rel_offset < section_offset || rel_offset >= section_offset + function_size {
            continue;
        }

        let ins_offset = rel_offset - section_offset;
        if !ins_offset.is_multiple_of(INS_SIZE) {
            return Err(RelocationError::InvalidRelocationOffset {
                offset: rel.offset,
                relocation_number: rel_n,
            });
        }
        let ins_index = ins_offset / INS_SIZE;

        let sym = symbol_table
            .get(&rel.symbol_index)
            .ok_or(RelocationError::UnknownSymbol {
                index: rel.symbol_index,
            })?;

        // Only process extern symbols
        if !sym.is_extern() {
            continue;
        }

        let extern_name = sym.name.as_ref().unwrap();
        let extern_desc =
            externs
                .get(extern_name)
                .ok_or_else(|| RelocationError::ExternNotFound {
                    name: extern_name.clone(),
                })?;

        let ins = &mut instructions[ins_index];
        let is_call = insn_is_call(*ins);

        if is_call {
            ins.set_src_reg(BPF_PSEUDO_KFUNC_CALL as u8);
            if extern_desc.is_resolved {
                let kernel_btf_id = extern_desc.kernel_btf_id.unwrap();
                ins.imm = kernel_btf_id as i32;
                ins.off = 0; // btf_fd_idx, typically 0 for vmlinux
            } else {
                // Unresolved weak kfunc call
                poison_kfunc_call(ins, rel.symbol_index);
            }
        } else {
            // Consistent Variable Reference Resolution
            match (extern_desc.kernel_btf_id, extern_desc.ksym_addr) {
                // SUCCESS: Symbol found in Kernel BTF
                (Some(btf_id), _) => {
                    ins.set_src_reg(BPF_PSEUDO_BTF_ID as u8);
                    ins.imm = btf_id as i32;
                    instructions[ins_index + 1].imm = 0; // vmlinux
                }
                // SUCCESS: Fallback to Kallsyms (BTF missing but address found)
                (None, Some(addr)) => {
                    ins.set_src_reg(0); // Standard 64-bit absolute load
                    ins.imm = (addr & 0xFFFFFFFF) as i32;
                    instructions[ins_index + 1].imm = (addr >> 32) as i32;
                }
                // SUCCESS: Weak symbol not found (Null-patch)
                (None, None) if extern_desc.is_weak => {
                    ins.set_src_reg(0);
                    ins.imm = 0;
                    instructions[ins_index + 1].imm = 0;
                }
                // FAILURE: Strong symbol not found anywhere
                _ => {
                    return Err(RelocationError::UnresolvableSymbol {
                        name: extern_name.clone(),
                    });
                }
            }
        }
    }

    Ok(())
}

const POISON_CALL_KFUNC_BASE: i32 = 2002000000;

fn poison_kfunc_call(ins: &mut bpf_insn, ext_idx: usize) {
    ins.code = (BPF_JMP | BPF_CALL) as u8;
    ins.set_dst_reg(0);
    ins.set_src_reg(0);
    ins.off = 0;
    ins.imm = POISON_CALL_KFUNC_BASE + ext_idx as i32;
}

fn relocate_maps<'a, I: Iterator<Item = &'a Relocation>>(
    fun: &mut Function,
    relocations: I,
    maps_by_section: &HashMap<usize, (&str, RawFd, &Map)>,
    maps_by_symbol: &HashMap<usize, (&str, RawFd, &Map)>,
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
        if !ins_offset.is_multiple_of(INS_SIZE) {
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
        if insn_is_call(instructions[ins_index]) || text_sections.contains(&section_index) {
            continue;
        }

        let (_name, fd, map) = if let Some(m) = maps_by_symbol.get(&rel.symbol_index) {
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
                debug!("failed relocating map by section index {section_index}");
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
                EbpfSectionKind::Bss | EbpfSectionKind::Data | EbpfSectionKind::Rodata
            ));
            m
        };
        debug_assert_eq!(map.section_index(), section_index);

        if map.data().is_empty() {
            instructions[ins_index].set_src_reg(BPF_PSEUDO_MAP_FD as u8);
        } else {
            instructions[ins_index].set_src_reg(BPF_PSEUDO_MAP_VALUE as u8);
            instructions[ins_index + 1].imm = instructions[ins_index].imm + sym.address as i32;
        }
        instructions[ins_index].imm = *fd;
    }

    Ok(())
}

struct FunctionLinker<'a> {
    functions: &'a BTreeMap<(usize, u64), Function>,
    linked_functions: HashMap<u64, usize>,
    relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
    symbol_table: &'a HashMap<usize, Symbol>,
    text_sections: &'a HashSet<usize>,
}

impl<'a> FunctionLinker<'a> {
    fn new(
        functions: &'a BTreeMap<(usize, u64), Function>,
        relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
        symbol_table: &'a HashMap<usize, Symbol>,
        text_sections: &'a HashSet<usize>,
    ) -> Self {
        Self {
            functions,
            linked_functions: HashMap::new(),
            relocations,
            symbol_table,
            text_sections,
        }
    }

    fn link(mut self, program_function: &Function) -> Result<Function, RelocationError> {
        let mut fun = program_function.clone();
        // relocate calls in the program's main function. As relocation happens,
        // it will trigger linking in all the callees.
        self.relocate(&mut fun, program_function)?;

        // this now includes the program function plus all the other functions called during
        // execution
        Ok(fun)
    }

    fn link_function(
        &mut self,
        program: &mut Function,
        fun: &Function,
    ) -> Result<usize, RelocationError> {
        if let Some(fun_ins_index) = self.linked_functions.get(&fun.address) {
            return Ok(*fun_ins_index);
        }

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
        Self::link_func_and_line_info(program, fun, start_ins);

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
            let is_call = insn_is_call(ins);

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
                    if sym.is_extern() {
                        return false;
                    }
                    sym.kind == SymbolKind::Text
                        || sym.section_index.is_some_and(|section_index| {
                            self.text_sections.contains(&section_index)
                        })
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
                    #[expect(clippy::todo, reason = "TODO")]
                    kind => todo!("FIXME: return an error here for kind={kind:?}"),
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
                        + i64::from(ins.imm + 1) * ins_size) as u64,
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
                .ok_or_else(|| RelocationError::UnknownFunction {
                    address: callee_address,
                    caller_name: fun.name.clone(),
                })?;

            debug!("callee is `{}`", callee.name);

            let callee_ins_index = self.link_function(program, callee)? as i32;

            let ins = &mut program.instructions[ins_index];
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

    fn link_func_and_line_info(program: &mut Function, fun: &Function, start: usize) {
        let func_info = &fun.func_info.func_info;
        let func_info = func_info.iter().copied().map(|mut info| {
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

            let line_info = line_info.iter().copied().map(|mut info| {
                // rebase offsets on top of start, which is the offset of the
                // function in the program being linked
                info.insn_off = start as u32 + (info.insn_off - original_start_off);
                info
            });

            program.line_info.line_info.extend(line_info);
            program.line_info.num_info = program.func_info.func_info.len() as u32;
        }
    }
}

fn insn_is_call(ins: bpf_insn) -> bool {
    let klass = u32::from(ins.code & 0x07);
    let op = u32::from(ins.code & 0xF0);
    let src = u32::from(ins.code & 0x08);

    klass == BPF_JMP
        && op == BPF_CALL
        && src == BPF_K
        && u32::from(ins.src_reg()) == BPF_PSEUDO_CALL
        && ins.dst_reg() == 0
        && ins.off == 0
}

#[cfg(test)]
mod test {
    use alloc::{string::ToString as _, vec, vec::Vec};

    use super::*;
    use crate::maps::{BtfMap, LegacyMap};

    fn fake_sym(index: usize, section_index: usize, address: u64, name: &str, size: u64) -> Symbol {
        Symbol {
            index,
            section_index: Some(section_index),
            name: Some(name.to_string()),
            address,
            size,
            is_definition: false,
            kind: SymbolKind::Data,
            is_weak: false,
        }
    }

    fn ins(bytes: &[u8]) -> bpf_insn {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) }
    }

    fn fake_legacy_map(symbol_index: usize) -> Map {
        Map::Legacy(LegacyMap {
            def: Default::default(),
            section_index: 0,
            section_kind: EbpfSectionKind::Undefined,
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

        let relocations = [Relocation {
            offset: 0x0,
            symbol_index: 1,
            size: 64,
        }];
        let maps_by_section = HashMap::new();

        let map = fake_legacy_map(1);
        let maps_by_symbol = HashMap::from([(1, ("test_map", 1, &map))]);

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

        let relocations = [
            Relocation {
                offset: 0x0,
                symbol_index: 1,
                size: 64,
            },
            Relocation {
                offset: size_of::<bpf_insn>() as u64,
                symbol_index: 2,
                size: 64,
            },
        ];
        let maps_by_section = HashMap::new();

        let map_1 = fake_legacy_map(1);
        let map_2 = fake_legacy_map(2);
        let maps_by_symbol = HashMap::from([
            (1, ("test_map_1", 1, &map_1)),
            (2, ("test_map_2", 2, &map_2)),
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

        let relocations = [Relocation {
            offset: 0x0,
            symbol_index: 1,
            size: 64,
        }];
        let maps_by_section = HashMap::new();

        let map = fake_btf_map(1);
        let maps_by_symbol = HashMap::from([(1, ("test_map", 1, &map))]);

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

        let relocations = [
            Relocation {
                offset: 0x0,
                symbol_index: 1,
                size: 64,
            },
            Relocation {
                offset: size_of::<bpf_insn>() as u64,
                symbol_index: 2,
                size: 64,
            },
        ];
        let maps_by_section = HashMap::new();

        let map_1 = fake_btf_map(1);
        let map_2 = fake_btf_map(2);
        let maps_by_symbol = HashMap::from([
            (1, ("test_map_1", 1, &map_1)),
            (2, ("test_map_2", 2, &map_2)),
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
    }
}
