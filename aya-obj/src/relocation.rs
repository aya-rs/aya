//! Program relocation handling.

use std::{
    borrow::ToOwned as _,
    collections::{BTreeMap, hash_map::Entry},
};

use log::debug;
use object::{Endian as _, Endianness, SectionIndex, SymbolKind};

use crate::{
    EbpfSectionKind,
    extern_types::ExternDesc,
    generated::{
        BPF_CALL, BPF_DW, BPF_IMM, BPF_JMP, BPF_K, BPF_LD, BPF_PSEUDO_BTF_ID, BPF_PSEUDO_CALL,
        BPF_PSEUDO_FUNC, BPF_PSEUDO_KFUNC_CALL, BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE, bpf_insn,
    },
    maps::Map,
    obj::{Function, JumpTable, JumpTablesSection, Object},
    util::{HashMap, HashSet},
};

type RawFd = std::os::fd::RawFd;

pub(crate) const INS_SIZE: usize = size_of::<bpf_insn>();

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

    /// BTF function info mismatch
    #[error("BTF function info for `{name}` does not match the program")]
    FunctionInfoMismatch {
        /// The function name
        name: String,
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

    /// Extern not found.
    #[error("extern `{name}` not found")]
    ExternNotFound {
        /// Name of the extern symbol.
        name: String,
    },

    /// Strong symbol not found anywhere (neither BTF nor kallsyms).
    #[error("strong extern `{name}` not resolvable (not in kernel BTF or kallsyms)")]
    UnresolvableSymbol {
        /// Name of the extern symbol
        name: String,
    },

    /// Invalid jump table
    #[error("invalid jump table `{}`: {reason}", .symbol_name.clone().unwrap_or_default())]
    InvalidJumpTable {
        /// The symbol name
        symbol_name: Option<String>,
        /// Why the table is invalid
        reason: String,
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

        let jump_tables_section = self.jump_tables.as_ref().map(|s| s.section_index);
        for function in self.functions.values_mut() {
            if let Some(relocations) = self.relocations.get(&function.section_index) {
                relocate_maps(
                    function,
                    relocations.values(),
                    &maps_by_section,
                    &maps_by_symbol,
                    &self.symbol_table,
                    text_sections,
                    jump_tables_section,
                )
                .map_err(|error| EbpfRelocationError {
                    function: function.name.clone(),
                    error,
                })?;
            }
        }

        Ok(())
    }

    /// Relocates extern kernel symbol references after they have been resolved.
    pub fn relocate_externs(&mut self) -> Result<(), EbpfRelocationError> {
        let Some(obj_btf) = self.btf.as_mut() else {
            return Ok(());
        };

        for (name, extern_desc) in obj_btf.externs.iter() {
            debug!(
                "extern '{}': resolved={}, btf_id={:?}",
                name, extern_desc.is_resolved, extern_desc.kernel_btf_id
            );
        }

        for function in self.functions.values_mut() {
            if let Some(relocations) = self.relocations.get(&function.section_index) {
                patch_extern_relocations(
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
                self.jump_tables.as_ref(),
                self.endianness,
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

fn patch_extern_relocations<'a, I: Iterator<Item = &'a Relocation>>(
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

        let extern_name = sym.name.as_ref().expect("extern symbol must have a name");
        let extern_desc =
            externs
                .get(extern_name)
                .ok_or_else(|| RelocationError::ExternNotFound {
                    name: extern_name.clone(),
                })?;

        let ins = &mut instructions[ins_index];
        // Extern relocations use CALL opcode to identify kfunc-call sites.
        // `insn_is_call()` is for internal pseudo-calls.
        let is_call = ins.code == (BPF_JMP | BPF_CALL) as u8;

        // We can't borrow two instructions mutably at once. Start from
        // modifying the first one, and carry the override of `imm` for the
        // next instruction if necessary.
        let ins_next_imm = if is_call {
            ins.set_src_reg(BPF_PSEUDO_KFUNC_CALL as u8);
            if extern_desc.is_resolved {
                let kernel_btf_id = extern_desc
                    .kernel_btf_id
                    .expect("resolved extern must have kernel_btf_id");
                ins.imm = kernel_btf_id as i32;
                ins.off = 0; // btf_fd_idx, typically 0 for vmlinux
            } else if extern_desc.is_weak {
                // Unresolved weak kfunc call
                poison_kfunc_call(ins, rel.symbol_index);
            } else {
                return Err(RelocationError::UnresolvableSymbol {
                    name: extern_name.clone(),
                });
            }
            None
        } else {
            if ins.code != (BPF_LD | BPF_DW | BPF_IMM) as u8 {
                return Err(RelocationError::InvalidRelocationOffset {
                    offset: rel.offset,
                    relocation_number: rel_n,
                });
            }

            Some(match (extern_desc.kernel_btf_id, extern_desc.ksym_addr) {
                // symbol found in kernel BTF
                (Some(btf_id), _) => {
                    ins.set_src_reg(BPF_PSEUDO_BTF_ID as u8);
                    ins.imm = btf_id as i32;
                    0 // vmlinux
                }
                // fallback to kallsyms (BTF missing but address found)
                (None, Some(addr)) => {
                    ins.set_src_reg(0); // Standard 64-bit absolute load
                    ins.imm = (addr & 0xFFFFFFFF) as i32;
                    (addr >> 32) as i32
                }
                // weak symbol not found, null-patch
                (None, None) if extern_desc.is_weak => {
                    ins.set_src_reg(0);
                    ins.imm = 0;
                    0
                }
                // strong symbol not found anywhere
                _ => {
                    return Err(RelocationError::UnresolvableSymbol {
                        name: extern_name.clone(),
                    });
                }
            })
        };
        if let Some(ins_next_imm) = ins_next_imm {
            // Non-call extern relocations should always target an ld_imm64 (LDDW),
            // which occupies two instructions. Guard against malformed relocations.
            let ins_next = instructions.get_mut(ins_index + 1).ok_or(
                RelocationError::InvalidRelocationOffset {
                    offset: rel.offset,
                    relocation_number: rel_n,
                },
            )?;
            ins_next.imm = ins_next_imm;
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
    ins.imm = POISON_CALL_KFUNC_BASE.wrapping_add(ext_idx as i32);
}

fn relocate_maps<'a, I: Iterator<Item = &'a Relocation>>(
    fun: &mut Function,
    relocations: I,
    maps_by_section: &HashMap<usize, (&str, RawFd, &Map)>,
    maps_by_symbol: &HashMap<usize, (&str, RawFd, &Map)>,
    symbol_table: &HashMap<usize, Symbol>,
    text_sections: &HashSet<usize>,
    jump_tables_section: Option<usize>,
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

        // jump tables are resolved by the linker, see `FunctionLinker::relocate_jump_tables`
        if Some(section_index) == jump_tables_section {
            continue;
        }

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

/// Translates the entries of the jump table `sym` in `data` (the `.jumptables` section) into
/// instruction indices of the program that `fun` has been linked into at `start_ins`.
///
/// Entries are `u64` byte offsets relative to the start of the ELF section containing `fun`.
fn jump_table_targets(
    data: &[u8],
    sym: &Symbol,
    fun: &Function,
    start_ins: usize,
    endianness: Endianness,
) -> Result<Vec<u32>, RelocationError> {
    const ENTRY_SIZE: usize = size_of::<u64>();

    let invalid = |reason: String| RelocationError::InvalidJumpTable {
        symbol_name: sym.name.clone(),
        reason,
    };
    let does_not_fit = |what: &'static str, value: u64| {
        move |std::num::TryFromIntError { .. }| {
            invalid(format!("{what} {value:#x} does not fit in usize"))
        }
    };

    // The symbol spans the table within the section. Its value and size come straight from the ELF
    // file, so every step of the arithmetic is checked.
    let sym_offset = usize::try_from(sym.address).map_err(does_not_fit("offset", sym.address))?;
    let sym_size = usize::try_from(sym.size).map_err(does_not_fit("size", sym.size))?;
    if !sym_offset.is_multiple_of(ENTRY_SIZE) || !sym_size.is_multiple_of(ENTRY_SIZE) {
        return Err(invalid(format!(
            "offset {sym_offset} and size {sym_size} must be multiples of {ENTRY_SIZE}"
        )));
    }
    let sym_end = sym_offset
        .checked_add(sym_size)
        .ok_or_else(|| invalid(format!("offset {sym_offset} and size {sym_size} overflow")))?;
    let entries = data.get(sym_offset..sym_end).ok_or_else(|| {
        invalid(format!(
            "offset {sym_offset} and size {sym_size} exceed the section size {}",
            data.len()
        ))
    })?;
    // The remainder is empty: the size is a multiple of ENTRY_SIZE.
    let (entries, _) = entries.as_chunks::<ENTRY_SIZE>();

    let function_start = fun.section_offset / INS_SIZE;
    entries
        .iter()
        .map(|entry| {
            let entry = endianness.read_u64(*entry);
            let offset = usize::try_from(entry).map_err(does_not_fit("entry", entry))?;
            if !offset.is_multiple_of(INS_SIZE) {
                return Err(invalid(format!(
                    "entry {entry:#x} is not instruction aligned"
                )));
            }
            let Some(target) = (offset / INS_SIZE).checked_sub(function_start) else {
                return Err(invalid(format!(
                    "entry {entry:#x} precedes function `{}`",
                    fun.name
                )));
            };
            if target >= fun.instructions.len() {
                return Err(invalid(format!(
                    "entry {entry:#x} is past the end of function `{}`",
                    fun.name
                )));
            }
            u32::try_from(start_ins + target).map_err(|std::num::TryFromIntError { .. }| {
                invalid(format!("entry {entry:#x} does not fit in u32"))
            })
        })
        .collect()
}

struct FunctionLinker<'a> {
    functions: &'a BTreeMap<(usize, u64), Function>,
    linked_functions: HashMap<(SectionIndex, u64), usize>,
    relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
    symbol_table: &'a HashMap<usize, Symbol>,
    text_sections: &'a HashSet<usize>,
    jump_tables: Option<&'a JumpTablesSection>,
    // Index in `Function::jump_tables` of each table already recorded for the program, keyed by
    // the table's offset in `.jumptables`. A table may be loaded by more than one instruction;
    // all of them must share one map, so libbpf keys its maps the same way.
    linked_jump_tables: HashMap<u64, usize>,
    endianness: Endianness,
}

impl<'a> FunctionLinker<'a> {
    fn new(
        functions: &'a BTreeMap<(usize, u64), Function>,
        relocations: &'a HashMap<SectionIndex, HashMap<u64, Relocation>>,
        symbol_table: &'a HashMap<usize, Symbol>,
        text_sections: &'a HashSet<usize>,
        jump_tables: Option<&'a JumpTablesSection>,
        endianness: Endianness,
    ) -> Self {
        Self {
            functions,
            linked_functions: HashMap::new(),
            relocations,
            symbol_table,
            text_sections,
            jump_tables,
            linked_jump_tables: HashMap::new(),
            endianness,
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
        let Function {
            address,
            name,
            section_index,
            section_offset: _,
            instructions,
            func_info,
            line_info: _,
            func_info_rec_size: _,
            line_info_rec_size: _,
            jump_tables: _,
        } = fun;
        if func_info.func_info.is_empty() != program.func_info.func_info.is_empty() {
            return Err(RelocationError::FunctionInfoMismatch { name: name.clone() });
        }
        let start_ins = match self.linked_functions.entry((*section_index, *address)) {
            Entry::Occupied(entry) => return Ok(*entry.get()),
            Entry::Vacant(entry) => *entry.insert(program.instructions.len()),
        };

        // Append the function once and use its instruction offset for pc-relative calls.
        program.instructions.extend(instructions);
        debug!("linked function `{name}` at instruction {start_ins}");

        // link func and line info into the main program
        // the offset needs to be adjusted
        Self::link_func_and_line_info(program, fun, start_ins);

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

        self.relocate_jump_tables(program, fun, start_ins)?;

        debug!(
            "finished relocating program `{}` function `{}`",
            program.name, fun.name
        );

        Ok(())
    }

    /// Records the jump tables referenced by `fun`, linked into `program` at instruction
    /// `start_ins`, translating their entries into instruction indices of `program`.
    ///
    /// This mirrors libbpf's `create_jt_map`, minus the map creation which is left to the caller.
    fn relocate_jump_tables(
        &mut self,
        program: &mut Function,
        fun: &Function,
        start_ins: usize,
    ) -> Result<(), RelocationError> {
        let Some(JumpTablesSection {
            section_index: jump_tables_section,
            data,
        }) = self.jump_tables
        else {
            return Ok(());
        };
        let Some(relocations) = self.relocations.get(&fun.section_index) else {
            return Ok(());
        };

        let section_offset = fun.section_offset;
        let n_instructions = fun.instructions.len();

        // Relocations live in a hash map; visit the ones in this function in instruction order so
        // the recorded tables and their loads are deterministic.
        let mut relocations: Vec<_> = relocations
            .values()
            .filter(|rel| {
                let rel_offset = rel.offset as usize;
                rel_offset >= section_offset
                    && rel_offset < section_offset + n_instructions * INS_SIZE
            })
            .collect();
        relocations.sort_unstable_by_key(|rel| rel.offset);

        for rel in relocations {
            let sym =
                self.symbol_table
                    .get(&rel.symbol_index)
                    .ok_or(RelocationError::UnknownSymbol {
                        index: rel.symbol_index,
                    })?;
            if sym.section_index != Some(*jump_tables_section) {
                continue;
            }
            let invalid = |reason: String| RelocationError::InvalidJumpTable {
                symbol_name: sym.name.clone(),
                reason,
            };

            let ins_offset = rel.offset as usize - section_offset;
            if !ins_offset.is_multiple_of(INS_SIZE) {
                return Err(invalid(format!(
                    "relocation offset {} is not instruction aligned",
                    rel.offset
                )));
            }
            // The table address is loaded by a two-slot `ld_imm64`.
            let insn_index = start_ins + ins_offset / INS_SIZE;
            if program
                .instructions
                .get(insn_index)
                .is_none_or(|ins| ins.code != (BPF_LD | BPF_IMM | BPF_DW) as u8)
                || insn_index + 1 >= program.instructions.len()
            {
                return Err(invalid(format!(
                    "instruction {insn_index} is not an ld_imm64"
                )));
            }

            match self.linked_jump_tables.entry(sym.address) {
                Entry::Occupied(entry) => {
                    debug!(
                        "jump table `{}` is also loaded at instruction {insn_index} of `{}`",
                        sym.name.as_deref().unwrap_or_default(),
                        program.name,
                    );
                    program.jump_tables[*entry.get()]
                        .insn_indices
                        .push(insn_index);
                }
                Entry::Vacant(entry) => {
                    let targets = jump_table_targets(data, sym, fun, start_ins, self.endianness)?;
                    debug!(
                        "jump table `{}` loaded at instruction {insn_index} of `{}` has {} targets",
                        sym.name.as_deref().unwrap_or_default(),
                        program.name,
                        targets.len()
                    );
                    entry.insert(program.jump_tables.len());
                    program.jump_tables.push(JumpTable {
                        insn_indices: vec![insn_index],
                        targets,
                    });
                }
            }
        }

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
            program.line_info.num_info = program.line_info.line_info.len() as u32;
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
    use std::string::ToString as _;

    use super::*;
    use crate::{
        extern_types::ExternType,
        maps::{BtfMap, LegacyMap},
    };

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

    fn fake_extern_sym(index: usize, name: &str, is_weak: bool) -> Symbol {
        Symbol {
            index,
            section_index: None,
            name: Some(name.to_string()),
            address: 0,
            size: 0,
            is_definition: false,
            kind: SymbolKind::Unknown,
            is_weak,
        }
    }

    fn ins(bytes: &[u8]) -> bpf_insn {
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) }
    }

    fn fake_legacy_map(symbol_index: usize) -> Map {
        Map::Legacy(LegacyMap {
            def: Default::default(),
            inner_def: None,
            section_index: 0,
            section_kind: EbpfSectionKind::Undefined,
            symbol_index: Some(symbol_index),
            data: Vec::new(),
        })
    }

    fn fake_btf_map(symbol_index: usize) -> Map {
        Map::Btf(BtfMap {
            def: Default::default(),
            inner_def: None,
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
            jump_tables: Vec::new(),
        }
    }

    fn fake_jump_tables(entries: &[u64]) -> JumpTablesSection {
        JumpTablesSection {
            section_index: 5,
            data: entries
                .iter()
                .flat_map(|e| Endianness::Little.write_u64(*e))
                .collect(),
        }
    }

    // `ld_imm64 rN, 0` occupies two instruction slots.
    fn ld_imm64(dst: u8) -> [bpf_insn; 2] {
        [ins(&[0x18, dst, 0, 0, 0, 0, 0, 0]), ins(&[0; 8])]
    }

    fn gotox(src: u8) -> bpf_insn {
        ins(&[0x0d, src, 0, 0, 0, 0, 0, 0])
    }

    fn exit() -> bpf_insn {
        ins(&[0x95, 0, 0, 0, 0, 0, 0, 0])
    }

    // ld_imm64 r1, T; gotox r1; exit; exit
    fn fake_gotox_func(section_offset: usize) -> Function {
        let [ld_lo, ld_hi] = ld_imm64(1);
        let mut fun = fake_func("gotox", vec![ld_lo, ld_hi, gotox(1), exit(), exit()]);
        fun.section_index = SectionIndex(1);
        fun.section_offset = section_offset;
        fun
    }

    #[test]
    fn test_jump_table_relocation() {
        // The function starts 16 bytes into its section; the table starts 8 bytes into
        // `.jumptables` and points at the two `exit` instructions.
        let fun = fake_gotox_func(16);
        let symbol_table = HashMap::from([(7, fake_sym(7, 5, 8, "BPF.JT.0.0", 16))]);
        let relocations = HashMap::from([(
            SectionIndex(1),
            HashMap::from([(
                16,
                Relocation {
                    offset: 16,
                    symbol_index: 7,
                    size: 64,
                },
            )]),
        )]);
        let jump_tables = fake_jump_tables(&[0xdead, 16 + 4 * 8, 16 + 3 * 8]);

        let functions = BTreeMap::new();
        let text_sections = HashSet::new();
        let linker = FunctionLinker::new(
            &functions,
            &relocations,
            &symbol_table,
            &text_sections,
            Some(&jump_tables),
            Endianness::Little,
        );
        let linked = linker.link(&fun).unwrap();

        assert_eq!(
            linked.jump_tables,
            vec![JumpTable {
                insn_indices: vec![0],
                targets: vec![4, 3],
            }]
        );
    }

    #[test]
    fn test_jump_table_relocation_shares_table_between_loads() {
        // ld_imm64 r1, T; ld_imm64 r2, T; gotox r1; exit; exit: both loads reference the same
        // table and must end up in a single `JumpTable`.
        let [ld1_lo, ld1_hi] = ld_imm64(1);
        let [ld2_lo, ld2_hi] = ld_imm64(2);
        let mut fun = fake_func(
            "gotox",
            vec![ld1_lo, ld1_hi, ld2_lo, ld2_hi, gotox(1), exit(), exit()],
        );
        fun.section_index = SectionIndex(1);
        let symbol_table = HashMap::from([(7, fake_sym(7, 5, 0, "BPF.JT.0.0", 16))]);
        let relocation = |offset| Relocation {
            offset,
            symbol_index: 7,
            size: 64,
        };
        let relocations = HashMap::from([(
            SectionIndex(1),
            HashMap::from([(16, relocation(16)), (0, relocation(0))]),
        )]);
        let jump_tables = fake_jump_tables(&[5 * 8, 6 * 8]);

        let functions = BTreeMap::new();
        let text_sections = HashSet::new();
        let linker = FunctionLinker::new(
            &functions,
            &relocations,
            &symbol_table,
            &text_sections,
            Some(&jump_tables),
            Endianness::Little,
        );
        let linked = linker.link(&fun).unwrap();

        assert_eq!(
            linked.jump_tables,
            vec![JumpTable {
                insn_indices: vec![0, 2],
                targets: vec![5, 6],
            }]
        );
    }

    #[test]
    fn test_jump_table_relocation_rejects_overflowing_symbol() {
        // Aligned offset and size whose sum overflows must be rejected, not panic.
        let fun = fake_gotox_func(0);
        let symbol_table = HashMap::from([(7, fake_sym(7, 5, 8, "BPF.JT.0.0", u64::MAX - 7))]);
        let relocations = HashMap::from([(
            SectionIndex(1),
            HashMap::from([(
                0,
                Relocation {
                    offset: 0,
                    symbol_index: 7,
                    size: 64,
                },
            )]),
        )]);
        let jump_tables = fake_jump_tables(&[0, 2 * 8]);

        let functions = BTreeMap::new();
        let text_sections = HashSet::new();
        let linker = FunctionLinker::new(
            &functions,
            &relocations,
            &symbol_table,
            &text_sections,
            Some(&jump_tables),
            Endianness::Little,
        );

        assert!(matches!(
            linker.link(&fun),
            Err(RelocationError::InvalidJumpTable { .. })
        ));
    }

    #[test]
    fn test_jump_table_relocation_rejects_target_outside_function() {
        let fun = fake_gotox_func(0);
        let symbol_table = HashMap::from([(7, fake_sym(7, 5, 0, "BPF.JT.0.0", 8))]);
        let relocations = HashMap::from([(
            SectionIndex(1),
            HashMap::from([(
                0,
                Relocation {
                    offset: 0,
                    symbol_index: 7,
                    size: 64,
                },
            )]),
        )]);
        let jump_tables = fake_jump_tables(&[5 * 8]);

        let functions = BTreeMap::new();
        let text_sections = HashSet::new();
        let linker = FunctionLinker::new(
            &functions,
            &relocations,
            &symbol_table,
            &text_sections,
            Some(&jump_tables),
            Endianness::Little,
        );

        assert!(matches!(
            linker.link(&fun),
            Err(RelocationError::InvalidJumpTable { .. })
        ));
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .unwrap();

        assert_eq!(fun.instructions[0].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[0].imm, 1);

        assert_eq!(fun.instructions[1].src_reg(), BPF_PSEUDO_MAP_FD as u8);
        assert_eq!(fun.instructions[1].imm, 2);
    }

    #[test]
    fn test_unresolved_weak_kfunc_call_is_poisoned() {
        let mut fun = fake_func(
            "test",
            vec![ins(&[0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        );

        let relocations = [Relocation {
            offset: 0,
            symbol_index: 1,
            size: 32,
        }];

        let externs = HashMap::from([(
            "missing_kfunc".to_string(),
            ExternDesc {
                name: "missing_kfunc".to_string(),
                extern_type: ExternType::Ksym,
                btf_id: 1,
                is_weak: true,
                is_resolved: false,
                kernel_btf_id: None,
                ksym_addr: None,
                type_id: Some(1),
                essential_name: None,
            },
        )]);

        let symbol_table = HashMap::from([(1, fake_extern_sym(1, "missing_kfunc", true))]);

        patch_extern_relocations(&mut fun, relocations.iter(), &externs, &symbol_table).unwrap();

        let ins = fun.instructions[0];
        assert_eq!(ins.code, (BPF_JMP | BPF_CALL) as u8);
        assert_eq!(ins.src_reg(), 0);
        assert_eq!(ins.dst_reg(), 0);
        assert_eq!(ins.off, 0);
        assert_eq!(ins.imm, POISON_CALL_KFUNC_BASE + 1);
    }

    #[test]
    fn test_unresolved_strong_kfunc_call_is_rejected() {
        let mut fun = fake_func(
            "test",
            vec![ins(&[0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        );

        let relocations = [Relocation {
            offset: 0,
            symbol_index: 1,
            size: 32,
        }];

        let externs = HashMap::from([(
            "missing_kfunc".to_string(),
            ExternDesc {
                name: "missing_kfunc".to_string(),
                extern_type: ExternType::Ksym,
                btf_id: 1,
                is_weak: false,
                is_resolved: false,
                kernel_btf_id: None,
                ksym_addr: None,
                type_id: Some(1),
                essential_name: None,
            },
        )]);

        let symbol_table = HashMap::from([(1, fake_extern_sym(1, "missing_kfunc", false))]);

        let err = patch_extern_relocations(&mut fun, relocations.iter(), &externs, &symbol_table)
            .unwrap_err();

        assert!(matches!(
            err,
            RelocationError::UnresolvableSymbol { name } if name == "missing_kfunc"
        ));
    }

    #[test]
    fn test_unresolved_weak_var_reference_is_null_patched() {
        let mut fun = fake_func(
            "test",
            vec![
                ins(&[
                    0x18, 0x01, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x11,
                    0x22, 0x33, 0x44,
                ]),
                ins(&[0; 8]),
            ],
        );

        let relocations = [Relocation {
            offset: 0,
            symbol_index: 1,
            size: 64,
        }];

        let externs = HashMap::from([(
            "missing_var".to_string(),
            ExternDesc {
                name: "missing_var".to_string(),
                extern_type: ExternType::Ksym,
                btf_id: 1,
                is_weak: true,
                is_resolved: false,
                kernel_btf_id: None,
                ksym_addr: None,
                type_id: None,
                essential_name: None,
            },
        )]);

        let symbol_table = HashMap::from([(1, fake_extern_sym(1, "missing_var", true))]);

        patch_extern_relocations(&mut fun, relocations.iter(), &externs, &symbol_table).unwrap();

        assert_eq!(fun.instructions[0].src_reg(), 0);
        assert_eq!(fun.instructions[0].imm, 0);
        assert_eq!(fun.instructions[1].imm, 0);
    }

    #[test]
    fn test_extern_ldimm_relocation_requires_second_instruction() {
        let mut fun = fake_func(
            "test",
            vec![ins(&[0x18, 0x01, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd])],
        );

        let relocations = [Relocation {
            offset: 0,
            symbol_index: 1,
            size: 64,
        }];

        let externs = HashMap::from([(
            "missing_var".to_string(),
            ExternDesc {
                name: "missing_var".to_string(),
                extern_type: ExternType::Ksym,
                btf_id: 1,
                is_weak: true,
                is_resolved: false,
                kernel_btf_id: None,
                ksym_addr: None,
                type_id: None,
                essential_name: None,
            },
        )]);

        let symbol_table = HashMap::from([(1, fake_extern_sym(1, "missing_var", true))]);

        let err = patch_extern_relocations(&mut fun, relocations.iter(), &externs, &symbol_table)
            .unwrap_err();

        assert!(matches!(
            err,
            RelocationError::InvalidRelocationOffset {
                offset: 0,
                relocation_number: 0,
            }
        ));
    }

    #[test]
    fn test_extern_variable_relocation_requires_ldimm64() {
        let mut fun = fake_func(
            "test",
            vec![
                ins(&[0xb7, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd]),
                ins(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ],
        );

        let relocations = [Relocation {
            offset: 0,
            symbol_index: 1,
            size: 64,
        }];

        let externs = HashMap::from([(
            "missing_var".to_string(),
            ExternDesc {
                name: "missing_var".to_string(),
                extern_type: ExternType::Ksym,
                btf_id: 1,
                is_weak: true,
                is_resolved: false,
                kernel_btf_id: None,
                ksym_addr: None,
                type_id: None,
                essential_name: None,
            },
        )]);

        let symbol_table = HashMap::from([(1, fake_extern_sym(1, "missing_var", true))]);

        let err = patch_extern_relocations(&mut fun, relocations.iter(), &externs, &symbol_table)
            .unwrap_err();

        assert!(matches!(
            err,
            RelocationError::InvalidRelocationOffset {
                offset: 0,
                relocation_number: 0,
            }
        ));
    }
}
