use std::collections::HashMap;

use object::{RelocationKind, RelocationTarget, SectionIndex};
use thiserror::Error;

use super::Object;
use crate::{
    generated::{bpf_insn, BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE},
    maps::Map,
};

#[derive(Debug, Clone, Error)]
pub enum RelocationError {
    #[error("unknown symbol, index `{index}`")]
    UnknownSymbol { index: usize },

    #[error("unknown symbol section, index `{index}`")]
    UnknownSymbolSection { index: usize },

    #[error("section `{section_index}` not found, referenced by symbol `{}`",
            .symbol_name.clone().unwrap_or_else(|| .symbol_index.to_string()))]
    RelocationSectionNotFound {
        section_index: usize,
        symbol_index: usize,
        symbol_name: Option<String>,
    },

    #[error("the map `{name}` at section `{section_index}` has not been created")]
    MapNotCreated { section_index: usize, name: String },

    #[error("invalid relocation offset `{offset}`")]
    InvalidRelocationOffset { offset: u64 },
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct Relocation {
    pub(crate) kind: RelocationKind,
    pub(crate) target: RelocationTarget,
    pub(crate) offset: u64,
    pub(crate) addend: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct Symbol {
    pub(crate) section_index: Option<SectionIndex>,
    pub(crate) name: Option<String>,
    pub(crate) address: u64,
}

pub fn relocate(obj: &mut Object, maps: &[Map]) -> Result<(), RelocationError> {
    let maps_by_section = maps
        .iter()
        .map(|map| (map.obj.section_index, map))
        .collect::<HashMap<_, _>>();

    for program in obj.programs.values_mut() {
        if let Some(relocations) = obj.relocations.get(&program.section_index) {
            for rel in relocations {
                match rel.target {
                    RelocationTarget::Symbol(index) => {
                        let sym = obj
                            .symbol_table
                            .get(&index)
                            .ok_or(RelocationError::UnknownSymbol { index: index.0 })?;

                        let section_index = sym
                            .section_index
                            .ok_or(RelocationError::UnknownSymbolSection { index: index.0 })?;

                        let map = maps_by_section.get(&section_index.0).ok_or(
                            RelocationError::RelocationSectionNotFound {
                                symbol_index: index.0,
                                symbol_name: sym.name.clone(),
                                section_index: section_index.0,
                            },
                        )?;

                        let map_fd = map.fd.ok_or_else(|| RelocationError::MapNotCreated {
                            name: map.obj.name.clone(),
                            section_index: section_index.0,
                        })?;

                        let instructions = &mut program.instructions;
                        let ins_index =
                            (rel.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;
                        if ins_index >= instructions.len() {
                            return Err(RelocationError::InvalidRelocationOffset {
                                offset: rel.offset,
                            });
                        }
                        if !map.obj.data.is_empty() {
                            instructions[ins_index].set_src_reg(BPF_PSEUDO_MAP_VALUE as u8);
                            instructions[ins_index + 1].imm =
                                instructions[ins_index].imm + sym.address as i32;
                        } else {
                            instructions[ins_index].set_src_reg(BPF_PSEUDO_MAP_FD as u8);
                        }
                        instructions[ins_index].imm = map_fd;
                    }
                    RelocationTarget::Section(_index) => {}
                    RelocationTarget::Absolute => todo!(),
                }
            }
        }
    }

    Ok(())
}
