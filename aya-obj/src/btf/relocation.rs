use core::{mem, ops::Bound::Included, ptr};

use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use object::SectionIndex;

use crate::{
    btf::{
        fields_are_compatible, types_are_compatible, Array, Btf, BtfError, BtfMember, BtfType,
        IntEncoding, Struct, Union, MAX_SPEC_LEN,
    },
    generated::{
        bpf_core_relo, bpf_core_relo_kind::*, bpf_insn, BPF_ALU, BPF_ALU64, BPF_B, BPF_CALL,
        BPF_DW, BPF_H, BPF_JMP, BPF_K, BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_W, BTF_INT_SIGNED,
    },
    util::HashMap,
    Function, Object,
};

#[cfg(not(feature = "std"))]
use crate::std;

/// The error type returned by [`Object::relocate_btf`].
#[derive(thiserror::Error, Debug)]
#[error("error relocating `{section}`")]
pub struct BtfRelocationError {
    /// The function name
    pub section: String,
    #[source]
    /// The original error
    error: RelocationError,
}

/// Relocation failures
#[derive(thiserror::Error, Debug)]
enum RelocationError {
    #[cfg(feature = "std")]
    /// I/O error
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Section not found
    #[error("section not found")]
    SectionNotFound,

    /// Function not found
    #[error("function not found")]
    FunctionNotFound,

    /// Invalid relocation access string
    #[error("invalid relocation access string {access_str}")]
    InvalidAccessString {
        /// The access string
        access_str: String,
    },

    /// Invalid instruction index referenced by relocation
    #[error("invalid instruction index #{index} referenced by relocation #{relocation_number}, the program contains {num_instructions} instructions")]
    InvalidInstructionIndex {
        /// The invalid instruction index
        index: usize,
        /// Number of instructions in the program
        num_instructions: usize,
        /// The relocation number
        relocation_number: usize,
    },

    /// Multiple candidate target types found with different memory layouts
    #[error("error relocating {type_name}, multiple candidate target types found with different memory layouts: {candidates:?}")]
    ConflictingCandidates {
        /// The type name
        type_name: String,
        /// The candidates
        candidates: Vec<String>,
    },

    /// Maximum nesting level reached evaluating candidate type
    #[error("maximum nesting level reached evaluating candidate type `{}`", err_type_name(.type_name))]
    MaximumNestingLevelReached {
        /// The type name
        type_name: Option<String>,
    },

    /// Invalid access string
    #[error("invalid access string `{spec}` for type `{}`: {error}", err_type_name(.type_name))]
    InvalidAccessIndex {
        /// The type name
        type_name: Option<String>,
        /// The access string
        spec: String,
        /// The index
        index: usize,
        /// The max index
        max_index: usize,
        /// The error message
        error: String,
    },

    /// Relocation not valid for type
    #[error(
        "relocation #{relocation_number} of kind `{relocation_kind}` not valid for type `{type_kind}`: {error}"
    )]
    InvalidRelocationKindForType {
        /// The relocation number
        relocation_number: usize,
        /// The relocation kind
        relocation_kind: String,
        /// The type kind
        type_kind: String,
        /// The error message
        error: String,
    },

    /// Invalid instruction referenced by relocation
    #[error(
        "instruction #{index} referenced by relocation #{relocation_number} is invalid: {error}"
    )]
    InvalidInstruction {
        /// The relocation number
        relocation_number: usize,
        /// The instruction index
        index: usize,
        /// The error message
        error: String,
    },

    #[error("applying relocation `{kind:?}` missing target BTF info for type `{type_id}` at instruction #{ins_index}")]
    MissingTargetDefinition {
        kind: RelocationKind,
        type_id: u32,
        ins_index: usize,
    },

    /// BTF error
    #[error("invalid BTF")]
    BtfError(#[from] BtfError),
}

fn err_type_name(name: &Option<String>) -> String {
    name.clone().unwrap_or_else(|| "[unknown name]".to_string())
}

#[derive(Copy, Clone, Debug)]
#[repr(u32)]
enum RelocationKind {
    FieldByteOffset = BPF_CORE_FIELD_BYTE_OFFSET,
    FieldByteSize = BPF_CORE_FIELD_BYTE_SIZE,
    FieldExists = BPF_CORE_FIELD_EXISTS,
    FieldSigned = BPF_CORE_FIELD_SIGNED,
    FieldLShift64 = BPF_CORE_FIELD_LSHIFT_U64,
    FieldRShift64 = BPF_CORE_FIELD_RSHIFT_U64,
    TypeIdLocal = BPF_CORE_TYPE_ID_LOCAL,
    TypeIdTarget = BPF_CORE_TYPE_ID_TARGET,
    TypeExists = BPF_CORE_TYPE_EXISTS,
    TypeSize = BPF_CORE_TYPE_SIZE,
    EnumVariantExists = BPF_CORE_ENUMVAL_EXISTS,
    EnumVariantValue = BPF_CORE_ENUMVAL_VALUE,
}

impl TryFrom<u32> for RelocationKind {
    type Error = BtfError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        use RelocationKind::*;

        Ok(match v {
            BPF_CORE_FIELD_BYTE_OFFSET => FieldByteOffset,
            BPF_CORE_FIELD_BYTE_SIZE => FieldByteSize,
            BPF_CORE_FIELD_EXISTS => FieldExists,
            BPF_CORE_FIELD_SIGNED => FieldSigned,
            BPF_CORE_FIELD_LSHIFT_U64 => FieldLShift64,
            BPF_CORE_FIELD_RSHIFT_U64 => FieldRShift64,
            BPF_CORE_TYPE_ID_LOCAL => TypeIdLocal,
            BPF_CORE_TYPE_ID_TARGET => TypeIdTarget,
            BPF_CORE_TYPE_EXISTS => TypeExists,
            BPF_CORE_TYPE_SIZE => TypeSize,
            BPF_CORE_ENUMVAL_EXISTS => EnumVariantExists,
            BPF_CORE_ENUMVAL_VALUE => EnumVariantValue,
            kind => return Err(BtfError::InvalidRelocationKind { kind }),
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct Relocation {
    kind: RelocationKind,
    ins_offset: usize,
    type_id: u32,
    access_str_offset: u32,
    number: usize,
}

impl Relocation {
    #[allow(unused_unsafe)]
    pub(crate) unsafe fn parse(data: &[u8], number: usize) -> Result<Relocation, BtfError> {
        if mem::size_of::<bpf_core_relo>() > data.len() {
            return Err(BtfError::InvalidRelocationInfo);
        }

        let rel = unsafe { ptr::read_unaligned::<bpf_core_relo>(data.as_ptr() as *const _) };

        Ok(Relocation {
            kind: rel.kind.try_into()?,
            ins_offset: rel.insn_off as usize,
            type_id: rel.type_id,
            access_str_offset: rel.access_str_off,
            number,
        })
    }
}

impl Object {
    /// Relocates programs inside this object file with loaded BTF info.
    pub fn relocate_btf(&mut self, target_btf: &Btf) -> Result<(), BtfRelocationError> {
        let (local_btf, btf_ext) = match (&self.btf, &self.btf_ext) {
            (Some(btf), Some(btf_ext)) => (btf, btf_ext),
            _ => return Ok(()),
        };

        let mut candidates_cache = HashMap::<u32, Vec<Candidate>>::new();
        for (sec_name_off, relos) in btf_ext.relocations() {
            let section_name =
                local_btf
                    .string_at(*sec_name_off)
                    .map_err(|e| BtfRelocationError {
                        section: format!("section@{sec_name_off}"),
                        error: RelocationError::BtfError(e),
                    })?;

            let (section_index, _) = self
                .section_infos
                .get(&section_name.to_string())
                .ok_or_else(|| BtfRelocationError {
                    section: section_name.to_string(),
                    error: RelocationError::SectionNotFound,
                })?;

            match relocate_btf_functions(
                section_index,
                &mut self.functions,
                relos,
                local_btf,
                target_btf,
                &mut candidates_cache,
            ) {
                Ok(_) => {}
                Err(error) => {
                    return Err(BtfRelocationError {
                        section: section_name.to_string(),
                        error,
                    })
                }
            }
        }

        Ok(())
    }
}

fn is_relocation_inside_function(
    section_index: &SectionIndex,
    func: &Function,
    rel: &Relocation,
) -> bool {
    if section_index.0 != func.section_index.0 {
        return false;
    }

    let ins_offset = rel.ins_offset / mem::size_of::<bpf_insn>();
    let func_offset = func.section_offset / mem::size_of::<bpf_insn>();
    let func_size = func.instructions.len();

    (func_offset..func_offset + func_size).contains(&ins_offset)
}

fn function_by_relocation<'a>(
    section_index: &SectionIndex,
    functions: &'a mut BTreeMap<(usize, u64), Function>,
    rel: &Relocation,
) -> Option<&'a mut Function> {
    functions
        .range_mut((
            Included(&(section_index.0, 0)),
            Included(&(section_index.0, u64::MAX)),
        ))
        .map(|(_, func)| func)
        .find(|func| is_relocation_inside_function(section_index, func, rel))
}

fn relocate_btf_functions<'target>(
    section_index: &SectionIndex,
    functions: &mut BTreeMap<(usize, u64), Function>,
    relos: &[Relocation],
    local_btf: &Btf,
    target_btf: &'target Btf,
    candidates_cache: &mut HashMap<u32, Vec<Candidate<'target>>>,
) -> Result<(), RelocationError> {
    let mut last_function_opt: Option<&mut Function> = None;

    for rel in relos {
        let function = match last_function_opt.take() {
            Some(func) if is_relocation_inside_function(section_index, func, rel) => func,
            _ => function_by_relocation(section_index, functions, rel)
                .ok_or(RelocationError::FunctionNotFound)?,
        };

        let instructions = &mut function.instructions;
        let ins_index = (rel.ins_offset - function.section_offset) / mem::size_of::<bpf_insn>();
        if ins_index >= instructions.len() {
            return Err(RelocationError::InvalidInstructionIndex {
                index: ins_index,
                num_instructions: instructions.len(),
                relocation_number: rel.number,
            });
        }

        let local_ty = local_btf.type_by_id(rel.type_id)?;
        let local_name = &*local_btf.type_name(local_ty)?;
        let access_str = &*local_btf.string_at(rel.access_str_offset)?;
        let local_spec = AccessSpec::new(local_btf, rel.type_id, access_str, *rel)?;

        let matches = match rel.kind {
            RelocationKind::TypeIdLocal => Vec::new(), // we don't need to look at target types to relocate this value
            _ => {
                let candidates = match candidates_cache.get(&rel.type_id) {
                    Some(cands) => cands,
                    None => {
                        candidates_cache.insert(
                            rel.type_id,
                            find_candidates(local_ty, local_name, target_btf)?,
                        );
                        candidates_cache.get(&rel.type_id).unwrap()
                    }
                };

                let mut matches = Vec::new();
                for candidate in candidates {
                    if let Some(candidate_spec) = match_candidate(&local_spec, candidate)? {
                        let comp_rel =
                            ComputedRelocation::new(rel, &local_spec, Some(&candidate_spec))?;
                        matches.push((candidate.name.clone(), candidate_spec, comp_rel));
                    }
                }

                matches
            }
        };

        let comp_rel = if !matches.is_empty() {
            let mut matches = matches.into_iter();
            let (_, target_spec, target_comp_rel) = matches.next().unwrap();

            // if there's more than one candidate, make sure that they all resolve to the
            // same value, else the relocation is ambiguous and can't be applied
            let conflicts = matches
                .filter_map(|(cand_name, cand_spec, cand_comp_rel)| {
                    if cand_spec.bit_offset != target_spec.bit_offset {
                        return Some(cand_name);
                    } else if let (Some(cand_comp_rel_target), Some(target_comp_rel_target)) = (
                        cand_comp_rel.target.as_ref(),
                        target_comp_rel.target.as_ref(),
                    ) {
                        if cand_comp_rel_target.value != target_comp_rel_target.value {
                            return Some(cand_name);
                        }
                    }

                    None
                })
                .collect::<Vec<_>>();
            if !conflicts.is_empty() {
                return Err(RelocationError::ConflictingCandidates {
                    type_name: local_name.to_string(),
                    candidates: conflicts,
                });
            }
            target_comp_rel
        } else {
            // there are no candidate matches and therefore no target_spec. This might mean
            // that matching failed, or that the relocation can be applied looking at local
            // types only (eg with EnumVariantExists, FieldExists etc)
            ComputedRelocation::new(rel, &local_spec, None)?
        };

        comp_rel.apply(function, rel, local_btf, target_btf)?;

        last_function_opt = Some(function);
    }

    Ok(())
}

fn flavorless_name(name: &str) -> &str {
    name.split_once("___").map_or(name, |x| x.0)
}

fn find_candidates<'target>(
    local_ty: &BtfType,
    local_name: &str,
    target_btf: &'target Btf,
) -> Result<Vec<Candidate<'target>>, BtfError> {
    let mut candidates = Vec::new();
    let local_name = flavorless_name(local_name);
    for (type_id, ty) in target_btf.types().enumerate() {
        if local_ty.kind() != ty.kind() {
            continue;
        }
        let name = &*target_btf.type_name(ty)?;
        if local_name != flavorless_name(name) {
            continue;
        }

        candidates.push(Candidate {
            name: name.to_owned(),
            btf: target_btf,
            _ty: ty,
            type_id: type_id as u32,
        });
    }

    Ok(candidates)
}

fn match_candidate<'target>(
    local_spec: &AccessSpec,
    candidate: &'target Candidate,
) -> Result<Option<AccessSpec<'target>>, RelocationError> {
    let mut target_spec = AccessSpec {
        btf: candidate.btf,
        root_type_id: candidate.type_id,
        relocation: local_spec.relocation,
        parts: Vec::new(),
        accessors: Vec::new(),
        bit_offset: 0,
    };

    match local_spec.relocation.kind {
        RelocationKind::TypeIdLocal
        | RelocationKind::TypeIdTarget
        | RelocationKind::TypeExists
        | RelocationKind::TypeSize => {
            if types_are_compatible(
                local_spec.btf,
                local_spec.root_type_id,
                candidate.btf,
                candidate.type_id,
            )? {
                return Ok(Some(target_spec));
            } else {
                return Ok(None);
            }
        }
        RelocationKind::EnumVariantExists | RelocationKind::EnumVariantValue => {
            let target_id = candidate.btf.resolve_type(candidate.type_id)?;
            let target_ty = candidate.btf.type_by_id(target_id)?;
            // the first accessor is guaranteed to have a name by construction
            let local_variant_name = local_spec.accessors[0].name.as_ref().unwrap();
            let match_enum =
                |name_offset, index, target_spec: &mut AccessSpec| -> Result<_, BtfError> {
                    let target_variant_name = candidate.btf.string_at(name_offset)?;
                    if flavorless_name(local_variant_name) == flavorless_name(&target_variant_name)
                    {
                        target_spec.parts.push(index);
                        target_spec.accessors.push(Accessor {
                            index,
                            type_id: target_id,
                            name: None,
                        });
                        Ok(Some(()))
                    } else {
                        Ok(None)
                    }
                };
            match target_ty {
                BtfType::Enum(en) => {
                    for (index, member) in en.variants.iter().enumerate() {
                        if let Ok(Some(_)) = match_enum(member.name_offset, index, &mut target_spec)
                        {
                            return Ok(Some(target_spec));
                        }
                    }
                }
                BtfType::Enum64(en) => {
                    for (index, member) in en.variants.iter().enumerate() {
                        if let Ok(Some(_)) = match_enum(member.name_offset, index, &mut target_spec)
                        {
                            return Ok(Some(target_spec));
                        }
                    }
                }
                _ => return Ok(None),
            }
        }
        RelocationKind::FieldByteOffset
        | RelocationKind::FieldByteSize
        | RelocationKind::FieldExists
        | RelocationKind::FieldSigned
        | RelocationKind::FieldLShift64
        | RelocationKind::FieldRShift64 => {
            let mut target_id = candidate.type_id;
            for (i, accessor) in local_spec.accessors.iter().enumerate() {
                target_id = candidate.btf.resolve_type(target_id)?;

                if accessor.name.is_some() {
                    if let Some(next_id) = match_member(
                        local_spec.btf,
                        local_spec,
                        accessor,
                        candidate.btf,
                        target_id,
                        &mut target_spec,
                    )? {
                        target_id = next_id;
                    } else {
                        return Ok(None);
                    }
                } else {
                    // i = 0 is the base struct. for i > 0, we need to potentially do bounds checking
                    if i > 0 {
                        let target_ty = candidate.btf.type_by_id(target_id)?;
                        let array = match target_ty {
                            BtfType::Array(Array { array, .. }) => array,
                            _ => return Ok(None),
                        };

                        let var_len = array.len == 0 && {
                            // an array is potentially variable length if it's the last field
                            // of the parent struct and has 0 elements
                            let parent = target_spec.accessors.last().unwrap();
                            let parent_ty = candidate.btf.type_by_id(parent.type_id)?;
                            match parent_ty {
                                BtfType::Struct(s) => parent.index == s.members.len() - 1,
                                _ => false,
                            }
                        };
                        if !var_len && accessor.index >= array.len as usize {
                            return Ok(None);
                        }
                        target_id = candidate.btf.resolve_type(array.element_type)?;
                    }

                    if target_spec.parts.len() == MAX_SPEC_LEN {
                        return Err(RelocationError::MaximumNestingLevelReached {
                            type_name: Some(candidate.name.clone()),
                        });
                    }

                    target_spec.parts.push(accessor.index);
                    target_spec.accessors.push(Accessor {
                        index: accessor.index,
                        type_id: target_id,
                        name: None,
                    });
                    target_spec.bit_offset +=
                        accessor.index * candidate.btf.type_size(target_id)? * 8;
                }
            }
        }
    };

    Ok(Some(target_spec))
}

fn match_member<'target>(
    local_btf: &Btf,
    local_spec: &AccessSpec<'_>,
    local_accessor: &Accessor,
    target_btf: &'target Btf,
    target_id: u32,
    target_spec: &mut AccessSpec<'target>,
) -> Result<Option<u32>, RelocationError> {
    let local_ty = local_btf.type_by_id(local_accessor.type_id)?;
    let local_member = match local_ty {
        // this won't panic, bounds are checked when local_spec is built in AccessSpec::new
        BtfType::Struct(s) => s.members.get(local_accessor.index).unwrap(),
        BtfType::Union(u) => u.members.get(local_accessor.index).unwrap(),
        _ => panic!("bug! this should only be called for structs and unions"),
    };

    let local_name = &*local_btf.string_at(local_member.name_offset)?;
    let target_id = target_btf.resolve_type(target_id)?;
    let target_ty = target_btf.type_by_id(target_id)?;

    let target_members: Vec<&BtfMember> = match target_ty.members() {
        Some(members) => members.collect(),
        // not a fields type, no match
        None => return Ok(None),
    };

    for (index, target_member) in target_members.iter().enumerate() {
        if target_spec.parts.len() == MAX_SPEC_LEN {
            let root_ty = target_spec.btf.type_by_id(target_spec.root_type_id)?;
            return Err(RelocationError::MaximumNestingLevelReached {
                type_name: target_spec.btf.err_type_name(root_ty),
            });
        }

        // this will not panic as we've already established these are fields types
        let bit_offset = target_ty.member_bit_offset(target_member).unwrap();
        let target_name = &*target_btf.string_at(target_member.name_offset)?;

        if target_name.is_empty() {
            let ret = match_member(
                local_btf,
                local_spec,
                local_accessor,
                target_btf,
                target_member.btf_type,
                target_spec,
            )?;
            if ret.is_some() {
                target_spec.bit_offset += bit_offset;
                target_spec.parts.push(index);
                return Ok(ret);
            }
        } else if local_name == target_name {
            if fields_are_compatible(
                local_spec.btf,
                local_member.btf_type,
                target_btf,
                target_member.btf_type,
            )? {
                target_spec.bit_offset += bit_offset;
                target_spec.parts.push(index);
                target_spec.accessors.push(Accessor {
                    type_id: target_id,
                    index,
                    name: Some(target_name.to_owned()),
                });
                return Ok(Some(target_member.btf_type));
            } else {
                return Ok(None);
            }
        }
    }

    Ok(None)
}

#[derive(Debug)]
struct AccessSpec<'a> {
    btf: &'a Btf,
    root_type_id: u32,
    parts: Vec<usize>,
    accessors: Vec<Accessor>,
    relocation: Relocation,
    bit_offset: usize,
}

impl<'a> AccessSpec<'a> {
    fn new(
        btf: &'a Btf,
        root_type_id: u32,
        spec: &str,
        relocation: Relocation,
    ) -> Result<AccessSpec<'a>, RelocationError> {
        let parts = spec
            .split(':')
            .map(|s| s.parse::<usize>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RelocationError::InvalidAccessString {
                access_str: spec.to_string(),
            })?;

        let mut type_id = btf.resolve_type(root_type_id)?;
        let ty = btf.type_by_id(type_id)?;

        let spec = match relocation.kind {
            RelocationKind::TypeIdLocal
            | RelocationKind::TypeIdTarget
            | RelocationKind::TypeExists
            | RelocationKind::TypeSize => {
                if parts != [0] {
                    return Err(RelocationError::InvalidAccessString {
                        access_str: spec.to_string(),
                    });
                }
                AccessSpec {
                    btf,
                    root_type_id,
                    relocation,
                    parts,
                    accessors: Vec::new(),
                    bit_offset: 0,
                }
            }
            RelocationKind::EnumVariantExists | RelocationKind::EnumVariantValue => match ty {
                BtfType::Enum(_) | BtfType::Enum64(_) => {
                    if parts.len() != 1 {
                        return Err(RelocationError::InvalidAccessString {
                            access_str: spec.to_string(),
                        });
                    }
                    let index = parts[0];

                    let (n_variants, name_offset) = match ty {
                        BtfType::Enum(en) => (
                            en.variants.len(),
                            en.variants.get(index).map(|v| v.name_offset),
                        ),
                        BtfType::Enum64(en) => (
                            en.variants.len(),
                            en.variants.get(index).map(|v| v.name_offset),
                        ),
                        _ => unreachable!(),
                    };

                    if name_offset.is_none() {
                        return Err(RelocationError::InvalidAccessIndex {
                            type_name: btf.err_type_name(ty),
                            spec: spec.to_string(),
                            index,
                            max_index: n_variants,
                            error: "tried to access nonexistant enum variant".to_string(),
                        });
                    }
                    let accessors = vec![Accessor {
                        type_id,
                        index,
                        name: Some(btf.string_at(name_offset.unwrap())?.to_string()),
                    }];

                    AccessSpec {
                        btf,
                        root_type_id,
                        relocation,
                        parts,
                        accessors,
                        bit_offset: 0,
                    }
                }
                _ => {
                    return Err(RelocationError::InvalidRelocationKindForType {
                        relocation_number: relocation.number,
                        relocation_kind: format!("{:?}", relocation.kind),
                        type_kind: format!("{:?}", ty.kind()),
                        error: "enum relocation on non-enum type".to_string(),
                    })
                }
            },

            RelocationKind::FieldByteOffset
            | RelocationKind::FieldByteSize
            | RelocationKind::FieldExists
            | RelocationKind::FieldSigned
            | RelocationKind::FieldLShift64
            | RelocationKind::FieldRShift64 => {
                let mut accessors = vec![Accessor {
                    type_id,
                    index: parts[0],
                    name: None,
                }];
                let mut bit_offset = accessors[0].index * btf.type_size(type_id)?;
                for index in parts.iter().skip(1).cloned() {
                    type_id = btf.resolve_type(type_id)?;
                    let ty = btf.type_by_id(type_id)?;

                    match ty {
                        BtfType::Struct(Struct { members, .. })
                        | BtfType::Union(Union { members, .. }) => {
                            if index >= members.len() {
                                return Err(RelocationError::InvalidAccessIndex {
                                    type_name: btf.err_type_name(ty),
                                    spec: spec.to_string(),
                                    index,
                                    max_index: members.len(),
                                    error: "out of bounds struct or union access".to_string(),
                                });
                            }

                            let member = &members[index];
                            bit_offset += ty.member_bit_offset(member).unwrap();

                            if member.name_offset != 0 {
                                accessors.push(Accessor {
                                    type_id,
                                    index,
                                    name: Some(btf.string_at(member.name_offset)?.to_string()),
                                });
                            }

                            type_id = member.btf_type;
                        }

                        BtfType::Array(Array { array, .. }) => {
                            type_id = btf.resolve_type(array.element_type)?;
                            let var_len = array.len == 0 && {
                                // an array is potentially variable length if it's the last field
                                // of the parent struct and has 0 elements
                                let parent = accessors.last().unwrap();
                                let parent_ty = btf.type_by_id(parent.type_id)?;
                                match parent_ty {
                                    BtfType::Struct(s) => index == s.members.len() - 1,
                                    _ => false,
                                }
                            };
                            if !var_len && index >= array.len as usize {
                                return Err(RelocationError::InvalidAccessIndex {
                                    type_name: btf.err_type_name(ty),
                                    spec: spec.to_string(),
                                    index,
                                    max_index: array.len as usize,
                                    error: "array index out of bounds".to_string(),
                                });
                            }
                            accessors.push(Accessor {
                                type_id,
                                index,
                                name: None,
                            });
                            let size = btf.type_size(type_id)?;
                            bit_offset += index * size * 8;
                        }
                        rel_kind => {
                            return Err(RelocationError::InvalidRelocationKindForType {
                                relocation_number: relocation.number,
                                relocation_kind: format!("{rel_kind:?}"),
                                type_kind: format!("{:?}", ty.kind()),
                                error: "field relocation on a type that doesn't have fields"
                                    .to_string(),
                            });
                        }
                    };
                }

                AccessSpec {
                    btf,
                    root_type_id,
                    parts,
                    accessors,
                    relocation,
                    bit_offset,
                }
            }
        };

        Ok(spec)
    }
}

#[derive(Debug)]
struct Accessor {
    type_id: u32,
    index: usize,
    name: Option<String>,
}

#[derive(Debug)]
struct Candidate<'a> {
    name: String,
    btf: &'a Btf,
    _ty: &'a BtfType,
    type_id: u32,
}

#[derive(Debug)]
struct ComputedRelocation {
    local: ComputedRelocationValue,
    target: Option<ComputedRelocationValue>,
}

#[derive(Debug)]
struct ComputedRelocationValue {
    value: u64,
    size: u32,
    type_id: Option<u32>,
}

fn poison_insn(ins: &mut bpf_insn) {
    ins.code = (BPF_JMP | BPF_CALL) as u8;
    ins.set_dst_reg(0);
    ins.set_src_reg(0);
    ins.off = 0;
    ins.imm = 0xBAD2310;
}

impl ComputedRelocation {
    fn new(
        rel: &Relocation,
        local_spec: &AccessSpec,
        target_spec: Option<&AccessSpec>,
    ) -> Result<ComputedRelocation, RelocationError> {
        use RelocationKind::*;
        let ret = match rel.kind {
            FieldByteOffset | FieldByteSize | FieldExists | FieldSigned | FieldLShift64
            | FieldRShift64 => ComputedRelocation {
                local: Self::compute_field_relocation(rel, Some(local_spec))?,
                target: Self::compute_field_relocation(rel, target_spec).ok(),
            },
            TypeIdLocal | TypeIdTarget | TypeExists | TypeSize => ComputedRelocation {
                local: Self::compute_type_relocation(rel, local_spec, target_spec)?,
                target: Self::compute_type_relocation(rel, local_spec, target_spec).ok(),
            },
            EnumVariantExists | EnumVariantValue => ComputedRelocation {
                local: Self::compute_enum_relocation(rel, Some(local_spec))?,
                target: Self::compute_enum_relocation(rel, target_spec).ok(),
            },
        };

        Ok(ret)
    }

    fn apply(
        &self,
        function: &mut Function,
        rel: &Relocation,
        local_btf: &Btf,
        target_btf: &Btf,
    ) -> Result<(), RelocationError> {
        let instructions = &mut function.instructions;
        let num_instructions = instructions.len();
        let ins_index = (rel.ins_offset - function.section_offset) / mem::size_of::<bpf_insn>();
        let ins =
            instructions
                .get_mut(ins_index)
                .ok_or(RelocationError::InvalidInstructionIndex {
                    index: rel.ins_offset,
                    num_instructions,
                    relocation_number: rel.number,
                })?;

        let target = if let Some(target) = self.target.as_ref() {
            target
        } else {
            let is_ld_imm64 = ins.code == (BPF_LD | BPF_DW) as u8;

            poison_insn(ins);

            if is_ld_imm64 {
                let next_ins = instructions.get_mut(ins_index + 1).ok_or(
                    RelocationError::InvalidInstructionIndex {
                        index: (ins_index + 1) * mem::size_of::<bpf_insn>(),
                        num_instructions,
                        relocation_number: rel.number,
                    },
                )?;

                poison_insn(next_ins);
            }

            return Ok(());
        };

        let class = (ins.code & 0x07) as u32;

        let target_value = target.value;

        match class {
            BPF_ALU | BPF_ALU64 => {
                let src_reg = ins.src_reg();
                if src_reg != BPF_K as u8 {
                    return Err(RelocationError::InvalidInstruction {
                        relocation_number: rel.number,
                        index: ins_index,
                        error: format!("invalid src_reg={src_reg:x} expected {BPF_K:x}"),
                    });
                }

                ins.imm = target_value as i32;
            }
            BPF_LDX | BPF_ST | BPF_STX => {
                if target_value > i16::MAX as u64 {
                    return Err(RelocationError::InvalidInstruction {
                        relocation_number: rel.number,
                        index: ins_index,
                        error: format!("value `{target_value}` overflows 16 bits offset field"),
                    });
                }

                ins.off = target_value as i16;

                if self.local.size != target.size {
                    let local_ty = local_btf.type_by_id(self.local.type_id.unwrap())?;
                    let target_ty = target_btf.type_by_id(target.type_id.unwrap())?;
                    let unsigned = |info: u32| ((info >> 24) & 0x0F) & BTF_INT_SIGNED == 0;
                    use BtfType::*;
                    match (local_ty, target_ty) {
                        (Ptr(_), Ptr(_)) => {}
                        (Int(local), Int(target))
                            if unsigned(local.data) && unsigned(target.data) => {}
                        _ => {
                            return Err(RelocationError::InvalidInstruction {
                                relocation_number: rel.number,
                                index: ins_index,
                                error: format!(
                                    "original type {} has size {} but target type {} has size {}",
                                    err_type_name(&local_btf.err_type_name(local_ty)),
                                    self.local.size,
                                    err_type_name(&target_btf.err_type_name(target_ty)),
                                    target.size,
                                ),
                            })
                        }
                    }

                    let size = match target.size {
                        8 => BPF_DW,
                        4 => BPF_W,
                        2 => BPF_H,
                        1 => BPF_B,
                        size => {
                            return Err(RelocationError::InvalidInstruction {
                                relocation_number: rel.number,
                                index: ins_index,
                                error: format!("invalid target size {size}"),
                            })
                        }
                    } as u8;
                    ins.code = ins.code & 0xE0 | size | ins.code & 0x07;
                }
            }
            BPF_LD => {
                ins.imm = target_value as i32;
                let next_ins = instructions.get_mut(ins_index + 1).ok_or(
                    RelocationError::InvalidInstructionIndex {
                        index: ins_index + 1,
                        num_instructions,
                        relocation_number: rel.number,
                    },
                )?;

                next_ins.imm = (target_value >> 32) as i32;
            }
            class => {
                return Err(RelocationError::InvalidInstruction {
                    relocation_number: rel.number,
                    index: ins_index,
                    error: format!("invalid instruction class {class:x}"),
                })
            }
        };

        Ok(())
    }

    fn compute_enum_relocation(
        rel: &Relocation,
        spec: Option<&AccessSpec>,
    ) -> Result<ComputedRelocationValue, RelocationError> {
        use RelocationKind::*;
        let value = match (rel.kind, spec) {
            (EnumVariantExists, spec) => spec.is_some() as u64,
            (EnumVariantValue, Some(spec)) => {
                let accessor = &spec.accessors[0];
                match spec.btf.type_by_id(accessor.type_id)? {
                    BtfType::Enum(en) => {
                        let value = en.variants[accessor.index].value;
                        if en.is_signed() {
                            value as i32 as u64
                        } else {
                            value as u64
                        }
                    }
                    BtfType::Enum64(en) => {
                        let variant = &en.variants[accessor.index];
                        (variant.value_high as u64) << 32 | variant.value_low as u64
                    }
                    // candidate selection ensures that rel_kind == local_kind == target_kind
                    _ => unreachable!(),
                }
            }
            _ => {
                return Err(RelocationError::MissingTargetDefinition {
                    kind: rel.kind,
                    type_id: rel.type_id,
                    ins_index: rel.ins_offset / mem::size_of::<bpf_insn>(),
                })?;
            }
        };

        Ok(ComputedRelocationValue {
            value,
            size: 0,
            type_id: None,
        })
    }

    fn compute_field_relocation(
        rel: &Relocation,
        spec: Option<&AccessSpec>,
    ) -> Result<ComputedRelocationValue, RelocationError> {
        use RelocationKind::*;

        if let FieldExists = rel.kind {
            // this is the bpf_preserve_field_info(member_access, FIELD_EXISTENCE) case. If we
            // managed to build a spec, it means the field exists.
            return Ok(ComputedRelocationValue {
                value: spec.is_some() as u64,
                size: 0,
                type_id: None,
            });
        }

        let spec = match spec {
            Some(spec) => spec,
            None => {
                return Err(RelocationError::MissingTargetDefinition {
                    kind: rel.kind,
                    type_id: rel.type_id,
                    ins_index: rel.ins_offset / mem::size_of::<bpf_insn>(),
                })?;
            }
        };

        let accessor = spec.accessors.last().unwrap();
        if accessor.name.is_none() {
            // the last accessor is unnamed, meaning that this is an array access
            return match rel.kind {
                FieldByteOffset => Ok(ComputedRelocationValue {
                    value: (spec.bit_offset / 8) as u64,
                    size: spec.btf.type_size(accessor.type_id)? as u32,
                    type_id: Some(accessor.type_id),
                }),
                FieldByteSize => Ok(ComputedRelocationValue {
                    value: spec.btf.type_size(accessor.type_id)? as u64,
                    size: 0,
                    type_id: Some(accessor.type_id),
                }),
                rel_kind => {
                    let ty = spec.btf.type_by_id(accessor.type_id)?;
                    return Err(RelocationError::InvalidRelocationKindForType {
                        relocation_number: rel.number,
                        relocation_kind: format!("{rel_kind:?}"),
                        type_kind: format!("{:?}", ty.kind()),
                        error: "invalid relocation kind for array type".to_string(),
                    });
                }
            };
        }

        let ty = spec.btf.type_by_id(accessor.type_id)?;
        let (ll_ty, member) = match ty {
            BtfType::Struct(t) => (ty, t.members.get(accessor.index).unwrap()),
            BtfType::Union(t) => (ty, t.members.get(accessor.index).unwrap()),
            _ => {
                return Err(RelocationError::InvalidRelocationKindForType {
                    relocation_number: rel.number,
                    relocation_kind: format!("{:?}", rel.kind),
                    type_kind: format!("{:?}", ty.kind()),
                    error: "field relocation on a type that doesn't have fields".to_string(),
                });
            }
        };

        let bit_off = spec.bit_offset as u32;
        let member_type_id = spec.btf.resolve_type(member.btf_type)?;
        let member_ty = spec.btf.type_by_id(member_type_id)?;

        let mut byte_size;
        let mut byte_off;
        let mut bit_size = ll_ty.member_bit_field_size(member).unwrap() as u32;
        let is_bitfield = bit_size > 0;
        if is_bitfield {
            // find out the smallest int size to load the bitfield
            byte_size = member_ty.size().unwrap();
            byte_off = bit_off / 8 / byte_size * byte_size;
            while bit_off + bit_size - byte_off * 8 > byte_size * 8 {
                if byte_size >= 8 {
                    // the bitfield is larger than 8 bytes!?
                    return Err(BtfError::InvalidTypeInfo.into());
                }
                byte_size *= 2;
                byte_off = bit_off / 8 / byte_size * byte_size;
            }
        } else {
            byte_size = spec.btf.type_size(member_type_id)? as u32;
            bit_size = byte_size * 8;
            byte_off = spec.bit_offset as u32 / 8;
        }

        let mut value = ComputedRelocationValue {
            value: 0,
            size: 0,
            type_id: None,
        };

        #[allow(clippy::wildcard_in_or_patterns)]
        match rel.kind {
            FieldByteOffset => {
                value.value = byte_off as u64;
                if !is_bitfield {
                    value.size = byte_size;
                    value.type_id = Some(member_type_id);
                }
            }
            FieldByteSize => {
                value.value = byte_size as u64;
            }
            FieldSigned => match member_ty {
                BtfType::Enum(en) => value.value = en.is_signed() as u64,
                BtfType::Enum64(en) => value.value = en.is_signed() as u64,
                BtfType::Int(i) => value.value = i.encoding() as u64 & IntEncoding::Signed as u64,
                _ => (),
            },
            #[cfg(target_endian = "little")]
            FieldLShift64 => {
                value.value = 64 - (bit_off + bit_size - byte_off * 8) as u64;
            }
            #[cfg(target_endian = "big")]
            FieldLShift64 => {
                value.value = (8 - byte_size) * 8 + (bit_off - byte_off * 8);
            }
            FieldRShift64 => {
                value.value = 64 - bit_size as u64;
            }
            FieldExists // this is handled at the start of the function
            | _ => panic!("bug! this should not be reached"),
        }

        Ok(value)
    }

    fn compute_type_relocation(
        rel: &Relocation,
        local_spec: &AccessSpec,
        target_spec: Option<&AccessSpec>,
    ) -> Result<ComputedRelocationValue, RelocationError> {
        use RelocationKind::*;

        let value = match (rel.kind, target_spec) {
            (TypeIdLocal, _) => local_spec.root_type_id as u64,
            (TypeIdTarget, Some(target_spec)) => target_spec.root_type_id as u64,
            (TypeExists, target_spec) => target_spec.is_some() as u64,
            (TypeSize, Some(target_spec)) => {
                target_spec.btf.type_size(target_spec.root_type_id)? as u64
            }
            _ => {
                return Err(RelocationError::MissingTargetDefinition {
                    kind: rel.kind,
                    type_id: rel.type_id,
                    ins_index: rel.ins_offset / mem::size_of::<bpf_insn>(),
                })?;
            }
        };

        Ok(ComputedRelocationValue {
            value,
            size: 0,
            type_id: None,
        })
    }
}
