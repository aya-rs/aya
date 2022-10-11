use std::{collections::HashMap, io, mem, ptr, str::FromStr};

use thiserror::Error;

use crate::{
    generated::{
        bpf_core_relo, bpf_core_relo_kind::*, bpf_insn, BPF_ALU, BPF_ALU64, BPF_B, BPF_DW, BPF_H,
        BPF_K, BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_W, BTF_INT_SIGNED,
    },
    obj::{
        btf::{
            fields_are_compatible, types_are_compatible, Array, BtfMember, BtfType, IntEncoding,
            Struct, Union, MAX_SPEC_LEN,
        },
        Btf, BtfError, Object, Program, ProgramSection,
    },
    BpfError,
};

#[derive(Error, Debug)]
pub enum RelocationError {
    #[error(transparent)]
    IOError(#[from] io::Error),

    #[error("program not found")]
    ProgramNotFound,

    #[error("invalid relocation access string {access_str}")]
    InvalidAccessString { access_str: String },

    #[error("invalid instruction index #{index} referenced by relocation #{relocation_number}, the program contains {num_instructions} instructions")]
    InvalidInstructionIndex {
        index: usize,
        num_instructions: usize,
        relocation_number: usize,
    },

    #[error("error relocating {type_name}, multiple candidate target types found with different memory layouts: {candidates:?}")]
    ConflictingCandidates {
        type_name: String,
        candidates: Vec<String>,
    },

    #[error("maximum nesting level reached evaluating candidate type `{}`", err_type_name(.type_name))]
    MaximumNestingLevelReached { type_name: Option<String> },

    #[error("invalid access string `{spec}` for type `{}`: {error}", err_type_name(.type_name))]
    InvalidAccessIndex {
        type_name: Option<String>,
        spec: String,
        index: usize,
        max_index: usize,
        error: String,
    },

    #[error(
        "relocation #{relocation_number} of kind `{relocation_kind}` not valid for type `{type_kind}`: {error}"
    )]
    InvalidRelocationKindForType {
        relocation_number: usize,
        relocation_kind: String,
        type_kind: String,
        error: String,
    },

    #[error(
        "instruction #{index} referenced by relocation #{relocation_number} is invalid: {error}"
    )]
    InvalidInstruction {
        relocation_number: usize,
        index: usize,
        error: String,
    },
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
pub struct Relocation {
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
    pub fn relocate_btf(&mut self, target_btf: &Btf) -> Result<(), BpfError> {
        let (local_btf, btf_ext) = match (&self.btf, &self.btf_ext) {
            (Some(btf), Some(btf_ext)) => (btf, btf_ext),
            _ => return Ok(()),
        };

        let mut candidates_cache = HashMap::<u32, Vec<Candidate>>::new();
        for (sec_name_off, relos) in btf_ext.relocations() {
            let section_name = local_btf.string_at(*sec_name_off)?;

            let program_section = match ProgramSection::from_str(&section_name) {
                Ok(program) => program,
                Err(_) => continue,
            };
            let section_name = program_section.name();

            let program = self
                .programs
                .get_mut(section_name)
                .ok_or(BpfError::RelocationError {
                    function: section_name.to_owned(),
                    error: Box::new(RelocationError::ProgramNotFound),
                })?;
            match relocate_btf_program(program, relos, local_btf, target_btf, &mut candidates_cache)
            {
                Ok(_) => {}
                Err(ErrorWrapper::BtfError(e)) => return Err(e.into()),
                Err(ErrorWrapper::RelocationError(error)) => {
                    return Err(BpfError::RelocationError {
                        function: section_name.to_owned(),
                        error: Box::new(error),
                    })
                }
            }
        }

        Ok(())
    }
}

fn relocate_btf_program<'target>(
    program: &mut Program,
    relos: &[Relocation],
    local_btf: &Btf,
    target_btf: &'target Btf,
    candidates_cache: &mut HashMap<u32, Vec<Candidate<'target>>>,
) -> Result<(), ErrorWrapper> {
    for rel in relos {
        let instructions = &mut program.function.instructions;
        let ins_index = rel.ins_offset / std::mem::size_of::<bpf_insn>();
        if ins_index >= instructions.len() {
            return Err(RelocationError::InvalidInstructionIndex {
                index: ins_index,
                num_instructions: instructions.len(),
                relocation_number: rel.number,
            }
            .into());
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
                    if cand_spec.bit_offset != target_spec.bit_offset
                        || cand_comp_rel.target.value != target_comp_rel.target.value
                    {
                        Some(cand_name)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if !conflicts.is_empty() {
                return Err(RelocationError::ConflictingCandidates {
                    type_name: local_name.to_string(),
                    candidates: conflicts,
                }
                .into());
            }
            target_comp_rel
        } else {
            // there are no candidate matches and therefore no target_spec. This might mean
            // that matching failed, or that the relocation can be applied looking at local
            // types only
            ComputedRelocation::new(rel, &local_spec, None)?
        };

        comp_rel.apply(program, rel, local_btf, target_btf)?;
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
) -> Result<Option<AccessSpec<'target>>, ErrorWrapper> {
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
            match target_ty {
                BtfType::Enum(en) => {
                    for (index, member) in en.variants.iter().enumerate() {
                        let target_variant_name = candidate.btf.string_at(member.name_offset)?;
                        if flavorless_name(local_variant_name)
                            == flavorless_name(&target_variant_name)
                        {
                            target_spec.parts.push(index);
                            target_spec.accessors.push(Accessor {
                                index,
                                type_id: target_id,
                                name: None,
                            });
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
                        }
                        .into());
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

fn match_member<'local, 'target>(
    local_btf: &Btf,
    local_spec: &AccessSpec<'local>,
    local_accessor: &Accessor,
    target_btf: &'target Btf,
    target_id: u32,
    target_spec: &mut AccessSpec<'target>,
) -> Result<Option<u32>, ErrorWrapper> {
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
            }
            .into());
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
    ) -> Result<AccessSpec<'a>, ErrorWrapper> {
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
                    }
                    .into());
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
                BtfType::Enum(en) => {
                    if parts.len() != 1 {
                        return Err(RelocationError::InvalidAccessString {
                            access_str: spec.to_string(),
                        }
                        .into());
                    }
                    let index = parts[0];
                    if index >= en.variants.len() {
                        return Err(RelocationError::InvalidAccessIndex {
                            type_name: btf.err_type_name(ty),
                            spec: spec.to_string(),
                            index,
                            max_index: en.variants.len(),
                            error: "tried to access nonexistant enum variant".to_string(),
                        }
                        .into());
                    }
                    let accessors = vec![Accessor {
                        type_id,
                        index,
                        name: Some(
                            btf.string_at(en.variants.get(index).unwrap().name_offset)?
                                .to_string(),
                        ),
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
                    }
                    .into())
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
                                }
                                .into());
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
                                }
                                .into());
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
                                relocation_kind: format!("{:?}", rel_kind),
                                type_kind: format!("{:?}", ty.kind()),
                                error: "field relocation on a type that doesn't have fields"
                                    .to_string(),
                            }
                            .into());
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
    target: ComputedRelocationValue,
}

#[derive(Debug)]
struct ComputedRelocationValue {
    value: u32,
    size: u32,
    type_id: Option<u32>,
}

impl ComputedRelocation {
    fn new(
        rel: &Relocation,
        local_spec: &AccessSpec,
        target_spec: Option<&AccessSpec>,
    ) -> Result<ComputedRelocation, ErrorWrapper> {
        use RelocationKind::*;
        let ret = match rel.kind {
            FieldByteOffset | FieldByteSize | FieldExists | FieldSigned | FieldLShift64
            | FieldRShift64 => ComputedRelocation {
                local: Self::compute_field_relocation(rel, Some(local_spec))?,
                target: Self::compute_field_relocation(rel, target_spec)?,
            },
            TypeIdLocal | TypeIdTarget | TypeExists | TypeSize => ComputedRelocation {
                local: Self::compute_type_relocation(rel, local_spec, target_spec)?,
                target: Self::compute_type_relocation(rel, local_spec, target_spec)?,
            },
            EnumVariantExists | EnumVariantValue => ComputedRelocation {
                local: Self::compute_enum_relocation(rel, Some(local_spec))?,
                target: Self::compute_enum_relocation(rel, target_spec)?,
            },
        };

        Ok(ret)
    }

    fn apply(
        &self,
        program: &mut Program,
        rel: &Relocation,
        local_btf: &Btf,
        target_btf: &Btf,
    ) -> Result<(), ErrorWrapper> {
        let instructions = &mut program.function.instructions;
        let num_instructions = instructions.len();
        let ins_index = rel.ins_offset / std::mem::size_of::<bpf_insn>();
        let mut ins =
            instructions
                .get_mut(ins_index)
                .ok_or(RelocationError::InvalidInstructionIndex {
                    index: rel.ins_offset,
                    num_instructions,
                    relocation_number: rel.number,
                })?;

        let class = (ins.code & 0x07) as u32;

        let target_value = self.target.value;

        match class {
            BPF_ALU | BPF_ALU64 => {
                let src_reg = ins.src_reg();
                if src_reg != BPF_K as u8 {
                    return Err(RelocationError::InvalidInstruction {
                        relocation_number: rel.number,
                        index: ins_index,
                        error: format!("invalid src_reg={:x} expected {:x}", src_reg, BPF_K),
                    }
                    .into());
                }

                ins.imm = target_value as i32;
            }
            BPF_LDX | BPF_ST | BPF_STX => {
                if target_value > std::i16::MAX as u32 {
                    return Err(RelocationError::InvalidInstruction {
                        relocation_number: rel.number,
                        index: ins_index,
                        error: format!("value `{}` overflows 16 bits offset field", target_value),
                    }
                    .into());
                }

                ins.off = target_value as i16;

                if self.local.size != self.target.size {
                    let local_ty = local_btf.type_by_id(self.local.type_id.unwrap())?;
                    let target_ty = target_btf.type_by_id(self.target.type_id.unwrap())?;
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
                                    self.target.size,
                                ),
                            }
                            .into())
                        }
                    }

                    let size = match self.target.size {
                        8 => BPF_DW,
                        4 => BPF_W,
                        2 => BPF_H,
                        1 => BPF_B,
                        size => {
                            return Err(RelocationError::InvalidInstruction {
                                relocation_number: rel.number,
                                index: ins_index,
                                error: format!("invalid target size {}", size),
                            }
                            .into())
                        }
                    } as u8;
                    ins.code = ins.code & 0xE0 | size | ins.code & 0x07;
                }
            }
            BPF_LD => {
                ins.imm = target_value as i32;
                let mut next_ins = instructions.get_mut(ins_index + 1).ok_or(
                    RelocationError::InvalidInstructionIndex {
                        index: ins_index + 1,
                        num_instructions,
                        relocation_number: rel.number,
                    },
                )?;

                next_ins.imm = 0;
            }
            class => {
                return Err(RelocationError::InvalidInstruction {
                    relocation_number: rel.number,
                    index: ins_index,
                    error: format!("invalid instruction class {:x}", class),
                }
                .into())
            }
        };

        Ok(())
    }

    fn compute_enum_relocation(
        rel: &Relocation,
        spec: Option<&AccessSpec>,
    ) -> Result<ComputedRelocationValue, ErrorWrapper> {
        use RelocationKind::*;
        let value = match rel.kind {
            EnumVariantExists => spec.is_some() as u32,
            EnumVariantValue => {
                let spec = spec.unwrap();
                let accessor = &spec.accessors[0];
                match spec.btf.type_by_id(accessor.type_id)? {
                    BtfType::Enum(en) => en.variants[accessor.index].value as u32,
                    _ => panic!("should not be reached"),
                }
            }
            // this function is only called for enum relocations
            _ => panic!("should not be reached"),
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
    ) -> Result<ComputedRelocationValue, ErrorWrapper> {
        use RelocationKind::*;

        if let FieldExists = rel.kind {
            // this is the bpf_preserve_field_info(member_access, FIELD_EXISTENCE) case. If we
            // managed to build a spec, it means the field exists.
            return Ok(ComputedRelocationValue {
                value: spec.is_some() as u32,
                size: 0,
                type_id: None,
            });
        }

        let spec = spec.unwrap();
        let accessor = spec.accessors.last().unwrap();
        if accessor.name.is_none() {
            // the last accessor is unnamed, meaning that this is an array access
            return match rel.kind {
                FieldByteOffset => Ok(ComputedRelocationValue {
                    value: (spec.bit_offset / 8) as u32,
                    size: spec.btf.type_size(accessor.type_id)? as u32,
                    type_id: Some(accessor.type_id),
                }),
                FieldByteSize => Ok(ComputedRelocationValue {
                    value: spec.btf.type_size(accessor.type_id)? as u32,
                    size: 0,
                    type_id: Some(accessor.type_id),
                }),
                rel_kind => {
                    let ty = spec.btf.type_by_id(accessor.type_id)?;
                    return Err(RelocationError::InvalidRelocationKindForType {
                        relocation_number: rel.number,
                        relocation_kind: format!("{:?}", rel_kind),
                        type_kind: format!("{:?}", ty.kind()),
                        error: "invalid relocation kind for array type".to_string(),
                    }
                    .into());
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
                }
                .into());
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
                value.value = byte_off;
                if !is_bitfield {
                    value.size = byte_size;
                    value.type_id = Some(member_type_id);
                }
            }
            FieldByteSize => {
                value.value = byte_size;
            }
            FieldSigned => match member_ty {
                BtfType::Enum(_) => value.value = 1,
                BtfType::Int(i) => value.value = i.encoding() as u32 & IntEncoding::Signed as u32,
                _ => (),
            },
            #[cfg(target_endian = "little")]
            FieldLShift64 => {
                value.value = 64 - (bit_off + bit_size - byte_off * 8);
            }
            #[cfg(target_endian = "big")]
            FieldLShift64 => {
                value.value = (8 - byte_size) * 8 + (bit_off - byte_off * 8);
            }
            FieldRShift64 => {
                value.value = 64 - bit_size;
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
    ) -> Result<ComputedRelocationValue, ErrorWrapper> {
        use RelocationKind::*;
        let value = match rel.kind {
            TypeIdLocal => local_spec.root_type_id,
            _ => match target_spec {
                Some(target_spec) => match rel.kind {
                    TypeIdTarget => target_spec.root_type_id,
                    TypeExists => 1,
                    TypeSize => target_spec.btf.type_size(target_spec.root_type_id)? as u32,
                    _ => panic!("bug! this should not be reached"),
                },
                // FIXME in the case of TypeIdTarget and TypeSize this should probably fail the
                // relocation...
                None => 0,
            },
        };

        Ok(ComputedRelocationValue {
            value,
            size: 0,
            type_id: None,
        })
    }
}

// this exists only to simplify propagating errors from relocate_btf() and to associate
// RelocationError(s) with their respective program name
#[derive(Error, Debug)]
enum ErrorWrapper {
    #[error(transparent)]
    BtfError(#[from] BtfError),

    #[error(transparent)]
    RelocationError(#[from] RelocationError),
}
