use std::{
    borrow::{Cow, ToOwned as _},
    collections::{BTreeMap, hash_map::Entry},
    format,
    num::ParseIntError,
    ops::Bound::Included,
    ptr,
    string::ToString as _,
};

use object::SectionIndex;

use crate::{
    Function, Object,
    btf::{
        Array, Btf, BtfError, BtfKind, BtfMember, BtfType, IntEncoding, MAX_SPEC_LEN, Struct,
        Union, fields_are_compatible, types_are_compatible,
    },
    generated::{
        BPF_ALU, BPF_ALU64, BPF_B, BPF_CALL, BPF_DW, BPF_H, BPF_JMP, BPF_K, BPF_LD, BPF_LDX,
        BPF_ST, BPF_STX, BPF_W, BTF_INT_SIGNED, bpf_core_relo, bpf_core_relo_kind, bpf_insn,
    },
    relocation::function_ref,
    util::{HashMap, HashSet},
};

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
    #[error(
        "invalid instruction index #{index} referenced by relocation #{relocation_number}, the program contains {num_instructions} instructions"
    )]
    InvalidInstructionIndex {
        /// The invalid instruction index
        index: usize,
        /// Number of instructions in the program
        num_instructions: usize,
        /// The relocation number
        relocation_number: usize,
    },

    /// Multiple candidate target types found with different memory layouts
    #[error(
        "error relocating {type_name}, multiple candidate target types found with different memory layouts: {candidates:?}"
    )]
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
    #[error(
        "invalid access string `{spec}` at `{access_path}`: {error} (index {index}, length {len})"
    )]
    InvalidAccessIndex {
        /// The path to the indexed container
        access_path: String,
        /// The access string
        spec: String,
        /// The index
        index: usize,
        /// The number of elements in the indexed container
        len: usize,
        /// The error message
        error: &'static str,
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
        error: &'static str,
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
        error: Cow<'static, str>,
    },

    #[error(
        "applying relocation `{kind:?}` missing target BTF info for type `{type_id}` at instruction #{ins_index}"
    )]
    MissingTargetDefinition {
        kind: RelocationKind,
        type_id: u32,
        ins_index: usize,
    },

    /// BTF error
    #[error("invalid BTF")]
    BtfError(#[from] BtfError),
}

#[expect(clippy::ref_option, reason = "more ergonomic here")]
fn err_type_name(name: &Option<String>) -> &str {
    name.as_deref().unwrap_or("[unknown name]")
}

#[derive(Copy, Clone, Debug)]
#[repr(u32)]
enum RelocationKind {
    FieldByteOffset = bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET,
    FieldByteSize = bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_SIZE,
    FieldExists = bpf_core_relo_kind::BPF_CORE_FIELD_EXISTS,
    FieldSigned = bpf_core_relo_kind::BPF_CORE_FIELD_SIGNED,
    FieldLShift64 = bpf_core_relo_kind::BPF_CORE_FIELD_LSHIFT_U64,
    FieldRShift64 = bpf_core_relo_kind::BPF_CORE_FIELD_RSHIFT_U64,
    TypeIdLocal = bpf_core_relo_kind::BPF_CORE_TYPE_ID_LOCAL,
    TypeIdTarget = bpf_core_relo_kind::BPF_CORE_TYPE_ID_TARGET,
    TypeExists = bpf_core_relo_kind::BPF_CORE_TYPE_EXISTS,
    TypeSize = bpf_core_relo_kind::BPF_CORE_TYPE_SIZE,
    EnumVariantExists = bpf_core_relo_kind::BPF_CORE_ENUMVAL_EXISTS,
    EnumVariantValue = bpf_core_relo_kind::BPF_CORE_ENUMVAL_VALUE,
}

impl TryFrom<u32> for RelocationKind {
    type Error = BtfError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(match v {
            bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET => Self::FieldByteOffset,
            bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_SIZE => Self::FieldByteSize,
            bpf_core_relo_kind::BPF_CORE_FIELD_EXISTS => Self::FieldExists,
            bpf_core_relo_kind::BPF_CORE_FIELD_SIGNED => Self::FieldSigned,
            bpf_core_relo_kind::BPF_CORE_FIELD_LSHIFT_U64 => Self::FieldLShift64,
            bpf_core_relo_kind::BPF_CORE_FIELD_RSHIFT_U64 => Self::FieldRShift64,
            bpf_core_relo_kind::BPF_CORE_TYPE_ID_LOCAL => Self::TypeIdLocal,
            bpf_core_relo_kind::BPF_CORE_TYPE_ID_TARGET => Self::TypeIdTarget,
            bpf_core_relo_kind::BPF_CORE_TYPE_EXISTS => Self::TypeExists,
            bpf_core_relo_kind::BPF_CORE_TYPE_SIZE => Self::TypeSize,
            bpf_core_relo_kind::BPF_CORE_ENUMVAL_EXISTS => Self::EnumVariantExists,
            bpf_core_relo_kind::BPF_CORE_ENUMVAL_VALUE => Self::EnumVariantValue,
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
    pub(crate) unsafe fn parse(data: &[u8], number: usize) -> Result<Self, BtfError> {
        if size_of::<bpf_core_relo>() > data.len() {
            return Err(BtfError::InvalidRelocationInfo);
        }

        let rel = unsafe { ptr::read_unaligned::<bpf_core_relo>(data.as_ptr().cast()) };

        Ok(Self {
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
        let (Some(local_btf), Some(btf_ext)) = (&self.btf, &self.btf_ext) else {
            return Ok(());
        };

        let groups = self.candidate_groups(local_btf, btf_ext.relocations());
        let mut lists = CandidateLists::default();
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
                *section_index,
                &mut self.functions,
                relos,
                local_btf,
                target_btf,
                &groups,
                &mut lists,
            ) {
                Ok(()) => {}
                Err(error) => {
                    return Err(BtfRelocationError {
                        section: section_name.to_string(),
                        error,
                    });
                }
            }
        }

        Ok(())
    }

    /// Groups the relocations whose candidates are pruned together. Returns the group of each
    /// function and local type id, for the functions that carry a relocation of the type that
    /// looks at the target types.
    ///
    /// The linker links each program with the functions that it reaches through the calls and
    /// text relocations that it follows, and the result runs against one target layout. So two
    /// functions share a group for a type when some program is linked with both, or when a
    /// chain of such pairs joins them. A function that carries no relocation of the type
    /// doesn't join the functions that reach it: programs that call the same helper stay
    /// apart. A function that no program reaches is never linked, so it joins no group with the
    /// functions it calls.
    fn candidate_groups(
        &self,
        local_btf: &Btf,
        core_relos: &[(u32, Vec<Relocation>)],
    ) -> HashMap<((usize, u64), u32), usize> {
        // The nodes are the functions and local types that have a relocation to match.
        let mut nodes = HashMap::<((usize, u64), u32), usize>::new();
        for (sec_name_off, relos) in core_relos {
            // An error in the relocation info is for `relocate_btf` to report.
            let Ok(section_name) = local_btf.string_at(*sec_name_off) else {
                continue;
            };
            let Some((section_index, _)) = self.section_infos.get(&section_name.to_string()) else {
                continue;
            };
            let keys = function_keys_by_relocation(*section_index, &self.functions, relos);
            for (rel, key) in relos.iter().zip(keys) {
                if matches!(rel.kind, RelocationKind::TypeIdLocal) {
                    continue;
                }
                if let Some(key) = key {
                    let next = nodes.len();
                    nodes.entry((key, rel.type_id)).or_insert(next);
                }
            }
        }
        if nodes.is_empty() {
            return HashMap::new();
        }

        let text_sections = self
            .functions
            .keys()
            .map(|(section_index, _)| *section_index)
            .collect::<HashSet<_>>();
        let ids = self
            .functions
            .keys()
            .enumerate()
            .map(|(id, key)| (*key, id))
            .collect::<HashMap<_, _>>();
        let functions = self.functions.values().collect::<Vec<_>>();

        // The functions that the linker starts from, by function id.
        let program_ids = self
            .programs
            .values()
            .filter_map(|program| ids.get(&program.function_key()).copied())
            .collect::<Vec<_>>();
        // The callees of each function, by function id. Only the functions that a walk reaches
        // get theirs, which are the ones that the linker links.
        let mut callees = vec![None::<Vec<usize>>; ids.len()];
        // The nodes of each function, by function id.
        let mut function_nodes = vec![Vec::new(); ids.len()];
        for ((key, type_id), node) in &nodes {
            function_nodes[ids[key]].push((*type_id, *node));
        }

        // A union-find forest over the nodes, whose roots name the groups.
        let mut parents = (0..nodes.len()).collect::<Vec<_>>();
        const fn root(parents: &mut [usize], mut node: usize) -> usize {
            while parents[node] != node {
                parents[node] = parents[parents[node]];
                node = parents[node];
            }
            node
        }

        // The walk starts at each program, as the linker links each one with the functions it
        // reaches. A function that no program reaches is never linked, so no walk joins its
        // nodes with others. Each walk visits a function and its calls at most once, and
        // objects have few programs.
        for id in program_ids {
            let mut reached = vec![false; ids.len()];
            let mut stack = vec![id];
            // The first node of each type among the functions that `id` reaches.
            let mut first = HashMap::<u32, usize>::new();
            while let Some(current) = stack.pop() {
                if reached[current] {
                    continue;
                }
                reached[current] = true;
                let current_callees = callees[current].get_or_insert_with(|| {
                    let fun = functions[current];
                    let relocations = self.relocations.get(&fun.section_index);
                    fun.instructions
                        .iter()
                        .enumerate()
                        .filter_map(|(ins_index, ins)| {
                            // An unresolved callee is for the linker to report.
                            let callee = function_ref(
                                fun,
                                ins_index,
                                *ins,
                                relocations,
                                &self.symbol_table,
                                &text_sections,
                            )?
                            .callee
                            .ok()?;
                            ids.get(&callee).copied()
                        })
                        .collect()
                });
                stack.extend(&*current_callees);
                for &(type_id, node) in &function_nodes[current] {
                    match first.entry(type_id) {
                        Entry::Occupied(entry) => {
                            let (first_root, node_root) =
                                (root(&mut parents, *entry.get()), root(&mut parents, node));
                            parents[node_root] = first_root;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(node);
                        }
                    }
                }
            }
        }

        nodes
            .into_iter()
            .map(|(key, node)| (key, root(&mut parents, node)))
            .collect()
    }
}

fn is_relocation_inside_function(
    section_index: SectionIndex,
    func: &Function,
    rel: &Relocation,
) -> bool {
    if section_index.0 != func.section_index.0 {
        return false;
    }

    let ins_offset = rel.ins_offset / size_of::<bpf_insn>();
    let func_offset = func.section_offset / size_of::<bpf_insn>();
    let func_size = func.instructions.len();

    (func_offset..func_offset + func_size).contains(&ins_offset)
}

/// Returns the key of the function that each relocation of a section applies to: the function
/// of the previous relocation if it holds this one too, else the first function that does, or
/// `None` if none does. With overlapping functions these can differ, so `relocate_btf_functions`
/// and `candidate_groups` both take their keys from here and agree on them.
fn function_keys_by_relocation(
    section_index: SectionIndex,
    functions: &BTreeMap<(usize, u64), Function>,
    relos: &[Relocation],
) -> Vec<Option<(usize, u64)>> {
    let mut last_key = None;
    relos
        .iter()
        .map(|rel| {
            last_key = last_key
                .filter(|key| {
                    functions
                        .get(key)
                        .is_some_and(|func| is_relocation_inside_function(section_index, func, rel))
                })
                .or_else(|| {
                    functions
                        .range((
                            Included(&(section_index.0, 0)),
                            Included(&(section_index.0, u64::MAX)),
                        ))
                        .find(|(_, func)| is_relocation_inside_function(section_index, func, rel))
                        .map(|(key, _)| *key)
                });
            last_key
        })
        .collect()
}

fn relocate_btf_functions<'target>(
    section_index: SectionIndex,
    functions: &mut BTreeMap<(usize, u64), Function>,
    relos: &[Relocation],
    local_btf: &Btf,
    target_btf: &'target Btf,
    groups: &HashMap<((usize, u64), u32), usize>,
    lists: &mut CandidateLists<'target>,
) -> Result<(), RelocationError> {
    let keys = function_keys_by_relocation(section_index, functions, relos);

    for (rel, key) in relos.iter().zip(keys) {
        let key = key.ok_or(RelocationError::FunctionNotFound)?;
        let function = functions
            .get_mut(&key)
            .ok_or(RelocationError::FunctionNotFound)?;

        let instructions = &mut function.instructions;
        let ins_index = (rel.ins_offset - function.section_offset) / size_of::<bpf_insn>();
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

        let matches = if matches!(rel.kind, RelocationKind::TypeIdLocal) {
            // we don't need to look at target types to relocate this value
            Vec::new()
        } else {
            // `candidate_groups` has a group for every relocation that gets here.
            let group = groups[&(key, rel.type_id)];
            let candidates = match lists.pruned.entry(group) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let found = match lists.found.entry(rel.type_id) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => {
                            entry.insert(find_candidates(local_ty, local_name, target_btf)?)
                        }
                    };
                    entry.insert(found.clone())
                }
            };

            let mut matches = Vec::new();
            for candidate in &*candidates {
                if let Some(candidate_spec) = match_candidate(&local_spec, candidate)? {
                    let comp_rel =
                        ComputedRelocation::new(rel, &local_spec, Some(&candidate_spec))?;
                    matches.push((candidate.name.clone(), candidate_spec, comp_rel));
                }
            }

            // A program runs against one target layout, so keep only the candidates that
            // matched for the rest of the group: the functions that some program links
            // together, through the calls and text relocations that the linker follows. Later
            // relocations can't pick another type of the same name. If none matched, keep them
            // all, as libbpf does. Functions that no program links together prune apart, as aya
            // relocates every program in the object, loaded or not, and a helper without a
            // relocation of the type doesn't join the programs that call it.
            if !matches.is_empty() {
                candidates.retain(|candidate| {
                    matches
                        .iter()
                        .any(|(_, spec, _)| spec.root_type_id == candidate.type_id)
                });
            }

            matches
        };

        let comp_rel = if matches.is_empty() {
            // there are no candidate matches and therefore no target_spec. This might mean
            // that matching failed, or that the relocation can be applied looking at local
            // types only (eg with EnumVariantExists, FieldExists etc)
            ComputedRelocation::new(rel, &local_spec, None)?
        } else {
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
                    ) && cand_comp_rel_target.value != target_comp_rel_target.value
                    {
                        return Some(cand_name);
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
        };

        comp_rel.apply(function, rel, local_btf, target_btf)?;
    }

    Ok(())
}

fn flavorless_name(name: &str) -> &str {
    name.split_once("___").map_or(name, |x| x.0)
}

// Whether an array access may go past the declared element count.
fn is_flex_array(btf: &Btf, array_len: u32, parent: &Accessor) -> Result<bool, BtfError> {
    // A zero-length array is a flexible array member, whose real length is only known at runtime,
    // when it is the last field of its parent struct; anywhere else it holds no elements at all.
    if array_len != 0 {
        return Ok(false);
    }
    let Accessor {
        type_id,
        index,
        name: _,
    } = parent;
    let parent_ty = btf.type_by_id(*type_id)?;
    Ok(match parent_ty {
        BtfType::Struct(s) => *index == s.members.len() - 1,
        _ => false,
    })
}

fn find_candidates<'target>(
    local_ty: &BtfType,
    local_name: &str,
    target_btf: &'target Btf,
) -> Result<Vec<Candidate<'target>>, BtfError> {
    let mut candidates = Vec::new();
    let local_name = flavorless_name(local_name);
    let local_kind = local_ty.kind();

    // When we downgrade an ENUM64 to a UNION we still want to match the enum
    // definition recorded in the target BTF. If the sanitized type has a
    // fallback, allow ENUM64 candidates through the kind check.
    //
    // Note that we do not sanitize the target BTF so the kinds will not
    // naturally match!
    let allow_enum_match = matches!(
        local_ty,
        BtfType::Union(Union {
            enum64_fallback: Some(_),
            ..
        })
    );

    for (type_id, ty) in target_btf.types().enumerate().filter(|(_, ty)| {
        let candidate_kind = ty.kind();
        candidate_kind == local_kind || (allow_enum_match && candidate_kind == BtfKind::Enum64)
    }) {
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
    local_spec: &AccessSpec<'_>,
    candidate: &Candidate<'target>,
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
                Ok(Some(target_spec))
            } else {
                Ok(None)
            }
        }
        RelocationKind::EnumVariantExists | RelocationKind::EnumVariantValue => {
            let target_id = candidate.btf.resolve_type(candidate.type_id)?;

            let match_enum = |iterator: &mut dyn Iterator<Item = u32>| {
                // the first accessor is guaranteed to have a name by construction
                let local_variant_name = local_spec.accessors[0].name.as_ref().unwrap();

                for (index, name_offset) in iterator.enumerate() {
                    let target_variant_name = candidate.btf.string_at(name_offset)?;
                    if flavorless_name(local_variant_name) == flavorless_name(&target_variant_name)
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
                Ok(None)
            };

            match candidate.btf.type_by_id(target_id)? {
                BtfType::Enum(en) => {
                    match_enum(&mut en.variants.iter().map(|member| member.name_offset))
                }
                BtfType::Enum64(en) => {
                    match_enum(&mut en.variants.iter().map(|member| member.name_offset))
                }
                BtfType::Union(Union {
                    enum64_fallback: Some(fallback),
                    ..
                }) => {
                    // Local ENUM64 types become UNION types during sanitisation; the fallback retains
                    // their original variant names so we can line them up with target enums.
                    match_enum(&mut fallback.variants.iter().map(|variant| variant.name_offset))
                }
                _ => Ok(None),
            }
        }
        RelocationKind::FieldByteOffset
        | RelocationKind::FieldByteSize
        | RelocationKind::FieldExists
        | RelocationKind::FieldSigned
        | RelocationKind::FieldLShift64
        | RelocationKind::FieldRShift64 => {
            let mut target_id = candidate.type_id;
            for accessor in &local_spec.accessors {
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
                    // The root has no parent; subsequent unnamed accessors index arrays.
                    if let Some(parent) = target_spec.accessors.last() {
                        let target_ty = candidate.btf.type_by_id(target_id)?;
                        let BtfType::Array(Array { array, .. }) = target_ty else {
                            return Ok(None);
                        };

                        let is_flex = is_flex_array(candidate.btf, array.len, parent)?;
                        if !is_flex && accessor.index >= array.len as usize {
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
            Ok(Some(target_spec))
        }
    }
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
        BtfType::Struct(s) => &s.members[local_accessor.index],
        BtfType::Union(u) => &u.members[local_accessor.index],
        #[expect(clippy::unreachable, reason = "accessors are validated upfront")]
        local_ty => unreachable!("unexpected type {:?}", local_ty),
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
            }
            return Ok(None);
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
    ) -> Result<Self, RelocationError> {
        let parts = spec
            .split(':')
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(
                |ParseIntError { .. }| RelocationError::InvalidAccessString {
                    access_str: spec.to_string(),
                },
            )?;

        let mut type_id = btf.resolve_type(root_type_id)?;
        let ty = btf.type_by_id(type_id)?;
        let root = (type_id, ty);

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
            RelocationKind::EnumVariantExists | RelocationKind::EnumVariantValue => {
                let index = || match parts.as_slice() {
                    [index] => Ok(*index),
                    _ => Err(RelocationError::InvalidAccessString {
                        access_str: spec.to_string(),
                    }),
                };

                let (n_variants, name_offset, index) = match ty {
                    BtfType::Enum(en) => {
                        let index = index()?;
                        (
                            en.variants.len(),
                            en.variants.get(index).map(|v| v.name_offset),
                            index,
                        )
                    }
                    BtfType::Enum64(en) => {
                        let index = index()?;
                        (
                            en.variants.len(),
                            en.variants.get(index).map(|v| v.name_offset),
                            index,
                        )
                    }
                    BtfType::Union(Union {
                        enum64_fallback: Some(fallback),
                        ..
                    }) => {
                        let index = index()?;
                        (
                            fallback.variants.len(),
                            fallback.variants.get(index).map(|v| v.name_offset),
                            index,
                        )
                    }
                    _ => {
                        return Err(RelocationError::InvalidRelocationKindForType {
                            relocation_number: relocation.number,
                            relocation_kind: format!("{:?}", relocation.kind),
                            type_kind: format!("{:?}", ty.kind()),
                            error: "enum relocation on non-enum type",
                        });
                    }
                };
                let name_offset =
                    name_offset.ok_or_else(|| RelocationError::InvalidAccessIndex {
                        access_path: access_path(btf, root, []),
                        spec: spec.to_string(),
                        index,
                        len: n_variants,
                        error: "tried to access nonexistent enum variant",
                    })?;
                let name = btf.string_at(name_offset)?;
                let accessors = vec![Accessor {
                    type_id,
                    index,
                    name: Some(name.to_string()),
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

            RelocationKind::FieldByteOffset
            | RelocationKind::FieldByteSize
            | RelocationKind::FieldExists
            | RelocationKind::FieldSigned
            | RelocationKind::FieldLShift64
            | RelocationKind::FieldRShift64 => {
                // Keep the current accessor separate so array accesses always have a parent.
                let mut accessor = Accessor {
                    type_id,
                    index: parts[0],
                    name: None,
                };
                let mut accessors = Vec::new();
                let size = btf.type_size(type_id)?;
                let mut bit_offset = accessor.index * size;
                for index in parts.iter().skip(1).copied() {
                    type_id = btf.resolve_type(type_id)?;
                    let ty = btf.type_by_id(type_id)?;

                    let next_accessor = match ty {
                        BtfType::Struct(Struct { members, .. })
                        | BtfType::Union(Union { members, .. }) => {
                            if index >= members.len() {
                                return Err(RelocationError::InvalidAccessIndex {
                                    access_path: access_path(
                                        btf,
                                        root,
                                        accessors.iter().chain([&accessor]),
                                    ),
                                    spec: spec.to_string(),
                                    index,
                                    len: members.len(),
                                    error: "out of bounds struct or union access",
                                });
                            }

                            let member = &members[index];
                            bit_offset += ty.member_bit_offset(member).unwrap();

                            let next_accessor = if member.name_offset != 0 {
                                let name = btf.string_at(member.name_offset)?;
                                Some(Accessor {
                                    type_id,
                                    index,
                                    name: Some(name.to_string()),
                                })
                            } else {
                                None
                            };

                            type_id = member.btf_type;
                            next_accessor
                        }

                        BtfType::Array(Array { array, .. }) => {
                            type_id = btf.resolve_type(array.element_type)?;
                            let is_flex = is_flex_array(btf, array.len, &accessor)?;
                            if !is_flex && index >= array.len as usize {
                                return Err(RelocationError::InvalidAccessIndex {
                                    access_path: access_path(
                                        btf,
                                        root,
                                        accessors.iter().chain([&accessor]),
                                    ),
                                    spec: spec.to_string(),
                                    index,
                                    len: array.len as usize,
                                    error: "array index out of bounds",
                                });
                            }
                            let size = btf.type_size(type_id)?;
                            bit_offset += index * size * 8;
                            Some(Accessor {
                                type_id,
                                index,
                                name: None,
                            })
                        }
                        rel_kind => {
                            return Err(RelocationError::InvalidRelocationKindForType {
                                relocation_number: relocation.number,
                                relocation_kind: format!("{rel_kind:?}"),
                                type_kind: format!("{:?}", ty.kind()),
                                error: "field relocation on a type that doesn't have fields",
                            });
                        }
                    };
                    if let Some(next_accessor) = next_accessor {
                        accessors.push(accessor);
                        accessor = next_accessor;
                    }
                }
                accessors.push(accessor);

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

fn access_path<'a>(
    btf: &Btf,
    (type_id, ty): (u32, &BtfType),
    accessors: impl IntoIterator<Item = &'a Accessor>,
) -> String {
    let mut path = btf
        .err_type_name(ty)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("<{:?} #{type_id}>", ty.kind()));
    for (position, accessor) in accessors.into_iter().enumerate() {
        let Accessor {
            type_id: _,
            index,
            name,
        } = accessor;
        match name {
            Some(name) => {
                path.push('.');
                path.push_str(name);
            }
            None => {
                if position != 0 || *index != 0 {
                    path.push('[');
                    path.push_str(&index.to_string());
                    path.push(']');
                }
            }
        }
    }
    path
}

/// The candidate target types for the local types of an object.
#[derive(Default)]
struct CandidateLists<'target> {
    /// All the candidates found in the target BTF for each local type id.
    found: HashMap<u32, Vec<Candidate<'target>>>,
    /// The candidates left for each group of `Object::candidate_groups`. A group holds
    /// relocations of one local type only.
    pruned: HashMap<usize, Vec<Candidate<'target>>>,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Copy, Debug)]
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
        local_spec: &AccessSpec<'_>,
        target_spec: Option<&AccessSpec<'_>>,
    ) -> Result<Self, RelocationError> {
        let ret = match rel.kind {
            RelocationKind::FieldByteOffset
            | RelocationKind::FieldByteSize
            | RelocationKind::FieldExists
            | RelocationKind::FieldSigned
            | RelocationKind::FieldLShift64
            | RelocationKind::FieldRShift64 => Self {
                local: Self::compute_field_relocation(rel, Some(local_spec))?,
                target: Self::compute_field_relocation(rel, target_spec).ok(),
            },
            RelocationKind::TypeIdLocal
            | RelocationKind::TypeIdTarget
            | RelocationKind::TypeExists
            | RelocationKind::TypeSize => Self {
                local: Self::compute_type_relocation(rel, local_spec, target_spec)?,
                target: Self::compute_type_relocation(rel, local_spec, target_spec).ok(),
            },
            RelocationKind::EnumVariantExists | RelocationKind::EnumVariantValue => Self {
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
        let ins_index = (rel.ins_offset - function.section_offset) / size_of::<bpf_insn>();
        let ins =
            instructions
                .get_mut(ins_index)
                .ok_or(RelocationError::InvalidInstructionIndex {
                    index: rel.ins_offset,
                    num_instructions,
                    relocation_number: rel.number,
                })?;

        let Some(target) = self.target.as_ref() else {
            let is_ld_imm64 = ins.code == (BPF_LD | BPF_DW) as u8;

            poison_insn(ins);

            if is_ld_imm64 {
                let next_ins = instructions.get_mut(ins_index + 1).ok_or(
                    RelocationError::InvalidInstructionIndex {
                        index: (ins_index + 1) * size_of::<bpf_insn>(),
                        num_instructions,
                        relocation_number: rel.number,
                    },
                )?;

                poison_insn(next_ins);
            }

            return Ok(());
        };

        let class = u32::from(ins.code & 0x07);

        let target_value = target.value;

        match class {
            BPF_ALU | BPF_ALU64 => {
                let src_reg = ins.src_reg();
                if src_reg != BPF_K as u8 {
                    return Err(RelocationError::InvalidInstruction {
                        relocation_number: rel.number,
                        index: ins_index,
                        error: format!("invalid src_reg={src_reg:x} expected {BPF_K:x}").into(),
                    });
                }

                ins.imm = target_value as i32;
            }
            BPF_LDX | BPF_ST | BPF_STX => {
                if target_value > i16::MAX as u64 {
                    return Err(RelocationError::InvalidInstruction {
                        relocation_number: rel.number,
                        index: ins_index,
                        error: format!("value `{target_value}` overflows 16 bits offset field")
                            .into(),
                    });
                }

                ins.off = target_value as i16;

                if self.local.size != target.size {
                    let local_ty = local_btf.type_by_id(self.local.type_id.unwrap())?;
                    let target_ty = target_btf.type_by_id(target.type_id.unwrap())?;
                    let unsigned = |info: u32| ((info >> 24) & 0x0F) & BTF_INT_SIGNED == 0;
                    match (local_ty, target_ty) {
                        (BtfType::Ptr(_), BtfType::Ptr(_)) => {}
                        (BtfType::Int(local), BtfType::Int(target))
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
                                )
                                .into(),
                            });
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
                                error: format!("invalid target size {size}").into(),
                            });
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
                    error: format!("invalid instruction class {class:x}").into(),
                });
            }
        }

        Ok(())
    }

    fn compute_enum_relocation(
        rel: &Relocation,
        spec: Option<&AccessSpec<'_>>,
    ) -> Result<ComputedRelocationValue, RelocationError> {
        let value = match (rel.kind, spec) {
            (RelocationKind::EnumVariantExists, spec) => u64::from(spec.is_some()),
            (RelocationKind::EnumVariantValue, Some(spec)) => {
                let accessor = &spec.accessors[0];
                match spec.btf.type_by_id(accessor.type_id)? {
                    BtfType::Enum(en) => {
                        let value = en.variants[accessor.index].value;
                        if en.is_signed() {
                            value as i32 as u64
                        } else {
                            u64::from(value)
                        }
                    }
                    BtfType::Enum64(en) => {
                        let variant = &en.variants[accessor.index];
                        (u64::from(variant.value_high) << 32) | u64::from(variant.value_low)
                    }
                    BtfType::Union(Union {
                        enum64_fallback: Some(fallback),
                        ..
                    }) => {
                        let variant = &fallback.variants[accessor.index];
                        if fallback.signed {
                            (variant.value as i64) as u64
                        } else {
                            variant.value
                        }
                    }
                    // candidate selection ensures that rel_kind == local_kind == target_kind
                    #[expect(clippy::unreachable, reason = "candidate selection enforces this")]
                    typ => unreachable!("unexpected type {typ:?}"),
                }
            }
            _ => {
                return Err(RelocationError::MissingTargetDefinition {
                    kind: rel.kind,
                    type_id: rel.type_id,
                    ins_index: rel.ins_offset / size_of::<bpf_insn>(),
                });
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
        spec: Option<&AccessSpec<'_>>,
    ) -> Result<ComputedRelocationValue, RelocationError> {
        if matches!(rel.kind, RelocationKind::FieldExists) {
            // this is the bpf_preserve_field_info(member_access, FIELD_EXISTENCE) case. If we
            // managed to build a spec, it means the field exists.
            return Ok(ComputedRelocationValue {
                value: u64::from(spec.is_some()),
                size: 0,
                type_id: None,
            });
        }

        let Some(spec) = spec else {
            return Err(RelocationError::MissingTargetDefinition {
                kind: rel.kind,
                type_id: rel.type_id,
                ins_index: rel.ins_offset / size_of::<bpf_insn>(),
            });
        };

        let accessor = spec.accessors.last().unwrap();
        if accessor.name.is_none() {
            // the last accessor is unnamed, meaning that this is an array access
            return match rel.kind {
                RelocationKind::FieldByteOffset => Ok(ComputedRelocationValue {
                    value: (spec.bit_offset / 8) as u64,
                    size: spec.btf.type_size(accessor.type_id)? as u32,
                    type_id: Some(accessor.type_id),
                }),
                RelocationKind::FieldByteSize => Ok(ComputedRelocationValue {
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
                        error: "invalid relocation kind for array type",
                    });
                }
            };
        }

        let ty = spec.btf.type_by_id(accessor.type_id)?;
        let (ll_ty, member) = match ty {
            BtfType::Struct(t) => (ty, &t.members[accessor.index]),
            BtfType::Union(t) => (ty, &t.members[accessor.index]),
            _ => {
                return Err(RelocationError::InvalidRelocationKindForType {
                    relocation_number: rel.number,
                    relocation_kind: format!("{:?}", rel.kind),
                    type_kind: format!("{:?}", ty.kind()),
                    error: "field relocation on a type that doesn't have fields",
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

        match rel.kind {
            RelocationKind::FieldByteOffset => {
                value.value = u64::from(byte_off);
                if !is_bitfield {
                    value.size = byte_size;
                    value.type_id = Some(member_type_id);
                }
            }
            RelocationKind::FieldByteSize => {
                value.value = u64::from(byte_size);
            }
            RelocationKind::FieldSigned => match member_ty {
                BtfType::Enum(en) => value.value = u64::from(en.is_signed()),
                BtfType::Enum64(en) => value.value = u64::from(en.is_signed()),
                BtfType::Int(i) => value.value = i.encoding() as u64 & IntEncoding::Signed as u64,
                _ => (),
            },
            RelocationKind::FieldLShift64 => {
                value.value = cfg_select! {
                    target_endian = "little" => {
                        64 - u64::from(bit_off + bit_size - byte_off * 8)
                    }
                    target_endian = "big" => {
                        u64::from((8 - byte_size) * 8 + (bit_off - byte_off * 8))
                    }
                }
            }
            RelocationKind::FieldRShift64 => {
                value.value = 64 - u64::from(bit_size);
            }
            kind @ (RelocationKind::FieldExists
            | RelocationKind::TypeIdLocal
            | RelocationKind::TypeIdTarget
            | RelocationKind::TypeExists
            | RelocationKind::TypeSize
            | RelocationKind::EnumVariantExists
            | RelocationKind::EnumVariantValue) => {
                #[expect(
                    clippy::unreachable,
                    reason = "unexpected relocation kinds indicate an internal bug"
                )]
                {
                    unreachable!("unexpected relocation kind {:?}", kind)
                }
            }
        }

        Ok(value)
    }

    fn compute_type_relocation(
        rel: &Relocation,
        local_spec: &AccessSpec<'_>,
        target_spec: Option<&AccessSpec<'_>>,
    ) -> Result<ComputedRelocationValue, RelocationError> {
        let value = match (rel.kind, target_spec) {
            (RelocationKind::TypeIdLocal, _) => u64::from(local_spec.root_type_id),
            (RelocationKind::TypeIdTarget, Some(target_spec)) => {
                u64::from(target_spec.root_type_id)
            }
            (RelocationKind::TypeExists, target_spec) => u64::from(target_spec.is_some()),
            (RelocationKind::TypeSize, Some(target_spec)) => {
                target_spec.btf.type_size(target_spec.root_type_id)? as u64
            }
            _ => {
                return Err(RelocationError::MissingTargetDefinition {
                    kind: rel.kind,
                    type_id: rel.type_id,
                    ins_index: rel.ins_offset / size_of::<bpf_insn>(),
                });
            }
        };

        Ok(ComputedRelocationValue {
            value,
            size: 0,
            type_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use object::{Endianness, SymbolKind};
    use rstest::rstest;

    use super::*;
    use crate::{
        Program, ProgramSection,
        btf::{
            BtfExt, Int,
            info::{FuncSecInfo, LineSecInfo},
        },
        generated::{BPF_EXIT, BPF_IMM, BPF_MEM, BPF_PSEUDO_CALL, BPF_PSEUDO_FUNC, btf_ext_header},
        relocation::Symbol,
        util::bytes_of,
    };

    // Access strings of the members of the local `e1000_adapter` built by `relocate`.
    const PTP_DELTA: &str = "0:0";
    const GOTCL_OLD: &str = "0:1";
    const MISSING: &str = "0:2";

    fn add_struct(btf: &mut Btf, name: &str, int_id: u32, members: &[&str]) -> u32 {
        let name_offset = btf.add_string(name);
        let members = members
            .iter()
            .enumerate()
            .map(|(index, member)| BtfMember {
                name_offset: btf.add_string(member),
                btf_type: int_id,
                offset: index as u32 * 64,
            })
            .collect::<Vec<_>>();
        let size = members.len() as u32 * 8;
        btf.add_type(BtfType::Struct(Struct::new(name_offset, members, size)))
    }

    /// Relocates programs that each load the members named by one slice of access strings
    /// from the local `e1000_adapter`, one `FieldByteOffset` relocation per member. The
    /// programs are functions placed one after another in one section. Each `(caller, callee)`
    /// pair in `calls` indexes `programs` and adds a pseudo-call to the callee at the end of
    /// the caller. Every program ends with an exit, so that one without accesses or calls
    /// still has an instruction. The programs that no call targets are the ones that the
    /// object registers, which the linker starts from.
    ///
    /// The target BTF holds two structs named `e1000_adapter`, like vmlinux does for the
    /// e1000 and e1000e drivers. `gotcl_old` is only in the first, at byte 16, and `ptp_delta`
    /// is only in the second, at byte 32. `missing` is in neither.
    ///
    /// Returns the offset each member access ends up with, or `None` if it was poisoned.
    fn relocate(programs: &[&[&str]], calls: &[(usize, usize)]) -> Vec<Vec<Option<i16>>> {
        relocate_in_sections(programs, &vec![0; programs.len()], calls, &[], None)
    }

    /// Adds a relocation of `size` bits at the byte `offset` of section `section_index`,
    /// against the symbol of the section `target`.
    fn relocate_to_section(
        obj: &mut Object,
        section_index: SectionIndex,
        offset: u64,
        size: u8,
        target: usize,
    ) {
        obj.relocations.entry(section_index).or_default().insert(
            offset,
            crate::relocation::Relocation {
                offset,
                size,
                symbol_index: target,
            },
        );
        obj.symbol_table.insert(
            target,
            Symbol {
                index: target,
                section_index: Some(target),
                name: None,
                address: 0,
                size: 0,
                is_definition: true,
                kind: SymbolKind::Section,
                is_weak: false,
            },
        );
    }

    /// Like `relocate`, but puts program `index` in section `sections[index]`, and relocates
    /// the sections in the order of their indices. A call to a program in another section is
    /// an `R_BPF_64_32` relocation against the section of the callee, like the one that the
    /// compiler emits for a call to a function in `.text`. Each `(referrer, target)` pair in
    /// `references` indexes `programs` and adds, after the calls of the referrer, an
    /// `ld_imm64` of the address of the target through an `R_BPF_64_64` relocation against the
    /// section of the target, like the one that the compiler emits for a callback passed to
    /// `bpf_loop`. The object registers the programs that `entries` lists, or when it is
    /// `None`, the ones that no call or reference targets.
    fn relocate_in_sections(
        programs: &[&[&str]],
        sections: &[usize],
        calls: &[(usize, usize)],
        references: &[(usize, usize)],
        entries: Option<&[usize]>,
    ) -> Vec<Vec<Option<i16>>> {
        let mut local_btf = Btf::new();
        let u64_name = local_btf.add_string("__u64");
        let u64_id = local_btf.add_type(BtfType::Int(Int::new(u64_name, 8, IntEncoding::None, 0)));
        let local_id = add_struct(
            &mut local_btf,
            "e1000_adapter",
            u64_id,
            &["ptp_delta", "gotcl_old", "missing"],
        );

        let mut target_btf = Btf::new();
        let u64_name = target_btf.add_string("long unsigned int");
        let u64_id = target_btf.add_type(BtfType::Int(Int::new(u64_name, 8, IntEncoding::None, 0)));
        add_struct(
            &mut target_btf,
            "e1000_adapter",
            u64_id,
            &["pad0", "pad1", "gotcl_old"],
        );
        add_struct(
            &mut target_btf,
            "e1000_adapter",
            u64_id,
            &["pad0", "pad1", "pad2", "pad3", "ptp_delta"],
        );

        let mut obj = Object::new(Endianness::default(), CString::new("GPL").unwrap(), None);
        let section_count = sections.iter().max().map_or(0, |last| last + 1);
        let section_names = (0..section_count)
            .map(|section| format!("kprobe{section}"))
            .collect::<Vec<_>>();
        // The `bpf_core_relo` records of each section.
        let mut core_relos = vec![Vec::new(); section_count];
        // The index of the first instruction of each program in its section: its accesses,
        // then its calls, then its references of two instructions each, then the exit.
        let mut starts = Vec::new();
        let mut instruction_counts = vec![0; section_count];
        for (index, accesses) in programs.iter().enumerate() {
            let instruction_count = &mut instruction_counts[sections[index]];
            starts.push(*instruction_count);
            *instruction_count += accesses.len()
                + calls.iter().filter(|(c, _)| *c == index).count()
                + 2 * references.iter().filter(|(r, _)| *r == index).count()
                + 1;
        }
        let mut section_offsets = Vec::new();
        for (index, accesses) in programs.iter().enumerate() {
            let section_index = SectionIndex(sections[index]);
            let section_offset = starts[index] * size_of::<bpf_insn>();
            for (insn_index, access) in accesses.iter().enumerate() {
                core_relos[sections[index]].push([
                    (section_offset + insn_index * size_of::<bpf_insn>()) as u32,
                    local_id,
                    local_btf.add_string(access),
                    bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET,
                ]);
            }

            let mut instructions = accesses
                .iter()
                .map(|_| bpf_insn {
                    code: (BPF_LDX | BPF_MEM | BPF_DW) as u8,
                    _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                    off: 0,
                    imm: 0,
                })
                .collect::<Vec<_>>();
            for (call_index, (_, callee)) in calls
                .iter()
                .filter(|(caller, _)| *caller == index)
                .enumerate()
            {
                let call_at = starts[index] + accesses.len() + call_index;
                let imm = if sections[*callee] == sections[index] {
                    starts[*callee] as i32 - call_at as i32 - 1
                } else {
                    // The linker finds the callee at the address of the section symbol plus
                    // `(imm + 1) * 8`.
                    relocate_to_section(
                        &mut obj,
                        section_index,
                        (call_at * size_of::<bpf_insn>()) as u64,
                        32,
                        sections[*callee],
                    );
                    starts[*callee] as i32 - 1
                };
                instructions.push(bpf_insn {
                    code: (BPF_JMP | BPF_CALL) as u8,
                    _bitfield_1: bpf_insn::new_bitfield_1(0, BPF_PSEUDO_CALL as u8),
                    off: 0,
                    imm,
                });
            }
            let first_reference =
                starts[index] + accesses.len() + calls.iter().filter(|(c, _)| *c == index).count();
            for (reference_index, (_, target)) in references
                .iter()
                .filter(|(referrer, _)| *referrer == index)
                .enumerate()
            {
                // The linker finds the target at the address of the section symbol plus `imm`.
                relocate_to_section(
                    &mut obj,
                    section_index,
                    ((first_reference + 2 * reference_index) * size_of::<bpf_insn>()) as u64,
                    64,
                    sections[*target],
                );
                instructions.push(bpf_insn {
                    code: (BPF_LD | BPF_IMM | BPF_DW) as u8,
                    _bitfield_1: bpf_insn::new_bitfield_1(0, BPF_PSEUDO_FUNC as u8),
                    off: 0,
                    imm: (starts[*target] * size_of::<bpf_insn>()) as i32,
                });
                // The second half of the `ld_imm64`.
                instructions.push(bpf_insn {
                    code: 0,
                    _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                    off: 0,
                    imm: 0,
                });
            }
            instructions.push(bpf_insn {
                code: (BPF_JMP | BPF_EXIT) as u8,
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });

            section_offsets.push(section_offset);
            obj.functions.insert(
                (section_index.0, section_offset as u64),
                Function {
                    address: section_offset as u64,
                    name: format!("prog{index}"),
                    section_index,
                    section_offset,
                    instructions,
                    func_info: FuncSecInfo::default(),
                    line_info: LineSecInfo::default(),
                    func_info_rec_size: 0,
                    line_info_rec_size: 0,
                },
            );
        }
        let entries = entries.map_or_else(
            || {
                (0..programs.len())
                    .filter(|index| {
                        !calls
                            .iter()
                            .chain(references)
                            .any(|(_, target)| target == index)
                    })
                    .collect()
            },
            <[usize]>::to_vec,
        );
        for index in entries {
            obj.programs.insert(
                format!("prog{index}"),
                Program {
                    license: CString::new("GPL").unwrap(),
                    kernel_version: None,
                    section: ProgramSection::KProbe,
                    section_index: sections[index],
                    address: section_offsets[index] as u64,
                },
            );
        }

        // The `.BTF.ext` core relocation info: the record size, then for each section its name,
        // the number of `bpf_core_relo` records and the records.
        let mut core_relo_info = vec![size_of::<bpf_core_relo>() as u32];
        for (section, (name, relos)) in section_names.iter().zip(&core_relos).enumerate() {
            core_relo_info.extend([local_btf.add_string(name), relos.len() as u32]);
            core_relo_info.extend(relos.iter().flatten());
            obj.section_infos
                .insert(name.clone(), (SectionIndex(section), 0));
        }

        let header = btf_ext_header {
            magic: 0xeb9f,
            version: 1,
            flags: 0,
            hdr_len: size_of::<btf_ext_header>() as u32,
            func_info_off: 0,
            func_info_len: 0,
            line_info_off: 0,
            line_info_len: 0,
            core_relo_off: 0,
            core_relo_len: (core_relo_info.len() * size_of::<u32>()) as u32,
        };
        // Safety: `btf_ext_header` is POD.
        let mut btf_ext_data = unsafe { bytes_of(&header) }.to_vec();
        btf_ext_data.extend(core_relo_info.iter().flat_map(|word| word.to_ne_bytes()));
        obj.btf_ext =
            Some(BtfExt::parse(&btf_ext_data, Endianness::default(), &local_btf).unwrap());
        obj.btf = Some(local_btf);

        obj.relocate_btf(&target_btf).unwrap();

        programs
            .iter()
            .zip(sections)
            .zip(section_offsets)
            .map(|((accesses, section), section_offset)| {
                obj.functions[&(*section, section_offset as u64)]
                    .instructions
                    .iter()
                    .take(accesses.len())
                    .map(|ins| {
                        let poisoned =
                            ins.code == (BPF_JMP | BPF_CALL) as u8 && ins.imm == 0xBAD2310;
                        (!poisoned).then_some(ins.off)
                    })
                    .collect()
            })
            .collect()
    }

    // A program only runs against one target layout, so once a relocation has picked the
    // struct holding one member, the ones that exist only in the other struct are poisoned.
    #[rstest]
    #[case::classic_first(&[GOTCL_OLD, PTP_DELTA], &[Some(16), None])]
    #[case::extended_first(&[PTP_DELTA, GOTCL_OLD], &[Some(32), None])]
    fn relocations_of_a_type_share_candidates(
        #[case] accesses: &[&str],
        #[case] expected: &[Option<i16>],
    ) {
        assert_eq!(relocate(&[accesses], &[]), [expected]);
    }

    // A relocation that no candidate matches doesn't narrow the candidates.
    #[test]
    fn unmatched_relocation_keeps_candidates() {
        assert_eq!(
            relocate(&[&[MISSING, GOTCL_OLD, PTP_DELTA]], &[]),
            [[None, Some(16), None]],
        );
    }

    // Every program is relocated whether or not it gets loaded, so the relocations of one
    // program don't narrow the candidates of another, even in the same section.
    #[test]
    fn relocations_in_different_programs_keep_candidates() {
        assert_eq!(
            relocate(&[&[GOTCL_OLD], &[PTP_DELTA]], &[]),
            [vec![Some(16)], vec![Some(32)]],
        );
    }

    // A callee is copied into its callers when the programs are linked, so a function and the
    // functions it calls run against the same layout: the relocations of one narrow the
    // candidates of the others, whichever is relocated first.
    #[test]
    fn relocations_in_called_functions_share_candidates() {
        assert_eq!(
            relocate(&[&[GOTCL_OLD], &[PTP_DELTA]], &[(0, 1)]),
            [vec![Some(16)], vec![None]],
        );
    }

    #[test]
    fn relocations_in_called_functions_share_candidates_callee_first() {
        assert_eq!(
            relocate(&[&[PTP_DELTA], &[GOTCL_OLD]], &[(1, 0)]),
            [vec![Some(32)], vec![None]],
        );
    }

    // The functions of a chain of calls share candidates, not only the neighbors.
    #[test]
    fn relocations_in_a_chain_of_calls_share_candidates() {
        assert_eq!(
            relocate(&[&[GOTCL_OLD], &[MISSING], &[PTP_DELTA]], &[(0, 1), (1, 2)]),
            [vec![Some(16)], vec![None], vec![None]],
        );
    }

    // The subprogram is relocated once and copied into both programs, so the programs that
    // call it run against the same layout too.
    #[test]
    fn relocations_in_programs_sharing_a_subprogram_share_candidates() {
        assert_eq!(
            relocate(&[&[GOTCL_OLD], &[PTP_DELTA], &[MISSING]], &[(0, 2), (1, 2)]),
            [vec![Some(16)], vec![None], vec![None]],
        );
    }

    // A helper that has no relocation of the type doesn't join the programs that call it, as
    // each of them is linked on its own.
    #[test]
    fn relocations_in_programs_sharing_an_unrelated_subprogram_keep_candidates() {
        assert_eq!(
            relocate(&[&[GOTCL_OLD], &[PTP_DELTA], &[]], &[(0, 2), (1, 2)]),
            [vec![Some(16)], vec![Some(32)], vec![]],
        );
    }

    // The functions that carry the relocations share candidates even when a function without
    // one sits between them.
    #[test]
    fn relocations_in_calls_through_an_unrelated_subprogram_share_candidates() {
        assert_eq!(
            relocate(&[&[GOTCL_OLD], &[], &[PTP_DELTA]], &[(0, 1), (1, 2)]),
            [vec![Some(16)], vec![], vec![None]],
        );
    }

    // A call that a relocation resolves to a function in another section links the callee into
    // the caller as well, whichever section is relocated first.
    #[test]
    fn relocations_in_functions_called_across_sections_share_candidates() {
        assert_eq!(
            relocate_in_sections(&[&[GOTCL_OLD], &[PTP_DELTA]], &[0, 1], &[(0, 1)], &[], None),
            [vec![Some(16)], vec![None]],
        );
    }

    #[test]
    fn relocations_in_functions_called_across_sections_share_candidates_callee_first() {
        assert_eq!(
            relocate_in_sections(&[&[GOTCL_OLD], &[PTP_DELTA]], &[1, 0], &[(0, 1)], &[], None),
            [vec![None], vec![Some(32)]],
        );
    }

    // The address of a function that a program takes, like a callback passed to `bpf_loop`,
    // links the function into the program as well, whichever is relocated first.
    #[test]
    fn relocations_in_referenced_functions_share_candidates() {
        assert_eq!(
            relocate_in_sections(&[&[GOTCL_OLD], &[PTP_DELTA]], &[0, 0], &[], &[(0, 1)], None),
            [vec![Some(16)], vec![None]],
        );
    }

    #[test]
    fn relocations_in_referenced_functions_share_candidates_callee_first() {
        assert_eq!(
            relocate_in_sections(&[&[PTP_DELTA], &[GOTCL_OLD]], &[0, 0], &[], &[(1, 0)], None),
            [vec![Some(32)], vec![None]],
        );
    }

    // The linker only links the functions that a program reaches, so a function that no
    // program reaches doesn't join the functions it calls, even if it calls both.
    #[test]
    fn relocations_in_functions_no_program_reaches_keep_candidates() {
        assert_eq!(
            relocate_in_sections(
                &[&[GOTCL_OLD], &[PTP_DELTA], &[], &[], &[]],
                &[0; 5],
                &[(2, 0), (2, 1), (3, 0), (4, 1)],
                &[],
                Some(&[3, 4]),
            ),
            [vec![Some(16)], vec![Some(32)], vec![], vec![], vec![]],
        );
    }

    // The functions of a section can overlap. A relocation applies to the function of the
    // previous relocation if that one holds it too, so the candidate groups have to take the
    // same function, not the first one that holds it. `f1` is a program with relocations of
    // two local types, so the groups of the types must stay apart: a group that joined them
    // would match `e1000_adapter` against the candidates of `other_struct`.
    #[test]
    fn relocations_in_overlapping_functions_resolve() {
        let mut local_btf = Btf::new();
        let u64_name = local_btf.add_string("__u64");
        let u64_id = local_btf.add_type(BtfType::Int(Int::new(u64_name, 8, IntEncoding::None, 0)));
        let adapter = add_struct(
            &mut local_btf,
            "e1000_adapter",
            u64_id,
            &["ptp_delta", "gotcl_old"],
        );
        let other = add_struct(&mut local_btf, "other_struct", u64_id, &["x"]);

        let mut target_btf = Btf::new();
        let u64_name = target_btf.add_string("long unsigned int");
        let u64_id = target_btf.add_type(BtfType::Int(Int::new(u64_name, 8, IntEncoding::None, 0)));
        add_struct(
            &mut target_btf,
            "e1000_adapter",
            u64_id,
            &["pad0", "pad1", "gotcl_old"],
        );
        add_struct(
            &mut target_btf,
            "other_struct",
            u64_id,
            &["pad0", "pad1", "pad2", "x"],
        );

        // `f0` holds the instructions 0 to 3 of the section and `f1` the instructions 2 to 5.
        let insn_size = size_of::<bpf_insn>();
        let mut obj = Object::new(Endianness::default(), CString::new("GPL").unwrap(), None);
        for (start, name) in [(0, "f0"), (2, "f1")] {
            let section_offset = start * insn_size;
            obj.functions.insert(
                (0, section_offset as u64),
                Function {
                    address: section_offset as u64,
                    name: name.into(),
                    section_index: SectionIndex(0),
                    section_offset,
                    instructions: vec![
                        bpf_insn {
                            code: (BPF_LDX | BPF_MEM | BPF_DW) as u8,
                            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                            off: 0,
                            imm: 0,
                        };
                        4
                    ],
                    func_info: FuncSecInfo::default(),
                    line_info: LineSecInfo::default(),
                    func_info_rec_size: 0,
                    line_info_rec_size: 0,
                },
            );
        }

        obj.programs.insert(
            "f1".into(),
            Program {
                license: CString::new("GPL").unwrap(),
                kernel_version: None,
                section: ProgramSection::KProbe,
                section_index: 0,
                address: (2 * insn_size) as u64,
            },
        );

        // The first relocation is in `f1` only. The second is in both, so it follows the first.
        let relos = [
            [
                (5 * insn_size) as u32,
                other,
                local_btf.add_string("0:0"),
                bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET,
            ],
            [
                (3 * insn_size) as u32,
                adapter,
                local_btf.add_string("0:1"),
                bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET,
            ],
        ];
        let mut core_relo_info = vec![size_of::<bpf_core_relo>() as u32];
        core_relo_info.extend([local_btf.add_string("kprobe0"), relos.len() as u32]);
        core_relo_info.extend(relos.iter().flatten());
        obj.section_infos
            .insert("kprobe0".into(), (SectionIndex(0), 0));
        let header = btf_ext_header {
            magic: 0xeb9f,
            version: 1,
            flags: 0,
            hdr_len: size_of::<btf_ext_header>() as u32,
            func_info_off: 0,
            func_info_len: 0,
            line_info_off: 0,
            line_info_len: 0,
            core_relo_off: 0,
            core_relo_len: (core_relo_info.len() * size_of::<u32>()) as u32,
        };
        // Safety: `btf_ext_header` is POD.
        let mut btf_ext_data = unsafe { bytes_of(&header) }.to_vec();
        btf_ext_data.extend(core_relo_info.iter().flat_map(|word| word.to_ne_bytes()));
        obj.btf_ext =
            Some(BtfExt::parse(&btf_ext_data, Endianness::default(), &local_btf).unwrap());
        obj.btf = Some(local_btf);

        obj.relocate_btf(&target_btf).unwrap();

        // Both relocations patch `f1`: the one on `other_struct::x` at its instruction 3 and
        // the one on `e1000_adapter::gotcl_old` at its instruction 1, to their byte offsets in
        // the target structs, which are 3 * 8 and 2 * 8 as `add_struct` places 8 bytes per
        // member. `f0` stays as it was.
        let offsets = |start: usize| {
            obj.functions[&(0, (start * insn_size) as u64)]
                .instructions
                .iter()
                .map(|ins| ins.off)
                .collect::<Vec<_>>()
        };
        assert_eq!(offsets(0), [0; 4]);
        assert_eq!(offsets(2), [0, 16, 0, 24]);
    }
}
