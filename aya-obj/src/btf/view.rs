use std::borrow::Cow;

use crate::btf::{Btf, BtfError, BtfKind, BtfType, MAX_RESOLVE_DEPTH};

pub(crate) trait BtfView {
    fn type_by_id(&self, type_id: u32) -> Result<&BtfType, BtfError>;

    fn string_at(&self, offset: u32) -> Result<Cow<'_, str>, BtfError>;

    fn resolve_type(&self, root_type_id: u32) -> Result<u32, BtfError> {
        let mut type_id = root_type_id;
        for () in core::iter::repeat_n((), MAX_RESOLVE_DEPTH) {
            let ty = self.type_by_id(type_id)?;

            match ty {
                BtfType::Volatile(ty) => {
                    type_id = ty.btf_type;
                }
                BtfType::Const(ty) => {
                    type_id = ty.btf_type;
                }
                BtfType::Restrict(ty) => {
                    type_id = ty.btf_type;
                }
                BtfType::Typedef(ty) => {
                    type_id = ty.btf_type;
                }
                BtfType::TypeTag(ty) => {
                    type_id = ty.btf_type;
                }
                _ => return Ok(type_id),
            }
        }

        Err(BtfError::MaximumTypeDepthReached {
            type_id: root_type_id,
        })
    }

    fn type_name(&self, ty: &BtfType) -> Result<Cow<'_, str>, BtfError> {
        self.string_at(ty.name_offset())
    }
}

impl BtfView for Btf {
    fn type_by_id(&self, type_id: u32) -> Result<&BtfType, BtfError> {
        Self::type_by_id(self, type_id)
    }

    fn string_at(&self, offset: u32) -> Result<Cow<'_, str>, BtfError> {
        Self::string_at(self, offset)
    }
}

#[derive(Debug)]
pub(crate) struct SplitBtf<'a> {
    base: &'a Btf,
    split: &'a Btf,
    start_id: u32,
    start_str_off: u32,
}

impl<'a> SplitBtf<'a> {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "exercised by split BTF tests until module BTF resolution uses it"
        )
    )]
    pub(crate) const fn new(base: &'a Btf, split: &'a Btf) -> Self {
        Self {
            base,
            split,
            start_id: base.type_count(),
            start_str_off: base.string_len(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn start_id(&self) -> u32 {
        self.start_id
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "exercised by split BTF tests until module BTF resolution uses it"
        )
    )]
    pub(crate) fn id_by_type_name_kind_own(
        &self,
        name: &str,
        kind: BtfKind,
    ) -> Result<u32, BtfError> {
        for (local_id, ty) in self.split.types().enumerate() {
            if ty.kind() != kind {
                continue;
            }
            if self.type_name(ty)? == name {
                return Ok(self.start_id + local_id as u32 - 1);
            }
        }

        Err(BtfError::UnknownBtfTypeName {
            type_name: name.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn id_by_type_name_kind_visible(
        &self,
        name: &str,
        kind: BtfKind,
    ) -> Result<u32, BtfError> {
        self.id_by_type_name_kind_own(name, kind)
            .or_else(|_| self.base.id_by_type_name_kind(name, kind))
    }
}

impl BtfView for SplitBtf<'_> {
    fn type_by_id(&self, type_id: u32) -> Result<&BtfType, BtfError> {
        if type_id == 0 {
            return self.split.type_by_id(type_id);
        }

        // Split BTF type IDs share one visible namespace with base BTF: IDs
        // below start_id belong to base, and IDs from start_id onward are
        // translated back into the split BTF's local type ID space.
        if type_id < self.start_id {
            self.base.type_by_id(type_id)
        } else {
            self.split.type_by_id(type_id - self.start_id + 1)
        }
    }

    fn string_at(&self, offset: u32) -> Result<Cow<'_, str>, BtfError> {
        // Split BTF string offsets are visible as base string length + local
        // offset.
        if offset < self.start_str_off {
            self.base.string_at(offset)
        } else {
            self.split.string_at(offset - self.start_str_off)
        }
    }
}
