use alloc::{string::String, vec, vec::Vec};

use bytes::BufMut as _;
use object::Endianness;

use crate::{
    generated::{bpf_func_info, bpf_line_info},
    relocation::INS_SIZE,
    util::{HashMap, bytes_of},
};

/* The func_info subsection layout:
 *   record size for struct bpf_func_info in the func_info subsection
 *   struct btf_sec_func_info for section #1
 *   a list of bpf_func_info records for section #1
 *     where struct bpf_func_info mimics one in include/uapi/linux/bpf.h
 *     but may not be identical
 *   struct btf_sec_func_info for section #2
 *   a list of bpf_func_info records for section #2
 *   ......
 */

/// A collection of [bpf_func_info] collected from the `btf_ext_info_sec` struct
/// inside the [FuncInfo] subsection.
///
/// See [BPF Type Format (BTF) — The Linux Kernel documentation](https://docs.kernel.org/bpf/btf.html)
/// for more information.
#[derive(Debug, Clone, Default)]
pub struct FuncSecInfo {
    pub(crate) _sec_name_offset: u32,
    /// The number of info entries
    pub num_info: u32,
    /// Info entries
    pub func_info: Vec<bpf_func_info>,
}

impl FuncSecInfo {
    pub(crate) fn parse(
        sec_name_offset: u32,
        num_info: u32,
        rec_size: usize,
        func_info_data: &[u8],
        endianness: Endianness,
    ) -> Self {
        let func_info = func_info_data
            .chunks(rec_size)
            .map(|data| {
                let read_u32 = if endianness == Endianness::Little {
                    u32::from_le_bytes
                } else {
                    u32::from_be_bytes
                };

                let mut offset = 0;

                // ELF instruction offsets are in bytes
                // Kernel instruction offsets are in instructions units
                // We can convert by dividing the length in bytes by INS_SIZE
                let insn_off =
                    read_u32(data[offset..offset + 4].try_into().unwrap()) / INS_SIZE as u32;
                offset += 4;
                let type_id = read_u32(data[offset..offset + 4].try_into().unwrap());

                bpf_func_info { insn_off, type_id }
            })
            .collect();

        Self {
            _sec_name_offset: sec_name_offset,
            num_info,
            func_info,
        }
    }

    /// Encodes the [bpf_func_info] entries.
    pub fn func_info_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        for l in &self.func_info {
            // Safety: bpf_func_info is POD
            buf.put(unsafe { bytes_of::<bpf_func_info>(l) })
        }
        buf
    }

    /// Returns the number of [bpf_func_info] entries.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.func_info.len()
    }
}

/// A collection of [FuncSecInfo] collected from the `func_info` subsection
/// in the `.BTF.ext` section.
///
/// See [BPF Type Format (BTF) — The Linux Kernel documentation](https://docs.kernel.org/bpf/btf.html)
/// for more information.
#[derive(Debug, Clone)]
pub struct FuncInfo {
    /// The [FuncSecInfo] subsections for some sections, referenced by section names
    pub data: HashMap<String, FuncSecInfo>,
}

impl FuncInfo {
    pub(crate) fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub(crate) fn get(&self, name: &str) -> FuncSecInfo {
        match self.data.get(name) {
            Some(d) => d.clone(),
            None => FuncSecInfo::default(),
        }
    }
}

/// A collection of [bpf_line_info] collected from the `btf_ext_info_sec` struct
/// inside the `line_info` subsection.
///
/// See [BPF Type Format (BTF) — The Linux Kernel documentation](https://docs.kernel.org/bpf/btf.html)
/// for more information.
#[derive(Debug, Clone, Default)]
pub struct LineSecInfo {
    // each line info section has a header
    pub(crate) _sec_name_offset: u32,
    /// The number of entries
    pub num_info: u32,
    // followed by one or more bpf_line_info structs
    /// The [bpf_line_info] entries
    pub line_info: Vec<bpf_line_info>,
}

impl LineSecInfo {
    pub(crate) fn parse(
        sec_name_offset: u32,
        num_info: u32,
        rec_size: usize,
        func_info_data: &[u8],
        endianness: Endianness,
    ) -> Self {
        let line_info = func_info_data
            .chunks(rec_size)
            .map(|data| {
                let read_u32 = if endianness == Endianness::Little {
                    u32::from_le_bytes
                } else {
                    u32::from_be_bytes
                };

                let mut offset = 0;

                // ELF instruction offsets are in bytes
                // Kernel instruction offsets are in instructions units
                // We can convert by dividing the length in bytes by INS_SIZE
                let insn_off =
                    read_u32(data[offset..offset + 4].try_into().unwrap()) / INS_SIZE as u32;
                offset += 4;
                let file_name_off = read_u32(data[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let line_off = read_u32(data[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let line_col = read_u32(data[offset..offset + 4].try_into().unwrap());

                bpf_line_info {
                    insn_off,
                    file_name_off,
                    line_off,
                    line_col,
                }
            })
            .collect();

        Self {
            _sec_name_offset: sec_name_offset,
            num_info,
            line_info,
        }
    }

    /// Encodes the entries.
    pub fn line_info_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        for l in &self.line_info {
            // Safety: bpf_func_info is POD
            buf.put(unsafe { bytes_of::<bpf_line_info>(l) })
        }
        buf
    }

    /// Returns the number of entries.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.line_info.len()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LineInfo {
    pub data: HashMap<String, LineSecInfo>,
}

impl LineInfo {
    pub(crate) fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub(crate) fn get(&self, name: &str) -> LineSecInfo {
        match self.data.get(name) {
            Some(d) => d.clone(),
            None => LineSecInfo::default(),
        }
    }
}
