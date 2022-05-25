use std::{collections::HashMap, convert::TryInto};

use bytes::BufMut;
use object::Endianness;

use crate::{
    generated::{bpf_func_info, bpf_line_info},
    obj::relocation::INS_SIZE,
    util::bytes_of,
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
#[derive(Debug, Clone, Default)]
pub struct FuncSecInfo {
    pub _sec_name_offset: u32,
    pub num_info: u32,
    pub func_info: Vec<bpf_func_info>,
}

impl FuncSecInfo {
    pub(crate) fn parse(
        sec_name_offset: u32,
        num_info: u32,
        rec_size: usize,
        func_info_data: &[u8],
        endianness: Endianness,
    ) -> FuncSecInfo {
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

        FuncSecInfo {
            _sec_name_offset: sec_name_offset,
            num_info,
            func_info,
        }
    }

    pub(crate) fn func_info_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        for l in &self.func_info {
            // Safety: bpf_func_info is POD
            buf.put(unsafe { bytes_of::<bpf_func_info>(l) })
        }
        buf
    }

    pub(crate) fn len(&self) -> usize {
        self.func_info.len()
    }
}

#[derive(Debug, Clone)]
pub struct FuncInfo {
    pub data: HashMap<String, FuncSecInfo>,
}

impl FuncInfo {
    pub(crate) fn new() -> FuncInfo {
        FuncInfo {
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

#[derive(Debug, Clone, Default)]
pub struct LineSecInfo {
    // each line info section has a header
    pub _sec_name_offset: u32,
    pub num_info: u32,
    // followed by one or more bpf_line_info structs
    pub line_info: Vec<bpf_line_info>,
}

impl LineSecInfo {
    pub(crate) fn parse(
        sec_name_offset: u32,
        num_info: u32,
        rec_size: usize,
        func_info_data: &[u8],
        endianness: Endianness,
    ) -> LineSecInfo {
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

        LineSecInfo {
            _sec_name_offset: sec_name_offset,
            num_info,
            line_info,
        }
    }

    pub(crate) fn line_info_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        for l in &self.line_info {
            // Safety: bpf_func_info is POD
            buf.put(unsafe { bytes_of::<bpf_line_info>(l) })
        }
        buf
    }

    pub(crate) fn len(&self) -> usize {
        self.line_info.len()
    }
}

#[derive(Debug, Clone)]
pub struct LineInfo {
    pub data: HashMap<String, LineSecInfo>,
}

impl LineInfo {
    pub(crate) fn new() -> LineInfo {
        LineInfo {
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
