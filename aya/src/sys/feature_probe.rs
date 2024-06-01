use std::{
    cmp,
    ffi::{c_char, CString},
    mem,
    os::fd::{AsFd as _, AsRawFd as _},
    slice,
};

use assert_matches::assert_matches;
use obj::{
    btf::{BtfEnum64, Enum64},
    maps::{bpf_map_def, LegacyMap},
    EbpfSectionKind,
};

use super::{btf::bpf_load_btf, program::bpf_prog_load};
use crate::{
    generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_map_type, bpf_prog_type},
    maps::MapData,
    obj::{
        self,
        btf::{
            BtfParam, BtfType, DataSec, DataSecEntry, DeclTag, Float, Func, FuncLinkage, FuncProto,
            Int, IntEncoding, Ptr, TypeTag, Var, VarLinkage,
        },
        copy_instructions,
    },
    sys::{
        link::{bpf_link_create, LinkTarget},
        utils::fd_sys_bpf,
    },
    Btf,
};

pub(crate) fn is_prog_name_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };
    let mut name: [c_char; 16] = [0; 16];
    let cstring = CString::new("aya_name_check").unwrap();
    let name_bytes = cstring.to_bytes();
    let len = cmp::min(name.len(), name_bytes.len());
    name[..len].copy_from_slice(unsafe {
        slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, len)
    });
    u.prog_name = name;

    let prog: &[u8] = &[
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32;

    bpf_prog_load(&mut attr).is_ok()
}

pub(crate) fn is_probe_read_kernel_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0xbf, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = r10
        0x07, 0x01, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, // r1 -= 8
        0xb7, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // r2 = 8
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r3 = 0
        0x85, 0x00, 0x00, 0x00, 0x71, 0x00, 0x00, 0x00, // call 113
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT as u32;

    bpf_prog_load(&mut attr).is_ok()
}

pub(crate) fn is_perf_link_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT as u32;

    if let Ok(fd) = bpf_prog_load(&mut attr) {
        let fd = crate::MockableFd::from_fd(fd);
        let fd = fd.as_fd();
        matches!(
            // Uses an invalid target FD so we get EBADF if supported.
            bpf_link_create(fd, LinkTarget::IfIndex(u32::MAX), bpf_attach_type::BPF_PERF_EVENT, None, 0),
            // Returns EINVAL if unsupported. EBADF if supported.
            Err((_, e)) if e.raw_os_error() == Some(libc::EBADF),
        )
    } else {
        false
    }
}

pub(crate) fn is_bpf_global_data_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0x18, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ld_pseudo r1, 0x2, 0x0
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, //
        0x7a, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // stdw [r1 + 0x0], 0x2a
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let mut insns = copy_instructions(prog).unwrap();

    let map = MapData::create(
        obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                key_size: 4,
                value_size: 32,
                max_entries: 1,
                ..Default::default()
            },
            section_index: 0,
            section_kind: EbpfSectionKind::Maps,
            symbol_index: None,
            data: Vec::new(),
        }),
        "aya_global",
        None,
    );

    if let Ok(map) = map {
        insns[0].imm = map.fd().as_fd().as_raw_fd();

        let gpl = b"GPL\0";
        u.license = gpl.as_ptr() as u64;
        u.insn_cnt = insns.len() as u32;
        u.insns = insns.as_ptr() as u64;
        u.prog_type = bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32;

        bpf_prog_load(&mut attr).is_ok()
    } else {
        false
    }
}

pub(crate) fn is_bpf_cookie_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0x85, 0x00, 0x00, 0x00, 0xae, 0x00, 0x00, 0x00, // call bpf_get_attach_cookie
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_KPROBE as u32;

    bpf_prog_load(&mut attr).is_ok()
}

/// Tests whether CpuMap, DevMap and DevMapHash support program ids
pub(crate) fn is_prog_id_supported(map_type: bpf_map_type) -> bool {
    assert_matches!(
        map_type,
        bpf_map_type::BPF_MAP_TYPE_CPUMAP
            | bpf_map_type::BPF_MAP_TYPE_DEVMAP
            | bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH
    );

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_1 };

    u.map_type = map_type as u32;
    u.key_size = 4;
    u.value_size = 8; // 4 for CPU ID, 8 for CPU ID + prog ID
    u.max_entries = 1;
    u.map_flags = 0;

    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    let fd = unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr) };
    let fd = fd.map(crate::MockableFd::from_fd);
    fd.is_ok()
}

pub(crate) fn is_btf_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    btf.add_type(int_type);
    let btf_bytes = btf.to_bytes();
    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_func_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let a_name = btf.add_string("a");
    let b_name = btf.add_string("b");
    let params = vec![
        BtfParam {
            name_offset: a_name,
            btf_type: int_type_id,
        },
        BtfParam {
            name_offset: b_name,
            btf_type: int_type_id,
        },
    ];
    let func_proto = BtfType::FuncProto(FuncProto::new(params, int_type_id));
    let func_proto_type_id = btf.add_type(func_proto);

    let add = btf.add_string("inc");
    let func = BtfType::Func(Func::new(add, func_proto_type_id, FuncLinkage::Static));
    btf.add_type(func);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_func_global_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let a_name = btf.add_string("a");
    let b_name = btf.add_string("b");
    let params = vec![
        BtfParam {
            name_offset: a_name,
            btf_type: int_type_id,
        },
        BtfParam {
            name_offset: b_name,
            btf_type: int_type_id,
        },
    ];
    let func_proto = BtfType::FuncProto(FuncProto::new(params, int_type_id));
    let func_proto_type_id = btf.add_type(func_proto);

    let add = btf.add_string("inc");
    let func = BtfType::Func(Func::new(add, func_proto_type_id, FuncLinkage::Global));
    btf.add_type(func);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_datasec_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("foo");
    let var_type = BtfType::Var(Var::new(name_offset, int_type_id, VarLinkage::Static));
    let var_type_id = btf.add_type(var_type);

    let name_offset = btf.add_string(".data");
    let variables = vec![DataSecEntry {
        btf_type: var_type_id,
        offset: 0,
        size: 4,
    }];
    let datasec_type = BtfType::DataSec(DataSec::new(name_offset, variables, 4));
    btf.add_type(datasec_type);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_enum64_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("enum64");

    let enum_64_type = BtfType::Enum64(Enum64::new(
        name_offset,
        true,
        vec![BtfEnum64::new(btf.add_string("a"), 1)],
    ));
    btf.add_type(enum_64_type);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_float_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("float");
    let float_type = BtfType::Float(Float::new(name_offset, 16));
    btf.add_type(float_type);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_decl_tag_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("foo");
    let var_type = BtfType::Var(Var::new(name_offset, int_type_id, VarLinkage::Static));
    let var_type_id = btf.add_type(var_type);

    let name_offset = btf.add_string("decl_tag");
    let decl_tag = BtfType::DeclTag(DeclTag::new(name_offset, var_type_id, -1));
    btf.add_type(decl_tag);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_type_tag_supported() -> bool {
    let mut btf = Btf::new();

    let int_type = BtfType::Int(Int::new(0, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("int");
    let type_tag = BtfType::TypeTag(TypeTag::new(name_offset, int_type_id));
    let type_tag_type = btf.add_type(type_tag);

    btf.add_type(BtfType::Ptr(Ptr::new(0, type_tag_type)));

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

#[cfg(test)]
mod tests {
    use std::io;

    use aya_obj::generated::{bpf_cmd, bpf_map_type};
    use libc::{EBADF, EINVAL};

    use super::*;
    use crate::sys::{override_syscall, Syscall};

    #[test]
    fn test_perf_link_supported() {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Err((-1, io::Error::from_raw_os_error(EBADF))),
            _ => Ok(crate::MockableFd::mock_signed_fd().into()),
        });
        let supported = is_perf_link_supported();
        assert!(supported);

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Err((-1, io::Error::from_raw_os_error(EINVAL))),
            _ => Ok(crate::MockableFd::mock_signed_fd().into()),
        });
        let supported = is_perf_link_supported();
        assert!(!supported);
    }

    #[test]
    fn test_prog_id_supported() {
        override_syscall(|_call| Ok(crate::MockableFd::mock_signed_fd().into()));

        // Ensure that the three map types we can check are accepted
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_CPUMAP);
        assert!(supported);
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_DEVMAP);
        assert!(supported);
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH);
        assert!(supported);

        override_syscall(|_call| Err((-1, io::Error::from_raw_os_error(EINVAL))));
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_CPUMAP);
        assert!(!supported);
    }

    #[test]
    #[should_panic = "assertion failed: `BPF_MAP_TYPE_HASH` does not match `bpf_map_type::BPF_MAP_TYPE_CPUMAP | bpf_map_type::BPF_MAP_TYPE_DEVMAP |
bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH`"]
    fn test_prog_id_supported_reject_types() {
        is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_HASH);
    }
}
