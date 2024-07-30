//! Tests the Info API.

use std::{fs, time::SystemTime};

use aya::{
    maps::{loaded_maps, MapError},
    programs::{loaded_programs, ProgramError, SocketFilter},
    util::KernelVersion,
    Ebpf,
};
use aya_obj::generated::{bpf_map_type, bpf_prog_type};
use libc::EINVAL;

use crate::utils::{kernel_assert, kernel_assert_eq};

const BPF_JIT_ENABLE: &str = "/proc/sys/net/core/bpf_jit_enable";

#[test]
fn list_loaded_programs() {
    // Kernels below v4.15 have been observed to have `bpf_jit_enable` disabled by default.
    let jit_enabled = enable_jit();

    // Load a program.
    // Since we are only testing the programs for their metadata, there is no need to "attach" them.
    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Ensure the `loaded_programs()` api does not panic and grab the last loaded program in the
    // iter, which should be our test program.
    let prog = match loaded_programs().last().unwrap() {
        Ok(prog) => prog,
        Err(err) => {
            if let ProgramError::SyscallError(err) = &err {
                // Skip entire test since feature not available
                if err
                    .io_error
                    .raw_os_error()
                    .is_some_and(|errno| errno == EINVAL)
                {
                    eprintln!("ignoring test completely as `loaded_programs()` is not available on the host");
                    return;
                }
            }
            panic!("{err}");
        }
    };

    // Test `bpf_prog_info` fields.
    kernel_assert_eq!(
        bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32,
        prog.program_type(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(prog.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert!(prog.tag() > 0, KernelVersion::new(4, 13, 0));
    if jit_enabled {
        kernel_assert!(prog.size_jitted() > 0, KernelVersion::new(4, 13, 0));
    }
    kernel_assert!(prog.size_translated() > 0, KernelVersion::new(4, 13, 0));
    let uptime = SystemTime::now().duration_since(prog.loaded_at()).unwrap();
    kernel_assert!(uptime.as_nanos() > 0, KernelVersion::new(4, 15, 0));
    let maps = prog.map_ids().unwrap();
    kernel_assert!(maps.is_empty(), KernelVersion::new(4, 15, 0));
    let name = prog.name_as_str().unwrap();
    kernel_assert_eq!("simple_prog", name, KernelVersion::new(4, 15, 0));
    kernel_assert!(prog.gpl_compatible(), KernelVersion::new(4, 18, 0));
    kernel_assert!(
        prog.verified_instruction_count() > 0,
        KernelVersion::new(5, 16, 0)
    );

    // We can't reliably test these fields since `0` can be interpreted as the actual value or
    // unavailable.
    prog.btf_id();

    // Ensure rest of the fields do not panic.
    prog.memory_locked().unwrap();
    prog.fd().unwrap();
}

#[test]
fn list_loaded_maps() {
    // Load a program with maps.
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Ensure the loaded_maps() api doesn't panic and retrieve loaded maps.
    let mut maps = loaded_maps().peekable();
    if let Err(err) = maps.peek().unwrap() {
        if let MapError::SyscallError(err) = &err {
            if err
                .io_error
                .raw_os_error()
                .is_some_and(|errno| errno == EINVAL)
            {
                eprintln!(
                    "ignoring test completely as `loaded_maps()` is not available on the host"
                );
                return;
            }
        }
        panic!("{err}");
    }
    let mut maps: Vec<_> = maps.filter_map(|m| m.ok()).collect();

    // There's not a good way to extract our maps of interest with load order being
    // non-deterministic. Since we are trying to be more considerate of older kernels, we should
    // only rely on v4.13 feats.
    // Expected sort order should be: `BAR`, `aya_global` (if ran local), `FOO`
    maps.sort_unstable_by_key(|m| (m.map_type(), m.id()));

    // Ensure program has the 2 maps.
    if let Ok(info) = prog.info() {
        let map_ids = info.map_ids().unwrap();
        kernel_assert_eq!(2, map_ids.len(), KernelVersion::new(4, 15, 0));

        for id in map_ids.iter() {
            assert!(
                maps.iter().any(|m| m.id() == *id),
                "expected `loaded_maps()` to have `map_ids` from program"
            );
        }
    }

    // Test `bpf_map_info` fields.
    let hash = maps.first().unwrap();
    kernel_assert_eq!(
        bpf_map_type::BPF_MAP_TYPE_HASH as u32,
        hash.map_type(),
        KernelVersion::new(4, 13, 0)
    );
    kernel_assert!(hash.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, hash.key_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(1, hash.value_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(8, hash.max_entries(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(
        "BAR",
        hash.name_as_str().unwrap(),
        KernelVersion::new(4, 15, 0)
    );

    hash.map_flags();
    hash.fd().unwrap();

    let array = maps.last().unwrap();
    kernel_assert_eq!(
        bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
        array.map_type(),
        KernelVersion::new(4, 13, 0)
    );
    kernel_assert!(array.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, array.key_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, array.value_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(10, array.max_entries(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(
        "FOO",
        array.name_as_str().unwrap(),
        KernelVersion::new(4, 15, 0)
    );

    array.map_flags();
    array.fd().unwrap();
}

/// Enable program to be JIT-compiled if not already enabled.
fn enable_jit() -> bool {
    match fs::read_to_string(BPF_JIT_ENABLE) {
        Ok(contents) => {
            if contents.chars().next().is_some_and(|c| c == '0') {
                let failed = fs::write(BPF_JIT_ENABLE, b"1").is_err();
                if failed {
                    return false;
                }
            }
            true
        }
        Err(_) => false,
    }
}
