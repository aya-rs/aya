//! Tests the Info API.

use std::{fs, time::SystemTime};

use aya::{
    maps::{loaded_maps, Array, HashMap, IterableMap, MapError},
    programs::{loaded_programs, ProgramError, SocketFilter},
    util::KernelVersion,
    Ebpf,
};
use aya_obj::generated::{bpf_map_type, bpf_prog_type};
use libc::EINVAL;

use crate::{kernel_assert, kernel_assert_eq};

const BPF_JIT_ENABLE: &str = "/proc/sys/net/core/bpf_jit_enable";

#[test]
fn test_loaded_programs() {
    // Load a program.
    // Since we are only testing the programs for their metadata, there is no need to "attach" them.
    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let test_prog = prog.info().unwrap();

    // Ensure loaded program doesn't panic
    let mut programs = loaded_programs().peekable();
    if let Err(err) = programs.peek().unwrap() {
        if let ProgramError::SyscallError(err) = &err {
            // Skip entire test since feature not available
            if err
                .io_error
                .raw_os_error()
                .is_some_and(|errno| errno == EINVAL)
            {
                eprintln!(
                    "ignoring test completely as `loaded_programs()` is not available on the host"
                );
                return;
            }
        }
        panic!("{err}");
    }

    // Loaded programs should contain our test program
    let mut programs = programs.filter_map(|prog| prog.ok());
    kernel_assert!(
        programs.any(|prog| prog.id() == test_prog.id()),
        KernelVersion::new(4, 13, 0)
    );
}

#[test]
fn test_program_info() {
    // Kernels below v4.15 have been observed to have `bpf_jit_enable` disabled by default.
    let jit_enabled = enable_jit();

    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let test_prog = prog.info().unwrap();

    // Test `bpf_prog_info` fields.
    kernel_assert_eq!(
        bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
        test_prog.program_type(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(test_prog.id().is_some(), KernelVersion::new(4, 13, 0));
    kernel_assert!(test_prog.tag().is_some(), KernelVersion::new(4, 13, 0));
    if jit_enabled {
        kernel_assert!(
            test_prog.size_jitted().is_some(),
            KernelVersion::new(4, 13, 0),
        );
    }
    kernel_assert!(
        test_prog.size_translated().is_some(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        test_prog.loaded_at().is_some(),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert!(
        test_prog.created_by_uid().is_some_and(|uid| uid == 0),
        KernelVersion::new(4, 15, 0),
    );
    let maps = test_prog.map_ids().unwrap();
    kernel_assert!(
        maps.is_some_and(|ids| ids.is_empty()),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert!(
        test_prog
            .name_as_str()
            .is_some_and(|name| name == "simple_prog"),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert!(
        test_prog.gpl_compatible().is_some_and(|gpl| gpl),
        KernelVersion::new(4, 18, 0),
    );
    kernel_assert!(
        test_prog.verified_instruction_count().is_some(),
        KernelVersion::new(5, 16, 0),
    );

    // We can't reliably test these fields since `0` can be interpreted as the actual value or
    // unavailable.
    test_prog.btf_id();

    // Ensure rest of the fields do not panic.
    test_prog.memory_locked().unwrap();
    test_prog.fd().unwrap();
}

#[test]
fn test_loaded_at() {
    let mut bpf: Ebpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();

    // SystemTime is not monotonic, which can cause this test to flake. We don't expect the clock
    // timestamp to continuously jump around, so we add some retries. If the test is ever correct,
    // we know that the value returned by loaded_at() was reasonable relative to SystemTime::now().
    let mut failures = Vec::new();
    for _ in 0..5 {
        let t1 = SystemTime::now();
        prog.load().unwrap();

        let t2 = SystemTime::now();
        let loaded_at = match prog.info().unwrap().loaded_at() {
            Some(time) => time,
            None => {
                eprintln!("ignoring test completely as `load_time` field of `bpf_prog_info` is not available on the host");
                return;
            }
        };
        prog.unload().unwrap();

        let range = t1..t2;
        if range.contains(&loaded_at) {
            failures.clear();
            break;
        }
        failures.push(LoadedAtRange(loaded_at, range));
    }
    assert!(
        failures.is_empty(),
        "loaded_at was not in range: {failures:?}",
    );

    struct LoadedAtRange(SystemTime, std::ops::Range<SystemTime>);
    impl std::fmt::Debug for LoadedAtRange {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self(loaded_at, range) = self;
            write!(f, "{range:?}.contains({loaded_at:?})")
        }
    }
}

#[test]
fn test_loaded_maps() {
    // Load a program with maps.
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Ensure the loaded_maps() api doesn't panic
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

    // Loaded maps should contain our test maps
    let maps: Vec<_> = maps.filter_map(|m| m.ok()).collect();
    if let Ok(info) = &prog.info() {
        if let Some(map_ids) = info.map_ids().unwrap() {
            assert_eq!(2, map_ids.len());
            for id in map_ids.iter() {
                assert!(
                    maps.iter().any(|m| &m.id().unwrap() == id),
                    "expected `loaded_maps()` to have `map_ids` from program"
                );
            }
        }
    }

    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let hash_id = hash.map().info().unwrap().id();
    kernel_assert!(
        maps.iter().any(|map| map.id() == hash_id),
        KernelVersion::new(4, 13, 0),
    );

    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let array_id = array.map().info().unwrap().id();
    kernel_assert!(
        maps.iter().any(|map| map.id() == array_id),
        KernelVersion::new(4, 13, 0),
    );
}

#[test]
fn test_map_info() {
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Test `bpf_map_info` fields.
    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let hash = hash.map().info().unwrap();
    kernel_assert_eq!(
        bpf_map_type::BPF_MAP_TYPE_HASH,
        hash.map_type(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(hash.id().is_some(), KernelVersion::new(4, 13, 0));
    kernel_assert!(
        hash.key_size().is_some_and(|size| size.get() == 4),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        hash.value_size().is_some_and(|size| size.get() == 1),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        hash.max_entries().is_some_and(|size| size.get() == 8),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        hash.name_as_str().is_some_and(|name| name == "BAR"),
        KernelVersion::new(4, 15, 0),
    );

    hash.map_flags();
    hash.fd().unwrap();

    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let array = array.map().info().unwrap();
    kernel_assert_eq!(
        bpf_map_type::BPF_MAP_TYPE_ARRAY,
        array.map_type(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(array.id().is_some(), KernelVersion::new(4, 13, 0));
    kernel_assert!(
        array.key_size().is_some_and(|size| size.get() == 4),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        array.value_size().is_some_and(|size| size.get() == 4),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        array.max_entries().is_some_and(|size| size.get() == 10),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        array.name_as_str().is_some_and(|name| name == "FOO"),
        KernelVersion::new(4, 15, 0),
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
