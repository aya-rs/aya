//! Tests the Info API.

// TODO: Figure out a way to assert that field is truly not present.
//       We can call `bpf_obj_get_info_by_fd()` and fill our target field with arbitrary data.
//       `E2BIG` error from `bpf_check_uarg_tail_zero()` will detect if we're accessing fields that
//       isn't supported on the kernel.
//       Issue is that `bpf_obj_get_info_by_fd()` will need to be public. :/

use std::{fs, panic, path::Path, time::SystemTime};

use aya::{
    Ebpf,
    maps::{Array, HashMap, IterableMap as _, MapError, MapType, loaded_maps},
    programs::{ProgramError, ProgramType, SocketFilter, TracePoint, UProbe, loaded_programs},
    sys::{
        enable_stats,
        feature_probe::{is_map_supported, is_program_supported},
    },
    util::KernelVersion,
};
use libc::EINVAL;

use crate::utils::{kernel_assert, kernel_assert_eq};

#[test]
fn test_loaded_programs() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    // Since we are only testing the programs for their metadata, there is no need to "attach" them.
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let test_prog = prog.info().unwrap();

    // Ensure loaded program doesn't panic
    let mut programs = loaded_programs().peekable();
    if let Err(err) = programs.peek().unwrap() {
        if let ProgramError::SyscallError(err) = &err {
            // Skip entire test since feature not available
            if err.io_error.raw_os_error() == Some(EINVAL) {
                eprintln!("skipping test - `loaded_programs()` not supported");
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

    // Use loaded programs to find our test program and exercise `from_program_info()`.
    let info = loaded_programs()
        .filter_map(|prog| prog.ok())
        .find(|prog| prog.id() == test_prog.id())
        .unwrap();

    let mut p: UProbe = unsafe {
        UProbe::from_program_info(info, "test_uprobe".into(), aya::programs::ProbeKind::UProbe)
            .unwrap()
    };

    // Ensure we can perform basic operations on the re-created program.
    let res = p
        .attach("uprobe_function", "/proc/self/exe", None, None)
        .unwrap();

    // Ensure the program can be detached.
    p.detach(res).unwrap();
}

#[test]
fn test_program_info() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    // Kernels below v4.15 have been observed to have `bpf_jit_enable` disabled by default.
    let _guard = ensure_sysctl_enabled("/proc/sys/net/core/bpf_jit_enable");

    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let test_prog = prog.info().unwrap();

    // Test `bpf_prog_info` fields.
    kernel_assert_eq!(
        ProgramType::SocketFilter,
        test_prog.program_type().unwrap_or(ProgramType::Unspecified),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(test_prog.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert!(test_prog.tag() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert!(test_prog.size_jitted() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert!(
        test_prog.size_translated().is_some(),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(
        test_prog.loaded_at().is_some(),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert_eq!(
        Some(0),
        test_prog.created_by_uid(),
        KernelVersion::new(4, 15, 0),
    );
    let maps = test_prog.map_ids().unwrap();
    kernel_assert_eq!(maps, Some(Vec::new()), KernelVersion::new(4, 15, 0));
    kernel_assert_eq!(
        Some("simple_prog"),
        test_prog.name_as_str(),
        KernelVersion::new(4, 15, 0),
    );
    kernel_assert_eq!(
        Some(true),
        test_prog.gpl_compatible(),
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
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();

    // SystemTime is not monotonic, which can cause this test to flake. We don't expect the clock
    // timestamp to continuously jump around, so we add some retries. If the test is ever correct,
    // we know that the value returned by loaded_at() was reasonable relative to SystemTime::now().
    let mut failures = Vec::new();
    for () in std::iter::repeat_n((), 5) {
        let t1 = SystemTime::now();
        prog.load().unwrap();

        let t2 = SystemTime::now();
        let loaded_at = match prog.info().unwrap().loaded_at() {
            Some(time) => time,
            None => {
                eprintln!("skipping test - `bpf_prog_info.load_time` field not supported");
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
fn test_prog_stats() {
    if !is_program_supported(ProgramType::TracePoint).unwrap() {
        eprintln!("skipping test - tracepoint program not supported");
        return;
    }
    if !Path::new("/sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf").exists() {
        eprintln!("skipping test - `syscalls/sys_enter_bpf` not available");
        return;
    }

    let _guard = ensure_sysctl_enabled("/proc/sys/kernel/bpf_stats_enabled");

    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut TracePoint = bpf
        .program_mut("test_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("syscalls", "sys_enter_bpf").unwrap();
    let test_prog = prog.info().unwrap();

    kernel_assert!(test_prog.run_count() > 0, KernelVersion::new(5, 1, 0));
}

#[test]
fn list_loaded_maps() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    } else if !is_map_supported(MapType::Hash).unwrap() {
        eprintln!("skipping test - hash map not supported");
        return;
    } else if !is_map_supported(MapType::Array).unwrap() {
        eprintln!("skipping test - array map not supported");
        return;
    }

    // Load a program with maps.
    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Ensure the loaded_maps() api doesn't panic
    let mut maps = loaded_maps().peekable();
    if let Err(err) = maps.peek().unwrap() {
        if let MapError::SyscallError(err) = &err {
            if err.io_error.raw_os_error() == Some(EINVAL) {
                eprintln!("skipping test - `loaded_maps()` not supported");
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
            for id in map_ids {
                assert!(
                    maps.iter().any(|m| m.id() == id),
                    "expected `loaded_maps()` to have `map_ids` from program",
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
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    } else if !is_map_supported(MapType::Hash).unwrap() {
        eprintln!("skipping test - hash map not supported");
        return;
    } else if !is_map_supported(MapType::Array).unwrap() {
        eprintln!("skipping test - array map not supported");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Test `bpf_map_info` fields.
    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let hash = hash.map().info().unwrap();
    kernel_assert_eq!(
        MapType::Hash,
        hash.map_type().unwrap_or(MapType::Unspecified),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(hash.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, hash.key_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(1, hash.value_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(8, hash.max_entries(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(
        Some("BAR"),
        hash.name_as_str(),
        KernelVersion::new(4, 15, 0),
    );

    hash.map_flags();
    hash.fd().unwrap();

    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let array = array.map().info().unwrap();
    kernel_assert_eq!(
        MapType::Array,
        array.map_type().unwrap_or(MapType::Unspecified),
        KernelVersion::new(4, 13, 0),
    );
    kernel_assert!(array.id() > 0, KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, array.key_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(4, array.value_size(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(10, array.max_entries(), KernelVersion::new(4, 13, 0));
    kernel_assert_eq!(
        Some("FOO"),
        array.name_as_str(),
        KernelVersion::new(4, 15, 0),
    );

    array.map_flags();
    array.fd().unwrap();
}

fn ensure_sysctl_enabled<'a>(
    path: &'a str,
) -> Option<scopeguard::ScopeGuard<&'a str, impl FnOnce(&'a str)>> {
    let content = fs::read_to_string(path).unwrap();
    (!content.starts_with('1')).then(move || {
        fs::write(path, b"1").unwrap();
        scopeguard::guard(path, |path| fs::write(path, b"0").unwrap())
    })
}
