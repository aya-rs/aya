//! Tests the Info API.

// TODO: Figure out a way to assert that field is truly not present.
//       We can call `bpf_obj_get_info_by_fd()` and fill our target field with arbitrary data.
//       `E2BIG` error from `bpf_check_uarg_tail_zero()` will detect if we're accessing fields that
//       isn't supported on the kernel.
//       Issue is that `bpf_obj_get_info_by_fd()` will need to be public. :/

use std::{fs, io::ErrorKind, panic, path::Path, time::SystemTime};

use aya::{
    Ebpf,
    maps::{Array, HashMap, IterableMap as _, MapError, MapType, loaded_maps},
    programs::{
        ProgramError, ProgramInfo, ProgramType, SocketFilter, TracePoint, TracePointError, UProbe,
        loaded_programs, uprobe::UProbeScope,
    },
    sys::is_program_supported,
    util::KernelVersion,
};
use aya_obj::generated::bpf_prog_type;
use libc::{EINVAL, ENOENT};

fn programs_allow_removed_ids() -> impl Iterator<Item = ProgramInfo> {
    loaded_programs().filter_map(|result| match result {
        Ok(program) => Some(program),
        Err(error) => {
            if let ProgramError::SyscallError(syscall) = &error
                && syscall.call == "bpf_prog_get_fd_by_id"
                && syscall.io_error.raw_os_error() == Some(ENOENT)
            {
                return None;
            }
            panic!("unexpected error enumerating programs: {error}");
        }
    })
}

fn load_program_or_expect_unsupported(result: Result<(), ProgramError>, kind: ProgramType) -> bool {
    if is_program_supported(kind).unwrap() {
        result.unwrap_or_else(|error| panic!("load {kind:?}: {error}"));
        true
    } else {
        assert_matches::assert_matches!(result, Err(ProgramError::LoadError { io_error, verifier_log }) => {
            assert_eq!(io_error.raw_os_error(), Some(EINVAL));
            assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
        });
        false
    }
}

fn load_map_test() -> Option<Ebpf> {
    let missing = super::unsupported_map_names([
        (MapType::Array, &["FOO"][..]),
        (MapType::Hash, &["BAR", "MAP_WITH_LOOOONG_NAAAAAAAAME"][..]),
    ]);
    super::map_load_or_expect_unsupported(Ebpf::load(crate::MAP_TEST), &missing)
}

fn assert_missing_program_info(error: ProgramError) {
    assert_matches::assert_matches!(error, ProgramError::SyscallError(syscall) => {
        assert_eq!(syscall.call, "bpf_obj_get_info_by_fd");
        assert_eq!(syscall.io_error.raw_os_error(), Some(EINVAL));
    });
}

fn program_info_or_expect_unsupported(
    result: Result<ProgramInfo, ProgramError>,
) -> Option<ProgramInfo> {
    match result {
        Ok(info) => Some(info),
        Err(error) => {
            let kernel_version = KernelVersion::current().unwrap();
            assert!(
                kernel_version < KernelVersion::new(4, 13, 0),
                "program info failed on {kernel_version}: {error}"
            );
            assert_missing_program_info(error);
            None
        }
    }
}

fn assert_optional_info<T: std::fmt::Debug + PartialEq>(
    actual: Option<T>,
    expected: T,
    since: KernelVersion,
    field: &str,
) {
    match actual {
        Some(actual) => assert_eq!(actual, expected, "{field}"),
        None => assert!(
            KernelVersion::current().unwrap() < since,
            "{field} is missing from the program info"
        ),
    }
}

fn assert_present_info(present: bool, since: KernelVersion, field: &str) {
    if !present {
        assert!(
            KernelVersion::current().unwrap() < since,
            "{field} is missing from the program info"
        );
    }
}

#[test_log::test]
fn test_loaded_programs() {
    // Since we are only testing the programs for their metadata, there is no need to "attach" them.
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();
    if !load_program_or_expect_unsupported(prog.load(), UProbe::PROGRAM_TYPE) {
        return;
    }
    // Both program information and enumeration were introduced in Linux 4.13.
    let Some(test_prog) = program_info_or_expect_unsupported(prog.info()) else {
        let mut programs = loaded_programs();
        assert_matches::assert_matches!(programs.next(), Some(Err(ProgramError::SyscallError(err))) => {
            assert_eq!(err.call, "bpf_prog_get_next_id");
            assert_eq!(err.io_error.raw_os_error(), Some(EINVAL));
        });
        return;
    };

    // Program information and enumeration can be backported separately.
    let mut programs = loaded_programs().peekable();
    if let Some(Err(ProgramError::SyscallError(error))) = programs.peek()
        && error.call == "bpf_prog_get_next_id"
    {
        assert!(KernelVersion::current().unwrap() < KernelVersion::new(4, 13, 0));
        assert_eq!(error.io_error.raw_os_error(), Some(EINVAL));
        return;
    }

    // Loaded programs should contain our test program
    let mut programs = programs_allow_removed_ids();
    assert!(programs.any(|prog| prog.id() == test_prog.id()));

    // Use loaded programs to find our test program and exercise `from_program_info()`.
    let info = programs_allow_removed_ids()
        .find(|prog| prog.id() == test_prog.id())
        .unwrap();

    let mut p: UProbe = unsafe {
        UProbe::from_program_info(info, "test_uprobe".into(), aya::programs::ProbeKind::Entry)
            .unwrap()
    };

    // Ensure we can perform basic operations on the re-created program.
    let res = p
        .attach(
            ["uprobe_function"],
            "/proc/self/exe",
            UProbeScope::AllProcesses,
        )
        .unwrap();

    // Ensure the program can be detached.
    p.detach(res).unwrap();
}

#[test_log::test]
fn test_program_info() {
    // Kernels below v4.15 have been observed to have `bpf_jit_enable` disabled by default.
    let _guard = ensure_sysctl_enabled("/proc/sys/net/core/bpf_jit_enable");

    let mut bpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    if !load_program_or_expect_unsupported(prog.load(), ProgramType::SocketFilter) {
        return;
    }
    let Some(test_prog) = program_info_or_expect_unsupported(prog.info()) else {
        return;
    };

    // Test `bpf_prog_info` fields.
    assert_eq!(
        bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
        test_prog.program_type()
    );
    assert!(test_prog.id() > 0);
    assert!(test_prog.tag() > 0);
    assert!(test_prog.size_jitted() > 0);
    assert_present_info(
        test_prog.size_translated().is_some(),
        KernelVersion::new(4, 15, 0),
        "xlated_prog_len",
    );
    assert_present_info(
        test_prog.loaded_at().is_some(),
        KernelVersion::new(4, 15, 0),
        "load_time",
    );
    assert_optional_info(
        test_prog.created_by_uid(),
        0,
        KernelVersion::new(4, 15, 0),
        "created_by_uid",
    );
    let maps = test_prog.map_ids().unwrap();
    assert_optional_info(maps, Vec::new(), KernelVersion::new(4, 15, 0), "map_ids");
    assert_optional_info(
        test_prog.name_as_str(),
        "simple_prog",
        KernelVersion::new(4, 15, 0),
        "name",
    );
    assert_optional_info(
        test_prog.gpl_compatible(),
        true,
        KernelVersion::new(4, 18, 0),
        "gpl_compatible",
    );
    assert_present_info(
        test_prog.verified_instruction_count().is_some(),
        KernelVersion::new(5, 16, 0),
        "verified_insns",
    );

    // We can't reliably test these fields since `0` can be interpreted as the actual value or
    // unavailable.
    test_prog.btf_id();

    // Ensure rest of the fields do not panic.
    test_prog.memory_locked().unwrap();
    test_prog.fd().unwrap();
}

#[test_log::test]
fn test_loaded_at() {
    let mut bpf: Ebpf = Ebpf::load(crate::SIMPLE_PROG).unwrap();
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();

    // SystemTime is not monotonic, which can cause this test to flake. We don't expect the clock
    // timestamp to continuously jump around, so we add some retries. If the test is ever correct,
    // we know that the value returned by loaded_at() was reasonable relative to SystemTime::now().
    let mut failures = Vec::new();
    for () in std::iter::repeat_n((), 5) {
        let t1 = SystemTime::now();
        if !load_program_or_expect_unsupported(prog.load(), ProgramType::SocketFilter) {
            return;
        }

        let t2 = SystemTime::now();
        let Some(info) = program_info_or_expect_unsupported(prog.info()) else {
            prog.unload().unwrap();
            return;
        };
        let Some(loaded_at) = info.loaded_at() else {
            assert!(KernelVersion::current().unwrap() < KernelVersion::new(4, 15, 0));
            prog.unload().unwrap();
            return;
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

#[test_log::test]
fn test_prog_stats() {
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut TracePoint = bpf
        .program_mut("test_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();
    if !load_program_or_expect_unsupported(prog.load(), ProgramType::TracePoint) {
        return;
    }

    if let Err(error) = prog.attach("syscalls", "sys_enter_bpf") {
        assert_matches::assert_matches!(error, ProgramError::TracePointError(TracePointError::FileError { filename, io_error }) => {
            assert!(filename.ends_with(Path::new("events/syscalls/sys_enter_bpf/id")), "{filename:?}");
            assert_eq!(io_error.kind(), ErrorKind::NotFound);
        });
        let tracing_paths = [
            Path::new("/sys/kernel/tracing"),
            Path::new("/sys/kernel/debug/tracing"),
        ];
        assert!(
            tracing_paths
                .iter()
                .any(|path| path.join("events").is_dir()),
            "tracefs must be mounted to test a missing tracepoint"
        );
        for path in tracing_paths {
            let event = path.join("events/syscalls/sys_enter_bpf/id");
            assert!(
                !event.exists(),
                "Aya could not attach the existing {event:?}"
            );
        }
        return;
    }
    let stats_path = "/proc/sys/kernel/bpf_stats_enabled";
    // https://github.com/torvalds/linux/blob/v5.1/kernel/sysctl.c#L1251-L1260
    if let Err(error) = fs::read(stats_path) {
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(KernelVersion::current().unwrap() < KernelVersion::new(5, 1, 0));
        if let Some(info) = program_info_or_expect_unsupported(prog.info()) {
            assert_eq!(info.run_count(), 0);
        }
        return;
    }
    let _guard = ensure_sysctl_enabled(stats_path);
    let test_prog = prog.info().unwrap();

    assert!(test_prog.run_count() > 0);
}

#[test_log::test]
fn list_loaded_maps() {
    // Load a program with maps.
    let Some(mut bpf) = load_map_test() else {
        return;
    };
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    if !load_program_or_expect_unsupported(prog.load(), ProgramType::SocketFilter) {
        return;
    }

    // Map enumeration was added in Linux 4.13. Test the syscall on older
    // kernels too, so a backport can exercise the map assertions below.
    let mut maps = loaded_maps().peekable();
    if let Some(Err(MapError::SyscallError(error))) = maps.peek()
        && error.call == "bpf_map_get_next_id"
    {
        assert!(KernelVersion::current().unwrap() < KernelVersion::new(4, 13, 0));
        assert_eq!(error.io_error.raw_os_error(), Some(EINVAL));
        return;
    }

    // Loaded maps should contain our test maps
    let maps: Vec<_> = maps
        .filter_map(|result| match result {
            Ok(info) => Some(info),
            // BPF_MAP_GET_NEXT_ID returns an ID without holding a reference, so the map can be
            // removed before BPF_MAP_GET_FD_BY_ID. The kernel selftests and bpftool both tolerate
            // that specific ENOENT race:
            // https://github.com/torvalds/linux/blob/b15dc417/kernel/bpf/syscall.c#L3184-L3207
            // https://github.com/torvalds/linux/blob/b95f03f0/tools/testing/selftests/bpf/prog_tests/bpf_obj_id.c#L205-L218
            // https://github.com/libbpf/bpftool/blob/5730b384/src/map.c#L703-L719
            Err(MapError::SyscallError(err))
                if err.call == "bpf_map_get_fd_by_id"
                    && err.io_error.raw_os_error() == Some(ENOENT) =>
            {
                None
            }
            Err(err) => panic!("{err:?}"),
        })
        .collect();
    let info = prog.info().unwrap();
    let map_ids = info.map_ids().unwrap();
    match map_ids {
        Some(map_ids) => {
            assert_eq!(2, map_ids.len());
            for id in map_ids {
                assert!(
                    maps.iter().any(|m| m.id() == id),
                    "expected `loaded_maps()` to have `map_ids` from program",
                );
            }
        }
        None => assert!(KernelVersion::current().unwrap() < KernelVersion::new(4, 15, 0)),
    }

    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let hash_id = hash.map().info().unwrap().id();
    assert!(maps.iter().any(|map| map.id() == hash_id));

    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let array_id = array.map().info().unwrap().id();
    assert!(maps.iter().any(|map| map.id() == array_id));
}

#[test_log::test]
fn test_map_info() {
    let Some(mut bpf) = load_map_test() else {
        return;
    };
    let prog: &mut SocketFilter = bpf.program_mut("simple_prog").unwrap().try_into().unwrap();
    if !load_program_or_expect_unsupported(prog.load(), ProgramType::SocketFilter) {
        return;
    }

    // Test `bpf_map_info` fields.
    let hash: HashMap<_, u32, u8> = HashMap::try_from(bpf.map("BAR").unwrap()).unwrap();
    let array: Array<_, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();
    let hash_info = hash.map().info();
    let array_info = array.map().info();
    // Map information was introduced alongside BPF_OBJ_GET_INFO_BY_FD in
    // Linux 4.13, and may also be backported to older kernels.
    let (hash, array) = match (hash_info, array_info) {
        (Ok(hash), Ok(array)) => (hash, array),
        (hash_result, array_result) => {
            assert!(KernelVersion::current().unwrap() < KernelVersion::new(4, 13, 0));
            assert_matches::assert_matches!(hash_result, Err(MapError::SyscallError(syscall)) => {
                assert_eq!(syscall.call, "bpf_obj_get_info_by_fd");
                assert_eq!(syscall.io_error.raw_os_error(), Some(EINVAL));
            });
            assert_matches::assert_matches!(array_result, Err(MapError::SyscallError(syscall)) => {
                assert_eq!(syscall.call, "bpf_obj_get_info_by_fd");
                assert_eq!(syscall.io_error.raw_os_error(), Some(EINVAL));
            });
            return;
        }
    };
    assert_eq!(MapType::Hash, hash.map_type().unwrap());
    assert!(hash.id() > 0);
    assert_eq!(4, hash.key_size());
    assert_eq!(1, hash.value_size());
    assert_eq!(8, hash.max_entries());
    assert_optional_info(
        hash.name_as_str(),
        "BAR",
        KernelVersion::new(4, 15, 0),
        "hash map name",
    );

    hash.map_flags();
    hash.fd().unwrap();

    assert_eq!(MapType::Array, array.map_type().unwrap());
    assert!(array.id() > 0);
    assert_eq!(4, array.key_size());
    assert_eq!(4, array.value_size());
    assert_eq!(10, array.max_entries());
    assert_optional_info(
        array.name_as_str(),
        "FOO",
        KernelVersion::new(4, 15, 0),
        "array map name",
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
