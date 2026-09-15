#![expect(
    clippy::self_named_module_files,
    reason = "the test harness uses a flat tests module"
)]
use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf, EbpfError,
    maps::{MapError, MapType},
    programs::ProgramError,
    sys::{BpfHelper, is_map_supported},
};
use aya_obj::btf::BtfError;

const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

fn vmlinux_btf_missing() -> bool {
    let config = procfs::kernel_config().unwrap();
    assert!(
        matches!(config.get("CONFIG_BPF"), Some(procfs::ConfigSetting::Yes)),
        "kernel config is missing CONFIG_BPF"
    );
    // procfs omits '# CONFIG_... is not set' entries from the parsed config.
    !matches!(
        config.get("CONFIG_DEBUG_INFO_BTF"),
        Some(procfs::ConfigSetting::Yes)
    )
}

fn assert_missing_vmlinux_btf(error: BtfError) {
    assert_matches!(error, BtfError::FileError { path, error } => {
        assert_eq!(path, std::path::Path::new(VMLINUX_BTF));
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    });
}

fn kernel_btf() -> Option<Btf> {
    let missing = vmlinux_btf_missing();
    match Btf::from_sys_fs() {
        Ok(btf) => {
            assert!(!missing, "kernel BTF exists without CONFIG_DEBUG_INFO_BTF");
            Some(btf)
        }
        Err(error) => {
            assert!(missing, "failed to load available kernel BTF: {error}");
            assert_missing_vmlinux_btf(error);
            None
        }
    }
}

fn assert_missing_vmlinux_btf_on_load(error: EbpfError) {
    assert_matches!(error, EbpfError::BtfError(error) => assert_missing_vmlinux_btf(error));
}

fn unsupported_map_names<'a>(
    maps: impl IntoIterator<Item = (MapType, &'a [&'a str])>,
) -> Vec<&'a str> {
    let mut names = Vec::new();
    for (map_type, map_names) in maps {
        if !is_map_supported(map_type).unwrap() {
            names.extend_from_slice(map_names);
        }
    }
    names
}

fn assert_unsupported_map(error: EbpfError, names: &[&str]) {
    let empty: &[&str] = &[];
    assert_ne!(names, empty);
    assert_matches!(error, EbpfError::MapError(error) => {
        assert_matches!(error, MapError::CreateError { name, io_error } => {
            assert!(names.contains(&name.as_str()), "unexpected map {name}; expected {names:?}");
            assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL), "{name}: {io_error}");
        });
    });
}

fn map_load_or_expect_unsupported(
    result: Result<Ebpf, EbpfError>,
    missing: &[&str],
) -> Option<Ebpf> {
    match result {
        Ok(bpf) => {
            assert!(
                missing.is_empty(),
                "map probe reported unsupported: {missing:?}"
            );
            Some(bpf)
        }
        Err(error) => {
            assert_unsupported_map(error, missing);
            None
        }
    }
}

fn assert_unsupported_helper(error: ProgramError, helper: BpfHelper) {
    // https://github.com/torvalds/linux/blob/v5.15/kernel/bpf/verifier.c#L6179-L6192
    assert_matches!(error, ProgramError::LoadError { io_error, verifier_log } => {
        let log = verifier_log.to_string();
        assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL), "{log}");
        assert!(
            (log.contains("invalid func ") || log.contains("unknown func "))
                && log.contains(&format!("#{}", helper as u32)),
            "expected missing helper {helper:?} in verifier log: {log}"
        );
    });
}

// The ARM32 JIT rejects BPF function pointers, atomics, and BPF-to-BPF calls:
// https://github.com/gregkh/linux/blob/v6.12.109/arch/arm/net/bpf_jit_32.c#L1851-L1856
// https://github.com/gregkh/linux/blob/v6.12.109/arch/arm/net/bpf_jit_32.c#L1898-L1901
// https://github.com/gregkh/linux/blob/v6.12.109/arch/arm/net/bpf_jit_32.c#L2051-L2062
// Accept a load failure only when a 32-bit kernel requires JIT compilation and
// reports its internal ENOTSUPP (524). Run the rest of each test after a successful load.
fn load_or_expect_unsupported_jit<T>(result: Result<T, ProgramError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            let config = procfs::kernel_config().unwrap();
            assert!(
                !matches!(config.get("CONFIG_64BIT"), Some(procfs::ConfigSetting::Yes))
                    && matches!(
                        config.get("CONFIG_BPF_JIT_ALWAYS_ON"),
                        Some(procfs::ConfigSetting::Yes)
                    ),
                "unexpected program load failure without a 32-bit mandatory JIT: {error}"
            );
            assert_matches!(error, ProgramError::LoadError { io_error, verifier_log } => {
                assert_eq!(io_error.raw_os_error(), Some(524), "{verifier_log}");
            });
            None
        }
    }
}

fn run_netns_tokio<F, Fut, T>(test: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let _netns = aya::test_helpers::NetNsGuard::new().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(test())
}

mod array;
mod bloom_filter;
mod bpf_probe_read;
mod btf_map_of_maps;
mod btf_maps;
mod btf_relocations;
mod cgroup_array;
mod cgroup_storage;
mod cgrp_storage;
mod elf;
mod feature_probe;
mod fexit;
mod hash_map;
mod info;
mod inode_storage;
mod iter;
mod kprobe;
mod ksyms;
mod linear_data_structures;
mod load;
mod log;
mod lpm_trie;
mod lsm;
mod map_pin;
mod maps_disjoint;
mod per_cpu_array;
mod perf_event_array;
mod perf_event_bp;
mod printk;
mod prog_array;
mod prog_test_run;
mod raw_tracepoint;
mod rbpf;
mod relocations;
mod ring_buf;
mod sk_lookup;
mod sk_reuseport;
mod sk_storage;
mod smoke;
mod socket_filter;
mod stack_trace;
mod stack_trace_lsm;
mod strncmp;
mod tc_netlink;
mod tcx;
mod uprobe_cookie;
mod uprobe_multi;
mod xdp;
