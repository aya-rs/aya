use std::{collections::HashMap, fs, io::ErrorKind, num::ParseIntError, path::PathBuf};

use assert_matches::assert_matches;
use aya::{
    Ebpf, maps,
    programs::{
        ProgramError,
        perf_event::{
            BreakpointConfig, PerfBreakpointLength, PerfBreakpointType, PerfEventConfig,
            PerfEventScope, SamplePolicy,
        },
    },
    sys::SyscallError,
    util::online_cpus,
};
use aya_obj::generated::{
    HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_RW, PERF_FLAG_FD_CLOEXEC, perf_event_attr,
    perf_event_sample_format::PERF_SAMPLE_RAW, perf_type_id::PERF_TYPE_BREAKPOINT,
};
use scopeguard::defer;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
compile_error!("perf_event_bp requires an architecture-specific breakpoint case");

const ARM32_KERNEL_BREAKPOINT_ADDRESS: u64 = 0xffff_fffc;

fn arm32_kernel_breakpoint_error() -> i32 {
    let mut attr = unsafe { std::mem::zeroed::<perf_event_attr>() };
    attr.type_ = PERF_TYPE_BREAKPOINT as u32;
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.bp_type = HW_BREAKPOINT_RW;
    attr.__bindgen_anon_3.bp_addr = ARM32_KERNEL_BREAKPOINT_ADDRESS;
    attr.__bindgen_anon_4.bp_len = u64::from(HW_BREAKPOINT_LEN_1);
    attr.__bindgen_anon_1.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_RAW as u64;
    attr.set_precise_ip(2);

    // ARM32 reports ENODEV when hardware debug monitor mode is unavailable,
    // or EPERM for a kernel-space breakpoint when the monitor is available:
    // https://github.com/gregkh/linux/blob/v6.12.109/arch/arm/kernel/hw_breakpoint.c#L591-L600
    // https://github.com/gregkh/linux/blob/v6.12.109/arch/arm/kernel/hw_breakpoint.c#L635-L641
    // SAFETY: attr points to a fully initialized perf_event_attr for this syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr,
            0,
            -1,
            -1,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    assert_eq!(fd, -1, "ARM32 unexpectedly accepted a kernel breakpoint");
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EPERM) => libc::EPERM,
        Some(libc::ENODEV) => libc::ENODEV,
        _ => panic!("unexpected ARM32 kernel breakpoint failure: {error}"),
    }
}

fn find_system_map() -> Vec<PathBuf> {
    const BOOT_PATH: &str = "/boot/";
    const SYSTEM_MAP_PREFIX: &str = "System.map-";
    let mut system_maps = Vec::new();
    for (i, entry) in fs::read_dir(BOOT_PATH)
        .unwrap_or_else(|error| panic!("fs::read_dir({BOOT_PATH}): {error:?}"))
        .enumerate()
    {
        let entry = entry.unwrap_or_else(|error| {
            panic!("fs::read_dir({BOOT_PATH}).enumerate().nth({i}): {error:?}")
        });
        if !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(SYSTEM_MAP_PREFIX.as_bytes())
        {
            continue;
        }
        system_maps.push(entry.path());
    }
    system_maps
}

struct KernelSymbol<'a> {
    address: u64,
    #[expect(dead_code, reason = "parsed for completeness")]
    r#type: &'a str,
    name: &'a str,
    #[expect(dead_code, reason = "parsed for completeness")]
    module: Option<&'a str>,
}

fn parse_kernel_symbol(line: &str) -> Option<KernelSymbol<'_>> {
    let mut parts = line.splitn(4, char::is_whitespace);
    let address = parts.next()?;
    let r#type = parts.next()?;
    let name = parts.next()?;
    let module = parts.next();
    // TODO(https://github.com/rust-lang/rust-clippy/issues/14112): Remove this allowance
    // when the lint behaves more sensibly.
    #[expect(clippy::manual_ok_err, reason = "type ascription")]
    let address = match u64::from_str_radix(address, 16) {
        Ok(address) => Some(address),
        Err(ParseIntError { .. }) => None,
    }?;
    Some(KernelSymbol {
        address,
        r#type,
        name,
        module,
    })
}

fn parse_kernel_symbols(content: &str) -> HashMap<&str, Vec<u64>> {
    let mut kernel_symbols = HashMap::<_, Vec<_>>::new();
    for line in content.lines() {
        let KernelSymbol {
            address,
            r#type: _,
            name,
            module: _,
        } = parse_kernel_symbol(line).unwrap_or_else(|| panic!("parse_kernel_symbol({line})"));
        kernel_symbols.entry(name).or_default().push(address);
    }
    kernel_symbols
}

#[track_caller]
fn run_breakpoint_case<F>(config: BreakpointConfig, mut trigger: F, expected_addr: u64)
where
    F: FnMut(),
{
    let mut bpf = Ebpf::load(crate::PERF_EVENT_BP).unwrap();

    let map: maps::HashMap<_, u32, u64> = bpf.take_map("READERS").unwrap().try_into().unwrap();

    let prog: &mut aya::programs::PerfEvent = bpf
        .program_mut("perf_event_bp")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    // x86 debug registers cannot trigger on read-only watchpoints, so the
    // kernel rejects `HW_BREAKPOINT_R` outright, see
    // https://github.com/torvalds/linux/blob/v6.12/arch/x86/kernel/hw_breakpoint.c#L345-L377.
    let type_supported = !(cfg!(target_arch = "x86_64")
        && matches!(
            config,
            BreakpointConfig::Data {
                r#type: PerfBreakpointType::Read,
                ..
            }
        ));

    let mut calling_process_scopes = Vec::new();
    let mut one_process_scopes = Vec::new();
    let mut all_processes_one_cpu_scopes = Vec::new();

    let pid = std::process::id();
    for cpu in online_cpus().unwrap() {
        calling_process_scopes.push(PerfEventScope::CallingProcess { cpu: Some(cpu) });
        one_process_scopes.push(PerfEventScope::OneProcess {
            pid,
            cpu: Some(cpu),
        });
        all_processes_one_cpu_scopes.push(PerfEventScope::AllProcessesOneCpu { cpu });
    }

    let scope_groups = &[
        &[PerfEventScope::CallingProcess { cpu: None }][..],
        &[PerfEventScope::OneProcess { pid, cpu: None }][..],
        calling_process_scopes.as_slice(),
        one_process_scopes.as_slice(),
        all_processes_one_cpu_scopes.as_slice(),
    ];

    for scope_group in scope_groups {
        let mut link_ids = Vec::new();
        for scope in *scope_group {
            // arm64 rejects per-task kernel breakpoints (the scopes that carry
            // a PID) to avoid single-step bookkeeping, see
            // https://github.com/torvalds/linux/blob/v6.12/arch/arm64/kernel/hw_breakpoint.c#L566-L571.
            // arm32 rejects per-CPU user-space breakpoints.
            // https://github.com/torvalds/linux/blob/v6.12/arch/arm/kernel/hw_breakpoint.c#L593-L625
            let scope_supported = type_supported
                && match scope {
                    PerfEventScope::CallingProcess { cpu: _ } => !cfg!(target_arch = "aarch64"),
                    PerfEventScope::OneProcess { pid: _, cpu: _ } => !cfg!(target_arch = "aarch64"),
                    PerfEventScope::AllProcessesOneCpu { cpu: _ } => !cfg!(target_arch = "arm"),
                };
            let attach = prog.attach(
                PerfEventConfig::Breakpoint(config),
                *scope,
                SamplePolicy::Period(1),
                true,
            );
            if scope_supported {
                let link_id = attach.unwrap_or_else(|error| {
                    panic!("{config:?} {scope:?} attach failed: {error:?}")
                });
                link_ids.push(link_id);
            } else {
                assert_matches!(
                    attach.unwrap_err(),
                    ProgramError::SyscallError(SyscallError {
                        call: "perf_event_open",
                        io_error,
                    }) => io_error.kind() == ErrorKind::InvalidInput
                );
            }
        }
        let attached = !link_ids.is_empty();
        defer! {
            for link_id in link_ids {
                prog.detach(link_id).unwrap();
            }
        }

        trigger();

        let lookup = map.get(&pid, 0);
        if attached {
            let recorded =
                lookup.unwrap_or_else(|error| panic!("{config:?} map lookup failed: {error:?}"));
            assert_eq!(
                recorded, expected_addr,
                "{config:?} recorded unexpected address"
            );
        } else {
            assert_matches!(lookup.unwrap_err(), maps::MapError::KeyNotFound);
        }
    }
}

fn get_address(symbols: &HashMap<&str, Vec<u64>>, name: &str) -> Option<u64> {
    symbols.get(name).map(|addrs| match addrs.as_slice() {
        [addr] => *addr,
        [] => panic!("no address found for {name} in {symbols:?}"),
        addrs => panic!("multiple addresses found for {name}: {addrs:?}"),
    })
}

#[test_log::test]
fn perf_event_bp() {
    if cfg!(target_arch = "arm") {
        let expected_errno = arm32_kernel_breakpoint_error();
        let mut bpf = Ebpf::load(crate::PERF_EVENT_BP).unwrap();
        let prog: &mut aya::programs::PerfEvent = bpf
            .program_mut("perf_event_bp")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        let attach = prog.attach(
            PerfEventConfig::Breakpoint(BreakpointConfig::Data {
                r#type: PerfBreakpointType::ReadWrite,
                address: ARM32_KERNEL_BREAKPOINT_ADDRESS,
                length: PerfBreakpointLength::Len1,
            }),
            PerfEventScope::CallingProcess { cpu: None },
            SamplePolicy::Period(1),
            true,
        );
        assert_matches!(attach, Err(ProgramError::SyscallError(SyscallError {
            call: "perf_event_open",
            io_error,
        })) => assert_eq!(io_error.raw_os_error(), Some(expected_errno)));

        if expected_errno == libc::ENODEV {
            return;
        }
        // ARM32 rejects kernel-space hardware breakpoints. Exercise a per-task
        // user-space ReadWrite watchpoint instead.
        // https://github.com/torvalds/linux/blob/v6.12/arch/arm/kernel/hw_breakpoint.c#L593-L625
        let mut watched = 0u8;
        let watched_ptr = &raw mut watched;
        let address = watched_ptr.addr() as u64;
        run_breakpoint_case(
            BreakpointConfig::Data {
                r#type: PerfBreakpointType::ReadWrite,
                address,
                length: PerfBreakpointLength::Len1,
            },
            // SAFETY: watched_ptr points to the local value for the entire call.
            || unsafe { watched_ptr.write_volatile(1) },
            address,
        );
        assert_eq!(watched, 1);
        return;
    }

    // Search for the address of modprobe_path. Prefer to grab it directly from
    // kallsyms, but if it's not there we can grab it from System.map and apply
    // the kaslr offset.
    const KALLSYMS_PATH: &str = "/proc/kallsyms";
    let kernel_symbols = fs::read_to_string(KALLSYMS_PATH)
        .unwrap_or_else(|error| panic!("fs::read_to_string({KALLSYMS_PATH}): {error:?}"));
    let kernel_symbols = parse_kernel_symbols(&kernel_symbols);

    let attach_addr = if let Some(addr) = get_address(&kernel_symbols, "modprobe_path") {
        addr
    } else {
        let gunzip_addr = get_address(&kernel_symbols, "gunzip")
            .unwrap_or_else(|| panic!("gunzip not found in {kernel_symbols:?}"));

        let system_map = find_system_map();
        let system_map = match system_map.as_slice() {
            [system_map] => system_map,
            [] => panic!("no system map found"),
            system_maps => panic!("multiple system maps found: {system_maps:?}"),
        };
        let system_map = fs::read_to_string(system_map).unwrap_or_else(|error| {
            panic!("fs::read_to_string({}): {error:?}", system_map.display())
        });
        let system_map = parse_kernel_symbols(&system_map);

        let gunzip_debug_addr = get_address(&system_map, "gunzip")
            .unwrap_or_else(|| panic!("gunzip not found in {system_map:?}"));
        let modprobe_path_debug_addr = get_address(&system_map, "modprobe_path")
            .unwrap_or_else(|| panic!("modprobe_path not found in {system_map:?}"));

        let kaslr_offset = gunzip_addr.wrapping_sub(gunzip_debug_addr);
        modprobe_path_debug_addr.wrapping_add(kaslr_offset)
    };

    // Trigger the hardware breakpoint by reading or writing
    // /proc/sys/kernel/modprobe, the sysctl connected to modprobe_path.
    //
    // See https://github.com/torvalds/linux/blob/v6.17/kernel/module/main.c#L132-L150.
    const MODPROBE_PATH: &str = "/proc/sys/kernel/modprobe";

    let read = |modprobe_contents: &mut Option<String>| {
        let contents = fs::read_to_string(MODPROBE_PATH)
            .unwrap_or_else(|error| panic!("fs::read_to_string({MODPROBE_PATH}): {error:?}"));
        if let Some(modprobe_contents) = modprobe_contents {
            assert_eq!(*modprobe_contents, contents);
        }
        *modprobe_contents = Some(contents);
    };

    let write = |contents: &str| {
        fs::write(MODPROBE_PATH, contents.as_bytes())
            .unwrap_or_else(|error| panic!("fs::write({MODPROBE_PATH}, ..): {error:?}"));
    };

    let mut modprobe_contents_before = None;
    run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::Read,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        || read(&mut modprobe_contents_before),
        attach_addr,
    );
    let modprobe_contents_before = modprobe_contents_before.unwrap();

    run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::Write,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        || write(&modprobe_contents_before),
        attach_addr,
    );

    let mut modprobe_contents_after = None;
    run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::ReadWrite,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        || read(&mut modprobe_contents_after),
        attach_addr,
    );
    let modprobe_contents_after = modprobe_contents_after.unwrap();

    run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::ReadWrite,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        || write(&modprobe_contents_after),
        attach_addr,
    );

    // Just for fun.
    assert_eq!(modprobe_contents_before, modprobe_contents_after);

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        #[cfg(target_arch = "x86_64")]
        let getpgid_symbol = "__x64_sys_getpgid";
        #[cfg(target_arch = "aarch64")]
        let getpgid_symbol = "__arm64_sys_getpgid";
        let execute_addr = get_address(&kernel_symbols, getpgid_symbol)
            .unwrap_or_else(|| panic!("{getpgid_symbol} not found in {kernel_symbols:?}"));
        run_breakpoint_case(
            BreakpointConfig::Instruction {
                address: execute_addr,
            },
            || {
                nix::unistd::getpgid(None).unwrap();
            },
            execute_addr,
        );
    }
}
