use std::{collections::HashMap, fs, io::ErrorKind, num::ParseIntError, path::PathBuf};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::MapError,
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
    #[expect(dead_code)]
    r#type: &'a str,
    name: &'a str,
    #[expect(dead_code)]
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
    #[expect(clippy::manual_ok_err)]
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

fn run_breakpoint_case<T, F>(config: BreakpointConfig, trigger: F, expected_addr: u64) -> T
where
    F: FnOnce() -> T,
{
    let mut bpf = Ebpf::load(crate::PERF_EVENT_BP).unwrap();
    let prog: &mut aya::programs::PerfEvent = bpf
        .program_mut("perf_event_bp")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let supported = !(cfg!(target_arch = "x86_64")
        && matches!(
            config,
            BreakpointConfig::Data {
                r#type: PerfBreakpointType::Read,
                ..
            }
        ));

    for cpu in online_cpus().unwrap() {
        let attach = prog.attach(
            PerfEventConfig::Breakpoint(config),
            PerfEventScope::AllProcessesOneCpu { cpu },
            SamplePolicy::Period(1),
            true,
        );
        if supported {
            attach.unwrap();
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

    let result = trigger();

    let map: aya::maps::HashMap<_, u32, u64> =
        aya::maps::HashMap::try_from(bpf.map_mut("READERS").unwrap()).unwrap();
    let tgid = std::process::id();

    let lookup = map.get(&tgid, 0);
    if supported {
        let recorded =
            lookup.unwrap_or_else(|error| panic!("{config:?} map lookup failed: {error:?}"));
        assert_eq!(
            recorded, expected_addr,
            "{config:?} recorded unexpected address"
        );
    } else {
        assert_matches!(lookup.unwrap_err(), MapError::KeyNotFound);
    }

    result
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
            system_maps => panic!("multiple system maps found: {:?}", system_maps),
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

    let read = || {
        fs::read_to_string(MODPROBE_PATH)
            .unwrap_or_else(|error| panic!("fs::read_to_string({MODPROBE_PATH}): {error:?}"))
    };

    let write = |contents: &str| {
        fs::write(MODPROBE_PATH, contents.as_bytes())
            .unwrap_or_else(|error| panic!("fs::write({MODPROBE_PATH}, ..): {error:?}"));
    };

    let modprobe_contents_before = run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::Read,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        read,
        attach_addr,
    );

    run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::Write,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        || write(&modprobe_contents_before),
        attach_addr,
    );

    let modprobe_contents_after = run_breakpoint_case(
        BreakpointConfig::Data {
            r#type: PerfBreakpointType::ReadWrite,
            address: attach_addr,
            length: PerfBreakpointLength::Len1,
        },
        read,
        attach_addr,
    );

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

    let execute_addr = {
        let getpgid_symbol = if cfg!(target_arch = "x86_64") {
            "__x64_sys_getpgid"
        } else if cfg!(target_arch = "aarch64") {
            "__arm64_sys_getpgid"
        } else {
            panic!("unsupported architecture");
        };
        get_address(&kernel_symbols, getpgid_symbol)
            .unwrap_or_else(|| panic!("{getpgid_symbol} not found in {kernel_symbols:?}"))
    };

    let _pgid = run_breakpoint_case(
        BreakpointConfig::Instruction {
            address: execute_addr,
        },
        || nix::unistd::getpgid(None).unwrap(),
        execute_addr,
    );
}
