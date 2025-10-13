use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader},
};

use aya::{
    Ebpf,
    programs::{
        PerfEventScope, PerfTypeId, SamplePolicy,
        perf_event::{
            PerfBreakpoint, PerfBreakpointSize::HwBreakpointLen1,
            PerfBreakpointType::HwBreakpointRW,
        },
    },
    util::online_cpus,
};
use log::info;

// Parse /proc/kallsyms and return the address for the given symbol name, if
// found.
fn find_kallsyms_symbol(sym: &str) -> Option<u64> {
    let file = File::open("/proc/kallsyms").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        // Format: "<addr> <type> <symbol> [<module>]"
        let mut parts = line.split_whitespace();
        let addr_str = parts.next()?;
        let _type = parts.next()?;
        let name = parts.next()?;
        if name == sym
            && let Ok(addr) = u64::from_str_radix(addr_str, 16)
        {
            return Some(addr);
        }
    }

    None
}

#[test_log::test]
fn perf_event_bp() {
    let mut bpf = Ebpf::load(crate::PERF_EVENT_BP).unwrap();

    let attach_addr = find_kallsyms_symbol("modprobe_path").unwrap();

    let prog: &mut aya::programs::PerfEvent = bpf
        .program_mut("perf_event_bp")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    // attach hardware breakpoint to modprobe_path global
    for cpu in online_cpus().unwrap() {
        info!("attaching to cpu {cpu}");
        prog.attach(
            PerfTypeId::Breakpoint,
            0u64,
            PerfEventScope::AllProcessesOneCpu { cpu },
            SamplePolicy::Period(1),
            true,
            Some(PerfBreakpoint {
                address: attach_addr,
                length: HwBreakpointLen1,
                type_: HwBreakpointRW,
            }),
        )
        .unwrap();
    }

    // trigger hardware breakpoint by reading modprobe_path via procfs
    let _ = fs::read_to_string("/proc/sys/kernel/modprobe");

    // assert that the map contains an entry for this process
    let map: aya::maps::HashMap<_, u32, u64> =
        aya::maps::HashMap::try_from(bpf.map_mut("READERS").unwrap()).unwrap();
    let tgid = std::process::id();
    let read_addr = map.get(&tgid, 0).unwrap();
    assert_eq!(read_addr, attach_addr);
}
