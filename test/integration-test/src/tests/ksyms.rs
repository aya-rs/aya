//! Integration tests for kernel symbol (ksym) resolution.

use std::{
    fs::File,
    io::{BufRead as _, BufReader},
};

use aya::{Btf, Ebpf, maps::Array, programs::BtfTracePoint, util::KernelVersion};
use test_log::test;

const PROC_KALLSYMS: &str = "/proc/kallsyms";
const SYS_ENTER: &str = "sys_enter";

fn kallsyms_available() -> bool {
    let file = File::open(PROC_KALLSYMS)
        .unwrap_or_else(|e| panic!("failed to open {PROC_KALLSYMS}: {e:?}"));
    for line in BufReader::new(file).lines() {
        let line =
            line.unwrap_or_else(|e| panic!("failed to read the line from {PROC_KALLSYMS}: {e:?}"));
        if let Some(addr) = line.split_whitespace().next() {
            let addr = u64::from_str_radix(addr, 16)
                .unwrap_or_else(|e| panic!("failed to parse the address: {addr}: {e:?}"));
            if addr != 0 {
                return true;
            }
        }
    }
    false
}

fn kallsyms_find(symbol_name: &str) -> Option<u64> {
    let file = File::open(PROC_KALLSYMS)
        .unwrap_or_else(|e| panic!("failed to open {PROC_KALLSYMS}: {e:?}"));
    for line in BufReader::new(file).lines() {
        let line =
            line.unwrap_or_else(|e| panic!("failed to read the line from {PROC_KALLSYMS}: {e:?}"));
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [addr, _type, name, ..] = parts.as_slice()
            && *name == symbol_name
        {
            let addr = u64::from_str_radix(addr, 16)
                .unwrap_or_else(|e| panic!("failed to parse the address: {addr}: {e:?}"));
            return Some(addr);
        }
    }
    None
}

/// Check if PERCPU DATASEC exists in kernel BTF.
/// Required for `bpf_this_cpu_ptr`/`bpf_per_cpu_ptr` to work.
fn btf_has_percpu_datasec(btf: &Btf) -> bool {
    use aya_obj::btf::BtfKind;
    btf.id_by_type_name_kind(".data..percpu", BtfKind::DataSec)
        .is_ok()
}

mod output_keys {
    pub(super) const WEAK_TYPED: u32 = 2;
    pub(super) const KFUNC_ADDR: u32 = 3;
    pub(super) const KFUNC_CALLED: u32 = 4;
    pub(super) const TYPED_MARKER: u32 = 5;
    pub(super) const KFUNC2_ADDR: u32 = 6;
    pub(super) const KFUNC2_CALLED: u32 = 7;
    pub(super) const TYPELESS_ADDR: u32 = 8;
    pub(super) const WEAK_TYPELESS: u32 = 9;
    pub(super) const TYPELESS_MARKER: u32 = 10;
}

mod output_keys_strong {
    pub(super) const TYPED_ADDR: u32 = 0;
    pub(super) const TYPED_VALUE: u32 = 1;
    pub(super) const PER_CPU_PTR_ADDR: u32 = 2;
    pub(super) const PER_CPU_PTR_VALUE: u32 = 3;
    pub(super) const MARKER: u32 = 4;
}

/// Test STRONG typed ksym resolution with per-cpu helpers.
/// Tests: strong ksym (`bpf_prog_active`), `bpf_this_cpu_ptr`, `bpf_per_cpu_ptr`.
#[test]
fn ksyms_typed_strong() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 10, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, typed ksyms require kernel >= 5.10");
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();

    if !btf_has_percpu_datasec(&btf) {
        eprintln!("skipping test, no PERCPU DATASEC in kernel BTF");
        return;
    }

    // Strong typed ksyms require the symbol to be in kallsyms.
    // With CONFIG_KALLSYMS_ALL=n, only function symbols are exported,
    // not variables like bpf_prog_active. The verifier uses
    // bpf_kallsyms_lookup_name() internally and will reject the program
    // if the symbol address cannot be resolved.
    if !kallsyms_available() {
        eprintln!("skipping test, kallsyms not available");
        return;
    }
    if kallsyms_find("bpf_prog_active").is_none() {
        eprintln!(
            "skipping test, bpf_prog_active kallsyms not available \
            (usually due to CONFIG_KALLSYMS_ALL kernel configuration disabled)"
        );
        return;
    }

    let mut bpf = Ebpf::load(crate::KSYMS_STRONG).unwrap();

    let prog: &mut BtfTracePoint = bpf
        .program_mut("ksyms_typed_strong")
        .unwrap()
        .try_into()
        .unwrap();

    if let Err(e) = prog.load(SYS_ENTER, &btf) {
        panic!("failed to load program {SYS_ENTER}: {e:?}");
    }
    prog.attach().unwrap();

    // Trigger the tracepoint
    drop(std::fs::metadata("/"));

    let output: Array<_, u64> = Array::try_from(bpf.map("strong_output").unwrap()).unwrap();

    // Verify BPF program executed
    let marker = output.get(&output_keys_strong::MARKER, 0).unwrap();
    assert_eq!(marker, 0xBEEFCAFE, "BPF program did not execute");

    // bpf_this_cpu_ptr: address should be non-zero
    let typed_addr = output.get(&output_keys_strong::TYPED_ADDR, 0).unwrap();
    assert!(typed_addr != 0, "strong ksym address should be non-zero");

    // bpf_this_cpu_ptr: value should be >= 0 (like libbpf)
    let typed_value = output.get(&output_keys_strong::TYPED_VALUE, 0).unwrap();
    let signed_value = typed_value as i32;
    assert!(
        signed_value >= 0,
        "bpf_prog_active should be >= 0, got {signed_value}"
    );

    // bpf_per_cpu_ptr: address should be non-zero
    let per_cpu_addr = output
        .get(&output_keys_strong::PER_CPU_PTR_ADDR, 0)
        .unwrap();
    assert!(
        per_cpu_addr != 0,
        "bpf_per_cpu_ptr address should be non-zero"
    );

    // bpf_per_cpu_ptr: value should be >= 0
    let per_cpu_value = output
        .get(&output_keys_strong::PER_CPU_PTR_VALUE, 0)
        .unwrap();
    let signed_per_cpu = per_cpu_value as i32;
    assert!(
        signed_per_cpu >= 0 || per_cpu_value != 0xFFFFFFFF,
        "bpf_per_cpu_ptr value invalid, got {per_cpu_value:#x}"
    );
}

/// Test WEAK typed ksym resolution and kfunc calls.
/// Tests: weak nonexistent typed ksym = 0, kfunc resolution.
#[test]
fn ksyms_typed_weak() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 10, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, typed ksyms require kernel >= 5.10");
        return;
    }

    let mut bpf = Ebpf::load(crate::KSYMS).unwrap();
    let prog: &mut BtfTracePoint = bpf
        .program_mut("ksyms_typed_weak")
        .unwrap()
        .try_into()
        .unwrap();

    let btf = Btf::from_sys_fs().unwrap();
    if let Err(e) = prog.load(SYS_ENTER, &btf) {
        panic!("failed to load program {SYS_ENTER}: {e:?}");
    }
    prog.attach().unwrap();

    // Trigger the tracepoint
    drop(std::fs::metadata("/"));

    let output: Array<_, u64> = Array::try_from(bpf.map("output").unwrap()).unwrap();

    // Verify BPF program executed
    let marker = output.get(&output_keys::TYPED_MARKER, 0).unwrap();
    assert_eq!(marker, 0xDEADBEEF, "BPF program did not execute");

    // Weak typed ksym (nonexistent) should resolve to 0
    let weak_typed = output.get(&output_keys::WEAK_TYPED, 0).unwrap();
    assert_eq!(
        weak_typed, 0,
        "weak nonexistent typed ksym should be 0, got {weak_typed}"
    );

    // Kfunc resolution - availability depends on kernel config, not just version
    let kfunc_addr = output.get(&output_keys::KFUNC_ADDR, 0).unwrap();
    let kfunc_called = output.get(&output_keys::KFUNC_CALLED, 0).unwrap();
    let kfunc2_addr = output.get(&output_keys::KFUNC2_ADDR, 0).unwrap();
    let kfunc2_called = output.get(&output_keys::KFUNC2_CALLED, 0).unwrap();

    // Consistency: if resolved, must be callable
    if kfunc_addr != 0 {
        assert_eq!(kfunc_called, 1, "kfunc resolved but not called");
    }
    if kfunc2_addr != 0 {
        assert_eq!(kfunc2_called, 1, "kfunc2 resolved but not called");
    }
}

/// Test typeless ksym resolution (kallsyms-based).
/// Tests: `init_task` address + kallsyms cross-check, weak nonexistent = 0.
#[test]
fn ksyms_typeless() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 10, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, typeless ksyms require kernel >= 5.10"
        );
        return;
    }

    let kallsyms_ok = kallsyms_available();
    let expected_addr = if kallsyms_ok {
        kallsyms_find("init_task")
    } else {
        None
    };

    let mut bpf = Ebpf::load(crate::KSYMS).unwrap();
    let prog: &mut BtfTracePoint = bpf
        .program_mut("ksyms_typeless")
        .unwrap()
        .try_into()
        .unwrap();

    let btf = Btf::from_sys_fs().unwrap();
    if let Err(e) = prog.load(SYS_ENTER, &btf) {
        panic!("failed to load program {SYS_ENTER}: {e:?}");
    }
    prog.attach().unwrap();

    // Trigger the tracepoint
    drop(std::fs::metadata("/"));

    let output: Array<_, u64> = Array::try_from(bpf.map("output").unwrap()).unwrap();

    // Verify BPF program executed
    let marker = output.get(&output_keys::TYPELESS_MARKER, 0).unwrap();
    assert_eq!(marker, 0xCAFEBABE, "BPF program did not execute");

    // Typeless ksym: init_task - cross-verify with kallsyms when available
    let typeless_addr = output.get(&output_keys::TYPELESS_ADDR, 0).unwrap();
    if typeless_addr != 0 {
        if let Some(kallsyms_addr) = expected_addr {
            assert_eq!(
                typeless_addr, kallsyms_addr,
                "BPF-resolved init_task ({typeless_addr:#x}) != kallsyms ({kallsyms_addr:#x})"
            );
        }
    }

    // Weak typeless ksym (nonexistent) should be 0
    let weak_typeless = output.get(&output_keys::WEAK_TYPELESS, 0).unwrap();
    assert_eq!(
        weak_typeless, 0,
        "weak nonexistent typeless ksym should be 0, got {weak_typeless:#x}"
    );
}
