//! Integration tests for kernel symbol (ksym) resolution.

use std::{
    fs::File,
    io::{BufRead as _, BufReader},
};

use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf, EbpfError,
    maps::Array,
    programs::{BtfTracePoint, ProgramError},
};
use aya_obj::{
    KsymsError,
    btf::{BtfError, BtfKind},
};
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
    let Some(btf) = super::kernel_btf() else {
        return;
    };

    let var_in_btf = match btf.id_by_type_name_kind("bpf_prog_active", BtfKind::Var) {
        Ok(_id) => true,
        Err(BtfError::UnknownBtfTypeName { type_name }) => {
            assert_eq!(type_name, "bpf_prog_active");
            false
        }
        Err(error) => panic!("unexpected kernel BTF error: {error}"),
    };
    let loaded = Ebpf::load(crate::KSYMS_STRONG);
    if !var_in_btf {
        assert_matches!(loaded, Err(EbpfError::KsymsError(KsymsError::VariableNotFound { name })) => {
            assert_eq!(name, "bpf_prog_active");
        });
        return;
    }
    let mut bpf = loaded.unwrap();

    let config = procfs::kernel_config().unwrap();
    let kallsyms_all = matches!(
        config.get("CONFIG_KALLSYMS_ALL"),
        Some(procfs::ConfigSetting::Yes)
    );
    let percpu_datasec = btf_has_percpu_datasec(&btf);

    let prog: &mut BtfTracePoint = bpf
        .program_mut("ksyms_typed_strong")
        .unwrap()
        .try_into()
        .unwrap();

    let loaded = prog.load(SYS_ENTER, &btf);
    if !kallsyms_all {
        // The verifier resolves a BTF variable's address through kallsyms.
        // https://github.com/torvalds/linux/blob/v5.15/kernel/bpf/verifier.c#L11260-L11266
        assert_matches!(loaded, Err(ProgramError::LoadError { io_error, verifier_log }) => {
            assert_eq!(io_error.raw_os_error(), Some(libc::ENOENT), "{verifier_log}");
            assert!(verifier_log.to_string().contains("failed to find the address for kernel symbol 'bpf_prog_active'"), "{verifier_log}");
        });
        return;
    }
    if !percpu_datasec {
        // Without the BTF per-CPU section the verifier cannot type this ksym
        // as the argument required by bpf_this_cpu_ptr.
        // https://github.com/torvalds/linux/blob/v5.15/kernel/bpf/verifier.c#L11272-L11295
        assert_matches!(loaded, Err(ProgramError::LoadError { io_error, verifier_log }) => {
            assert_eq!(io_error.raw_os_error(), Some(libc::EACCES), "{verifier_log}");
            assert!(verifier_log.to_string().contains("expected=percpu"), "{verifier_log}");
        });
        return;
    }
    loaded.unwrap();
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
        signed_per_cpu >= 0,
        "bpf_per_cpu_ptr value should be >= 0, got {signed_per_cpu}"
    );
}

/// Test WEAK typed ksym resolution and kfunc calls.
/// Tests: weak nonexistent typed ksym = 0, kfunc resolution.
#[test]
fn ksyms_typed_weak() {
    let Some(btf) = super::kernel_btf() else {
        return;
    };
    let mut bpf = Ebpf::load(crate::KSYMS).unwrap();
    let prog: &mut BtfTracePoint = bpf
        .program_mut("ksyms_typed_weak")
        .unwrap()
        .try_into()
        .unwrap();

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

    assert_eq!(kfunc_called, u64::from(kfunc_addr != 0));
    assert_eq!(kfunc2_called, u64::from(kfunc2_addr != 0));
}

/// Test typeless ksym resolution (kallsyms-based).
/// Tests: `init_task` address + kallsyms cross-check, weak nonexistent = 0.
#[test]
fn ksyms_typeless() {
    let kallsyms_ok = kallsyms_available();
    let expected_addr = if kallsyms_ok {
        kallsyms_find("init_task")
    } else {
        None
    };

    let Some(btf) = super::kernel_btf() else {
        return;
    };
    let mut bpf = Ebpf::load(crate::KSYMS).unwrap();
    let prog: &mut BtfTracePoint = bpf
        .program_mut("ksyms_typeless")
        .unwrap()
        .try_into()
        .unwrap();

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

    // Typeless weak ksym: resolve init_task exactly when kallsyms exposes it.
    let typeless_addr = output.get(&output_keys::TYPELESS_ADDR, 0).unwrap();
    assert_eq!(typeless_addr, expected_addr.unwrap_or(0));

    // Weak typeless ksym (nonexistent) should be 0
    let weak_typeless = output.get(&output_keys::WEAK_TYPELESS, 0).unwrap();
    assert_eq!(
        weak_typeless, 0,
        "weak nonexistent typeless ksym should be 0, got {weak_typeless:#x}"
    );
}

#[test]
fn ksyms_typed_missing_var_fails_at_load() {
    let err = Ebpf::load(crate::KSYMS_TYPED_MISSING_VAR).unwrap_err();
    if super::vmlinux_btf_missing() {
        super::assert_missing_vmlinux_btf_on_load(err);
        return;
    }
    match err {
        EbpfError::KsymsError(KsymsError::VariableNotFound { name }) => {
            assert_eq!(name, "totally_bogus_symbol");
        }
        other => panic!("expected VariableNotFound KsymsError, got {other:?}"),
    }
}

#[test]
fn ksyms_typed_missing_kfunc_fails_at_load() {
    let err = Ebpf::load(crate::KSYMS_TYPED_MISSING_KFUNC).unwrap_err();
    if super::vmlinux_btf_missing() {
        super::assert_missing_vmlinux_btf_on_load(err);
        return;
    }
    match err {
        EbpfError::KsymsError(KsymsError::FunctionNotFound { name }) => {
            assert_eq!(name, "nonexistent_kfunc");
        }
        other => panic!("expected FunctionNotFound KsymsError, got {other:?}"),
    }
}

#[test]
fn ksyms_typeless_missing_fails_at_load() {
    let err = Ebpf::load(crate::KSYMS_TYPELESS_MISSING).unwrap_err();
    match err {
        EbpfError::KsymsError(KsymsError::VariableNotFound { name }) => {
            assert_eq!(name, "totally_bogus_typeless_symbol");
        }
        other => panic!("expected VariableNotFound KsymsError, got {other:?}"),
    }
}
