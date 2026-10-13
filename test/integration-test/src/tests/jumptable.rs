//! Loads a C program whose `switch` LLVM lowered to a jump table.
//!
//! The object carries a `.jumptables` section with the case targets, an
//! `R_BPF_64_64` relocation against a `BPF.JT.*` symbol in that section and a
//! `gotox` (indirect jump) instruction. The loader has to turn the table into a
//! `BPF_MAP_TYPE_INSN_ARRAY` map and relocate the `ld_imm64` against it, as
//! libbpf does in `create_jt_map`.

use aya::{
    Ebpf, TestRunOptions, TestRunResult,
    maps::{Array, MapType},
    programs::{SocketFilter, TestRun as _},
    sys::is_map_supported,
};

// Keep in sync with bpf/jumptable.bpf.c.
const SELECTOR_KEY: u32 = 0;
const OPERAND_KEY: u32 = 1;

/// Mirrors `apply` in bpf/jumptable.bpf.c.
fn apply(selector: u64, operand: u64) -> u64 {
    match selector {
        0 => operand.wrapping_add(7),
        1 => operand.wrapping_mul(3),
        2 => operand ^ 0x55,
        3 => operand >> 1,
        4 => (operand << 4) | 1,
        5 => !operand,
        6 => operand.wrapping_sub(11),
        7 => operand % 13,
        _ => 0xdead,
    }
}

#[test_log::test]
fn jumptable() {
    // build.rs writes an empty object when clang cannot emit jump tables (LLVM < 22).
    if crate::JUMPTABLE.is_empty() {
        eprintln!("skipping test - clang does not support BPF jump tables");
        return;
    }
    // Instruction array maps and `gotox` landed together; without them the kernel rejects the
    // program no matter what the loader does.
    if !is_map_supported(MapType::InsnArray).unwrap() {
        eprintln!("skipping test - instruction array maps not supported");
        return;
    }

    let mut ebpf = Ebpf::load(crate::JUMPTABLE).unwrap();
    let mut inputs: Array<_, u64> = ebpf.take_map("inputs").unwrap().try_into().unwrap();
    let prog: &mut SocketFilter = ebpf.program_mut("jumptable").unwrap().try_into().unwrap();
    prog.load().unwrap();

    const OPERAND: u64 = 1000;
    inputs.set(OPERAND_KEY, &OPERAND, 0).unwrap();

    // Socket filter test runs need at least an Ethernet header's worth of data.
    let data_in = [0u8; 64];
    let mut data_out = [0u8; 64];

    // Every jump table entry, then the out-of-range `default` branch.
    for selector in 0..=8 {
        inputs.set(SELECTOR_KEY, &selector, 0).unwrap();

        let opts = TestRunOptions {
            data_in: Some(&data_in),
            data_out: Some(&mut data_out),
            ..TestRunOptions::default()
        };
        let TestRunResult { return_value, .. } = prog.test_run(opts).unwrap();

        // The program returns `(int)apply(...)`, which the kernel reports as a u32.
        assert_eq!(
            return_value,
            apply(selector, OPERAND) as u32,
            "selector {selector}"
        );
    }
}
