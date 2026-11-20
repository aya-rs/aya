//! Loads C and Rust programs whose `switch`/`match` LLVM lowered to a jump table.
//!
//! The object carries a `.jumptables` section with the case targets, an
//! `R_BPF_64_64` relocation against a `BPF.JT.*` symbol in that section and a
//! `gotox` (indirect jump) instruction. The loader has to turn the table into a
//! `BPF_MAP_TYPE_INSN_ARRAY` map and relocate the `ld_imm64` against it, as
//! libbpf does in `create_jt_map`. In each object one table sits in a program
//! and another in a subprogram shared by two programs, which link it at
//! different offsets.

use aya::{
    Ebpf, TestRunOptions, TestRunResult,
    maps::{Array, MapType},
    programs::{SocketFilter, TestRun as _},
    sys::is_map_supported,
};
use object::Object as _;

// Keep in sync with bpf/jumptable.bpf.c and integration-ebpf-jumptable.
const SELECTOR_KEY: u32 = 0;
const OPERAND_KEY: u32 = 1;

/// Mirrors `apply` in bpf/jumptable.bpf.c and integration-ebpf-jumptable.
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
    // Instruction array maps and `gotox` landed together; without them the kernel rejects the
    // programs no matter what the loader does.
    if !is_map_supported(MapType::InsnArray).unwrap() {
        eprintln!("skipping test - instruction array maps not supported");
        return;
    }

    // Each object has the same programs; the map is named by the source language's convention.
    for (toolchain, object, map) in [
        ("clang", crate::JUMPTABLE, "inputs"),
        ("bpf-linker", crate::JUMPTABLE_RUST, "INPUTS"),
    ] {
        // build.rs writes an empty object when the system clang rejects the jump table flags
        // (LLVM < 22); bpf-linker objects are never empty, build.rs fails instead.
        if object.is_empty() {
            eprintln!("skipping {toolchain} object - clang does not support BPF jump tables");
            continue;
        }
        // Make sure the switch was lowered to a jump table rather than compare-and-branch, or
        // the test would pass without exercising the loader.
        let file = object::File::parse(object).unwrap();
        assert!(
            file.section_by_name(".jumptables").is_some(),
            "{toolchain} object has no .jumptables section"
        );
        check_jump_tables(object, map);
    }
}

/// What a program computes from the selector and operand.
type Apply = fn(u64, u64) -> u64;

fn check_jump_tables(object: &[u8], map: &str) {
    // Mirrors the programs in bpf/jumptable.bpf.c and integration-ebpf-jumptable.
    const PROGRAMS: &[(&str, Apply)] = &[
        ("jumptable", apply),
        ("jumptable_subprog", apply),
        ("jumptable_subprog_twice", |selector, operand| {
            apply(selector, apply(selector, operand))
        }),
    ];

    let mut ebpf = Ebpf::load(object).unwrap();
    let mut inputs: Array<_, u64> = ebpf.take_map(map).unwrap().try_into().unwrap();

    const OPERAND: u64 = 1000;
    inputs.set(OPERAND_KEY, &OPERAND, 0).unwrap();

    // Socket filter test runs need at least an Ethernet header's worth of data.
    let data_in = [0u8; 64];
    let mut data_out = [0u8; 64];

    for (name, expected) in PROGRAMS {
        let prog: &mut SocketFilter = ebpf.program_mut(name).unwrap().try_into().unwrap();
        prog.load().unwrap();

        // Every jump table entry, then the out-of-range `default` branch.
        for selector in 0..=8 {
            inputs.set(SELECTOR_KEY, &selector, 0).unwrap();

            let opts = TestRunOptions {
                data_in: Some(&data_in),
                data_out: Some(&mut data_out),
                ..TestRunOptions::default()
            };
            let TestRunResult { return_value, .. } = prog.test_run(opts).unwrap();

            // The kernel reports the return value as a u32.
            assert_eq!(
                return_value,
                expected(selector, OPERAND) as u32,
                "{name}: selector {selector}"
            );
        }
    }
}
