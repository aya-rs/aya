//! Rust counterpart of `test/integration-test/bpf/jumptable.bpf.c`.
//!
//! This crate is built with `-Ctarget-cpu=v4` and
//! `-Clink-arg=--llvm-args=-bpf-min-jump-table-entries=4` so that LLVM lowers
//! the `match` below to a jump table: the arm targets land in a `.jumptables`
//! section referenced by an `R_BPF_64_64` relocation against a `BPF.JT.*`
//! symbol, and the dispatch is a `gotox` (indirect jump) instruction.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::Array,
    programs::SkBuffContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static INPUTS: Array<u64> = Array::with_max_entries(2, 0);

const SELECTOR_KEY: u32 = 0;
const OPERAND_KEY: u32 = 1;

// Each arm applies a distinct operation to a runtime operand so that LLVM
// cannot fold the `match` into arithmetic or a lookup table.
#[inline(always)]
const fn apply(selector: u64, operand: u64) -> u64 {
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

// A subprogram owning a jump table: its relocation lives in `.rel.text` and the
// table entries must be rebased to wherever the subprogram is linked in each
// program that calls it.
#[inline(never)]
const fn apply_subprog(selector: u64, operand: u64) -> u64 {
    apply(selector, operand)
}

#[inline(always)]
fn inputs() -> Option<(u64, u64)> {
    Some((*INPUTS.get(SELECTOR_KEY)?, *INPUTS.get(OPERAND_KEY)?))
}

// The table lives in the program itself.
#[socket_filter]
fn jumptable(_ctx: SkBuffContext) -> i64 {
    let Some((selector, operand)) = inputs() else {
        return 0;
    };
    apply(selector, operand) as i64
}

// The table lives in `apply_subprog`.
#[socket_filter]
fn jumptable_subprog(_ctx: SkBuffContext) -> i64 {
    let Some((selector, operand)) = inputs() else {
        return 0;
    };
    apply_subprog(selector, operand) as i64
}

// Same subprogram, linked at a different offset: the two programs need
// different instruction array maps for the same table.
#[socket_filter]
fn jumptable_subprog_twice(_ctx: SkBuffContext) -> i64 {
    let Some((selector, operand)) = inputs() else {
        return 0;
    };
    apply_subprog(selector, apply_subprog(selector, operand)) as i64
}
