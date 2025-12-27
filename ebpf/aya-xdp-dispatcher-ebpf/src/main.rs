// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Contributors of Aya and Authors of bpfd
// from https://github.com/bpfman/bpfman/blob/cfdcc21909f80d8c81cf176462fe869e0de7bf79/bpfd-ebpf/src/xdp.rs
#![no_std]
#![no_main]

#[cfg(target_arch = "bpf")]
pub mod prog;
