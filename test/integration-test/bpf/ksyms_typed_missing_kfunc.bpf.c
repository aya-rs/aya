// clang-format off
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

char _license[] SEC("license") = "GPL";

extern void nonexistent_kfunc(void) __ksym;

SEC("tp_btf/sys_enter")
int BPF_PROG(ksyms_typed_missing_kfunc, struct pt_regs *regs, long id) {
  nonexistent_kfunc();
  return 0;
}
