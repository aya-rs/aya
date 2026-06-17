// clang-format off
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 8);
  __type(key, __u32);
  __type(value, __u64);
} module_output SEC(".maps");

extern const int aya_ksyms_test_var __ksym;

SEC("tp_btf/sys_enter")
int BPF_PROG(ksyms_module_btf, struct pt_regs *regs, long id) {
  __u32 key;
  __u64 val;
  int *p;

  key = 0;
  p = bpf_this_cpu_ptr(&aya_ksyms_test_var);
  val = (__u64)(unsigned long)p;
  bpf_map_update_elem(&module_output, &key, &val, BPF_ANY);

  key = 1;
  val = p ? (__u64)*p : 0;
  bpf_map_update_elem(&module_output, &key, &val, BPF_ANY);

  key = 2;
  val = p ? 0 : 1;
  bpf_map_update_elem(&module_output, &key, &val, BPF_ANY);

  key = 3;
  val = 0xA11CEB7F;
  bpf_map_update_elem(&module_output, &key, &val, BPF_ANY);

  return 0;
}
