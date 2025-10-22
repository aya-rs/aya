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
} strong_output SEC(".maps");

// STRONG typed ksym - NO __weak
// If this symbol is not in kernel BTF, aya will fail at Ebpf::load()
extern const int bpf_prog_active __ksym;

SEC("tp_btf/sys_enter")
int BPF_PROG(ksyms_typed_strong, struct pt_regs *regs, long id) {
  __u32 key;
  __u64 val;

  // bpf_this_cpu_ptr - uses strong ksym directly
  key = 0;
  int *p = bpf_this_cpu_ptr(&bpf_prog_active);
  val = (__u64)(unsigned long)p;
  bpf_map_update_elem(&strong_output, &key, &val, BPF_ANY);

  // Read value
  key = 1;
  val = p ? (__u64)*p : 0;
  bpf_map_update_elem(&strong_output, &key, &val, BPF_ANY);

  // bpf_per_cpu_ptr for CPU 0
  key = 2;
  int *p0 = bpf_per_cpu_ptr(&bpf_prog_active, 0);
  val = (__u64)(unsigned long)p0;
  bpf_map_update_elem(&strong_output, &key, &val, BPF_ANY);

  key = 3;
  val = p0 ? (__u64)*p0 : 0xFFFFFFFF;
  bpf_map_update_elem(&strong_output, &key, &val, BPF_ANY);

  // Marker
  key = 4;
  val = 0xBEEFCAFE;
  bpf_map_update_elem(&strong_output, &key, &val, BPF_ANY);

  return 0;
}
