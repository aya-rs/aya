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

#ifndef __weak
#define __weak __attribute__((weak))
#endif

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
  __type(key, __u32);
  __type(value, __u64);
} output SEC(".maps");

// Typed ksyms - declared weak for portability
extern const int nonexistent_typed_ksym __ksym __weak;

// Typeless ksyms (kallsyms-based)
extern const void init_task __ksym __weak;
extern const void nonexistent_typeless_ksym __ksym __weak;

// Kfuncs
extern void bpf_rcu_read_lock(void) __ksym __weak;
extern void bpf_rcu_read_unlock(void) __ksym __weak;
extern void bpf_rcu_read_lock_trace(void) __ksym __weak;
extern void bpf_rcu_read_unlock_trace(void) __ksym __weak;

// Program using WEAK typed ksyms - tests weak symbol resolution and kfuncs
// No per-cpu helpers here - those are tested in ksyms_typed_strong
SEC("tp_btf/sys_enter")
int BPF_PROG(ksyms_typed_weak, struct pt_regs *regs, long id) {
  __u32 key;
  __u64 val;

  // Weak typed ksym (nonexistent) - should resolve to 0
  key = 2;
  val = (&nonexistent_typed_ksym) ? 1 : 0;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Kfunc address
  key = 3;
  val = (__u64)(unsigned long)bpf_rcu_read_lock;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Kfunc call
  key = 4;
  if (bpf_rcu_read_lock) {
    bpf_rcu_read_lock();
    val = 1;
    bpf_rcu_read_unlock();
  } else {
    val = 0;
  }
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Marker
  key = 5;
  val = 0xDEADBEEF;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Second kfunc address
  key = 6;
  val = (__u64)(unsigned long)bpf_rcu_read_lock_trace;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Second kfunc call
  key = 7;
  if (bpf_rcu_read_lock_trace) {
    bpf_rcu_read_lock_trace();
    val = 1;
    bpf_rcu_read_unlock_trace();
  } else {
    val = 0;
  }
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  return 0;
}

// Program for typeless ksyms (kallsyms-based)
SEC("tp_btf/sys_enter")
int BPF_PROG(ksyms_typeless, struct pt_regs *regs, long id) {
  __u32 key;
  __u64 val;

  // Typeless ksym address (init_task)
  key = 8;
  val = (__u64)(unsigned long)&init_task;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Weak typeless ksym (nonexistent)
  key = 9;
  val = (__u64)(unsigned long)&nonexistent_typeless_ksym;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  // Marker
  key = 10;
  val = 0xCAFEBABE;
  bpf_map_update_elem(&output, &key, &val, BPF_ANY);

  return 0;
}
