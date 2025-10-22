// clang-format off
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
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u64);
} output_map SEC(".maps");

/* Typeless ksym variable - resolved via /proc/kallsyms */
/* init_task is the initial kernel task, available on all architectures */
extern const void init_task __ksym;

/* Weak kfuncs - available on kernel 5.19+ */
extern void bpf_rcu_read_lock(void) __ksym __weak;
extern void bpf_rcu_read_unlock(void) __ksym __weak;

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id) {
  __u32 key;
  __u64 value;

  /* Test 1: Typeless ksym variable (init_task) - resolved via kallsyms */
  /* Just verify the address was resolved (non-zero) */
  key = 0;
  value = (unsigned long)&init_task;
  bpf_map_update_elem(&output_map, &key, &value, BPF_ANY);

  /* Test 2: Weak kfunc (if available on 5.19+) */
  key = 1;
  if (bpf_rcu_read_lock) {
    bpf_rcu_read_lock();
    value = 1; /* kfunc available */
    bpf_rcu_read_unlock();
  } else {
    value = 0; /* kfunc not available */
  }
  bpf_map_update_elem(&output_map, &key, &value, BPF_ANY);

  return 0;
}
