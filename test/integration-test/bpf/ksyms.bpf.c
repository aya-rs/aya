#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} counter_map SEC(".maps");

extern void bpf_rcu_read_lock(void) __attribute__((section(".ksyms")));
extern void bpf_rcu_read_unlock(void) __attribute__((section(".ksyms")));

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id) {
  __u32 key = 0;
  __u64 *count;

  bpf_rcu_read_lock();

  count = bpf_map_lookup_elem(&counter_map, &key);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }

  bpf_rcu_read_unlock();
  return 0;
}