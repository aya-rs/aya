// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, char[32]);
  __type(value, __u8);
} executed_once SEC(".maps");

#define assign_str(target, str)

// BPF will not allow us to write out of bounds, so we skip the length checks
#define mark_executed(key)                                                     \
  {                                                                            \
    __u8 __executed = 1;                                                       \
    char __probe_type[32] = {};                                                \
    __builtin_memcpy(__probe_type, key, sizeof(key));                          \
    bpf_map_update_elem(&executed_once, &__probe_type, &__executed, BPF_ANY);  \
  }                                                                            \
  do {                                                                         \
  } while (0)

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_tp_btf, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
  mark_executed("tp_btf");
  return 0;
}

SEC("tracepoint/sched/sched_switch")
int sched_switch_tp(bool preempt, struct task_struct *prev,
                    struct task_struct *next) {
  mark_executed("tracepoint");
  return 0;
}

char _license[] SEC("license") = "GPL";