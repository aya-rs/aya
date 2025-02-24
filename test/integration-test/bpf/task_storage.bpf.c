// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
// clang-format on

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u32);
} task_storage SEC(".maps");

SEC("fentry/sched_post_fork")
int BPF_PROG(sched_post_fork, struct task_struct *task) {
  __u32 value = 1;
  bpf_task_storage_get(&task_storage, task, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  return 0;
}
