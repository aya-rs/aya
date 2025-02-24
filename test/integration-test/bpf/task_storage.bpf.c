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

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id) {
  __u32 value = 1;
  struct task_struct *task = bpf_get_current_task_btf();
  bpf_task_storage_get(&task_storage, task, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
}
