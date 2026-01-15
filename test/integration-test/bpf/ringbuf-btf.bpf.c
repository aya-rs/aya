// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
  u32 pid;
  u8 comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __type(value, struct event);
} events SEC(".maps");

SEC("uprobe")
int bpf_prog(void *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  struct event *task_info;

  task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  task_info->pid = tgid;
  bpf_get_current_comm(&task_info->comm, TASK_COMM_LEN);

  bpf_ringbuf_submit(task_info, 0);

  return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
