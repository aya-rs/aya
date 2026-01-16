// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __type(value, __u32);
} map SEC(".maps");

SEC("uprobe")
int bpf_prog(void *ctx) {
  u32 val = 0xdeadbeef;

  u32 *buf;
  buf = bpf_ringbuf_reserve(&map, sizeof(__u32), 0);
  if (!buf) {
    return 0;
  }

  *buf = val;

  bpf_ringbuf_submit(buf, 0);

  return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
