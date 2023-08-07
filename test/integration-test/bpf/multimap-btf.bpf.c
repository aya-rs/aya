// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} map_1 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} map_2 SEC(".maps");

SEC("tracepoint")
int bpf_prog(void *ctx) {
  __u32 key = 0;
  __u64 twenty_four = 24;
  __u64 forty_two = 42;
  bpf_map_update_elem(&map_1, &key, &twenty_four, BPF_ANY);
  bpf_map_update_elem(&map_2, &key, &forty_two, BPF_ANY);
  return 0;
}

char _license[] SEC("license") = "GPL";
