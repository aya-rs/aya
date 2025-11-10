// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} output_map SEC(".maps");

long set_output(__u64 value) {
  __u32 key = 0;
  return bpf_map_update_elem(&output_map, &key, &value, BPF_ANY);
}
