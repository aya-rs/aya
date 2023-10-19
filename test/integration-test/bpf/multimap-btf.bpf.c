// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 2);
} map_1 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 2);
} map_2 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 2);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_pin_by_name SEC(".maps");

SEC("uprobe")
int bpf_prog(void *ctx) {
  __u32 key = 0;
  __u64 twenty_four = 24;
  __u64 forty_two = 42;
  __u64 forty_four = 44;

  bpf_map_update_elem(&map_1, &key, &twenty_four, BPF_ANY);
  bpf_map_update_elem(&map_2, &key, &forty_two, BPF_ANY);
  bpf_map_update_elem(&map_pin_by_name, &key, &forty_four, BPF_ANY);
  return 0;
}

SEC("uprobe")
int bpf_prog1(void *ctx) {
  __u32 key = 1;
  __u64 twenty_four = 35;
  __u64 forty_two = 53;
  __u64 forty_four = 55;

  bpf_map_update_elem(&map_1, &key, &twenty_four, BPF_ANY);
  bpf_map_update_elem(&map_2, &key, &forty_two, BPF_ANY);
  bpf_map_update_elem(&map_pin_by_name, &key, &forty_four, BPF_ANY);
  return 0;
}

char _license[] SEC("license") = "GPL";
