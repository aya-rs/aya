// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

struct inner_map_type {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 10);            // Size is different from the outer map
  __uint(map_flags, BPF_F_INNER_MAP); // Flag required due to ^^^
} inner_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __type(key, __u32); // value omitted as should be fixed by loader
  __uint(max_entries, 1);
  __array(values, struct inner_map_type);
} outer_array_map SEC(".maps") = {
    .values =
        {
            [0] = &inner_map,
        },
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __type(key, __u32); // value omitted as should be fixed by loader
  __uint(max_entries, 1);
  __array(values, struct inner_map_type);
} outer_hash_map SEC(".maps") = {
    .values =
        {
            [0] = &inner_map,
        },
};

static int map_in_map_test(void *outer_map) {
  int key = 0;
  int value = 42;
  void *inner_map;

  inner_map = bpf_map_lookup_elem(outer_map, &key);
  if (!inner_map)
    return 0;

  bpf_map_update_elem(inner_map, &key, &value, 0);

  return 0;
}

SEC("xdp")
int mim_test_array(struct xdp_md *ctx) {
  map_in_map_test(&outer_array_map);
  return XDP_PASS;
}

SEC("xdp")
int mim_test_hash(struct xdp_md *ctx) {
  map_in_map_test(&outer_hash_map);
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
