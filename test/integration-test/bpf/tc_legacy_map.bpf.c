// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf_elf.h>
// clang-format on

struct bpf_elf_map SEC("maps") tc_map_1 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = 1,
    .id = 1,
};

struct bpf_elf_map SEC("maps") tc_map_2 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = 2,
    .id = 2,
};

SEC("classifier")
int tc_pass(void *ctx) {
  __u32 key = 0;
  __u32 val = 42;

  bpf_map_update_elem(&tc_map_1, &key, &val, BPF_ANY);
  bpf_map_update_elem(&tc_map_2, &key, &val, BPF_ANY);
  return 0;
}

char _license[] SEC("license") = "GPL";
