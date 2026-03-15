// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

// Layout of iproute2/tc's legacy map declaration struct. See
// https://git.kernel.org/pub/scm/linux/kernel/git/jkirsher/iproute2.git/tree/include/bpf_elf.h
struct bpf_elf_map {
  __u32 type;
  __u32 size_key;
  __u32 size_value;
  __u32 max_elem;
  __u32 flags;
  __u32 id;
  __u32 pinning;
  __u32 inner_id;
  __u32 inner_idx;
};

// Declares itself as an inner map for a would-be map-of-maps by setting
// inner_id. Aya does not support map-in-map for legacy maps, so this must be
// rejected at parse time rather than silently ignored.
struct bpf_elf_map SEC("maps") tc_map_in_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = 1,
    .id = 1,
    .inner_id = 1,
};

SEC("classifier")
int tc_pass(void *ctx) { return 0; }

char _license[] SEC("license") = "GPL";
