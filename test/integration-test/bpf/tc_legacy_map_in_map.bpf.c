// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf_elf.h>
// clang-format on

// Sets inner_id, which tc uses to declare a map-of-maps. Aya does not support
// map-of-maps for legacy maps, so this must be rejected at parse time rather
// than silently ignored.
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
