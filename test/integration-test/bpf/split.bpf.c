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

// Try to access ip_tables structures. In most distros, ip_tables is compiled
// and loaded as a separate module, making it a pretty good target.
struct ipt_entry {
    __u16 target_offset;
}

SEC("uprobe") int check_can_access_module(void *ctx) {
    if (bpf_core_type_exists(struct ipt_entry) && bpf_core_field_offset(struct ipt_entry, target_offset) != 0) {
        // We successfully accessed target_offset in ipt_entry.
        set_output(1);
    } else {
        set_output(0);
    }
}
