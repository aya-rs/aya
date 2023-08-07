// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) { return XDP_DROP; }

char _license[] SEC("license") = "GPL";
