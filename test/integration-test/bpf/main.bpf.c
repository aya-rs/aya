// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// clang-format on

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }

char _license[] SEC("license") = "GPL";
