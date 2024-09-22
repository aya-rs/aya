// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int CONFIG_BPF __kconfig;

SEC("xdp")
int kconfig(struct xdp_md *ctx) {
  if (!CONFIG_BPF) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
