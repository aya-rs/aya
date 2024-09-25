// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

// CONFIG_BPF=y => 1
extern unsigned int CONFIG_BPF __kconfig;
// CONFIG_PANIC_TIMEOUT=0 => 0
extern unsigned int CONFIG_PANIC_TIMEOUT __kconfig;
// CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120
extern unsigned int CONFIG_DEFAULT_HUNG_TASK_TIMEOUT __kconfig;

SEC("xdp")
int kconfig(struct xdp_md *ctx) {
  if (CONFIG_BPF != 1) {
    return XDP_DROP;
  }

  if (CONFIG_PANIC_TIMEOUT != 0) {
    return XDP_DROP;
  }

  if (CONFIG_DEFAULT_HUNG_TASK_TIMEOUT != 120) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
