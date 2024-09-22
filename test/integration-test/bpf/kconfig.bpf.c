// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

// Test char (1 byte alignment)
// CONFIG_BPF=y => 1
extern unsigned char CONFIG_BPF __kconfig;
// Test short (2 byte alignment)
// CONFIG_PANIC_TIMEOUT=0 => 0
extern unsigned short CONFIG_PANIC_TIMEOUT __kconfig;
// Test int (4 byte alignment)
// CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120
extern unsigned int CONFIG_DEFAULT_HUNG_TASK_TIMEOUT __kconfig;
// Test long (8 byte alignment)
// CONFIG_BPF_JIT=y => 1
extern unsigned long CONFIG_BPF_JIT __kconfig;
// CONFIG_DEFAULT_HOSTNAME
extern char CONFIG_DEFAULT_HOSTNAME[] __kconfig;

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

  if (CONFIG_BPF_JIT != 1) {
    return XDP_DROP;
  }

  for (int i = 0; i < 7; i++) {
    if ("(none)"[i] != CONFIG_DEFAULT_HOSTNAME[i]) {
      return XDP_DROP;
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
