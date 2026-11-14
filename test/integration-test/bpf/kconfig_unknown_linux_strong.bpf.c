// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int LINUX_HAS_FUTURE_FEATURE __kconfig;

SEC("uprobe")
int test_kconfig_unknown_linux_strong(void *ctx) {
  return LINUX_HAS_FUTURE_FEATURE != 0;
}

char _license[] SEC("license") = "GPL";
