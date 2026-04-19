// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int LINUX_HAS_FUTURE_FEATURE __kconfig __weak;

SEC("uprobe")
int test_kconfig_virtuals(void *ctx) {
  return LINUX_HAS_FUTURE_FEATURE;
}

char _license[] SEC("license") = "GPL";
