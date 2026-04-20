// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int CONFIG_REQUIRED __kconfig;

SEC("uprobe")
int test_kconfig_missing_strong(void *ctx) {
  return CONFIG_REQUIRED != 0;
}

char _license[] SEC("license") = "GPL";
