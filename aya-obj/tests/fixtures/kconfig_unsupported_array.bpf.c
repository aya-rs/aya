// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int CONFIG_UNSUPPORTED_ARRAY[4] __kconfig;

SEC("uprobe")
int test_kconfig_unsupported_array(void *ctx) {
  return CONFIG_UNSUPPORTED_ARRAY[0];
}

char _license[] SEC("license") = "GPL";
