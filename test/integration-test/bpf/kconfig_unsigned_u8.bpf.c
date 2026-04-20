// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned char CONFIG_TOO_LARGE __kconfig;

SEC("uprobe")
int test_kconfig_unsigned_u8(void *ctx) {
  return CONFIG_TOO_LARGE != 0;
}

char _license[] SEC("license") = "GPL";
