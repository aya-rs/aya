// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern char CONFIG_UNSIZED_STRING[] __kconfig;

SEC("uprobe")
int test_kconfig_invalid_array(void *ctx) {
  return CONFIG_UNSIZED_STRING[0] != 0;
}

char _license[] SEC("license") = "GPL";
