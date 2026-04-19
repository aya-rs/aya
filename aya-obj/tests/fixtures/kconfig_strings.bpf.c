// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern char CONFIG_DEFAULT_HOSTNAME[] __kconfig;
extern char CONFIG_TRUNCATED_STRING[4] __kconfig;
extern char CONFIG_OPTIONAL_STRING[] __kconfig __weak;

SEC("uprobe")
int test_kconfig_strings(void *ctx) {
  return CONFIG_DEFAULT_HOSTNAME[0] + CONFIG_TRUNCATED_STRING[0] +
         CONFIG_OPTIONAL_STRING[0];
}

char _license[] SEC("license") = "GPL";
