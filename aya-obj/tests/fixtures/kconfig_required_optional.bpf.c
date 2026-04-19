// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int CONFIG_REQUIRED __kconfig;
extern unsigned int CONFIG_OPTIONAL __kconfig __weak;
extern unsigned int UNKNOWN_OPTIONAL __kconfig __weak;
extern unsigned int LINUX_HAS_FUTURE_FEATURE __kconfig __weak;

SEC("uprobe")
int test_kconfig_required_optional(void *ctx) {
  return CONFIG_REQUIRED + CONFIG_OPTIONAL + UNKNOWN_OPTIONAL +
         LINUX_HAS_FUTURE_FEATURE;
}

char _license[] SEC("license") = "GPL";
