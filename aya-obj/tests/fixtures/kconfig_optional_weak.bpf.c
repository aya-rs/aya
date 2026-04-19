// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int CONFIG_REQUIRED __kconfig;
extern unsigned int CONFIG_OPTIONAL __kconfig __weak;

SEC("uprobe")
int test_kconfig_optional_weak(void *ctx) {
  return CONFIG_REQUIRED + CONFIG_OPTIONAL;
}

char _license[] SEC("license") = "GPL";
