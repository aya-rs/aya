// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern enum libbpf_tristate CONFIG_TRISTATE_ENUM __kconfig;

SEC("uprobe")
int test_kconfig_tristate_enum(void *ctx) { return CONFIG_TRISTATE_ENUM; }

char _license[] SEC("license") = "GPL";
