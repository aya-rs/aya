// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern _Bool CONFIG_BOOL_VALUE __kconfig;

SEC("uprobe")
int test_kconfig_invalid_bool(void *ctx) { return CONFIG_BOOL_VALUE; }

char _license[] SEC("license") = "GPL";
