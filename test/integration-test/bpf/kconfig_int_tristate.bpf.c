// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern int CONFIG_INT_VALUE __kconfig;

SEC("uprobe")
int test_kconfig_int_tristate(void *ctx) { return CONFIG_INT_VALUE != 0; }

char _license[] SEC("license") = "GPL";
