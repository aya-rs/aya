// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern signed char CONFIG_SIGNED_VALUE __kconfig;

SEC("uprobe")
int test_kconfig_signed_i8(void *ctx) { return CONFIG_SIGNED_VALUE != 0; }

char _license[] SEC("license") = "GPL";
