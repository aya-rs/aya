// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

enum other_enum {
  OTHER_VALUE = 1,
};

extern enum other_enum CONFIG_NOT_TRISTATE __kconfig;

SEC("uprobe")
int test_kconfig_non_tristate_enum(void *ctx) { return CONFIG_NOT_TRISTATE; }

char _license[] SEC("license") = "GPL";
