// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned int UNKNOWN_OPTIONAL __kconfig __weak;

SEC("uprobe")
int test_kconfig_unknown_weak(void *ctx) {
  return UNKNOWN_OPTIONAL != 0;
}

char _license[] SEC("license") = "GPL";
