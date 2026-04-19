// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern _Bool CONFIG_BPF __kconfig;
extern unsigned short CONFIG_PANIC_TIMEOUT __kconfig;
extern unsigned int CONFIG_DEFAULT_HUNG_TASK_TIMEOUT __kconfig;
extern _Bool CONFIG_BPF_JIT __kconfig;
extern char CONFIG_DEFAULT_HOSTNAME[64] __kconfig;

SEC("uprobe")
int test_kconfig_current(void *ctx) {
  return CONFIG_BPF + CONFIG_PANIC_TIMEOUT + CONFIG_DEFAULT_HUNG_TASK_TIMEOUT +
         CONFIG_BPF_JIT + CONFIG_DEFAULT_HOSTNAME[0];
}

char _license[] SEC("license") = "GPL";
