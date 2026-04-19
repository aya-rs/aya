// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

extern unsigned char CONFIG_BYTE __kconfig;
extern unsigned int CONFIG_TRIMMED __kconfig;
extern unsigned int CONFIG_PADDED __kconfig;
extern unsigned char CONFIG_TOO_LARGE __kconfig;
extern signed char CONFIG_TOO_POSITIVE __kconfig;
extern signed char CONFIG_TOO_NEGATIVE __kconfig;
extern _Bool CONFIG_BOOL_VALUE __kconfig;
extern char CONFIG_CHAR_VALUE __kconfig;
extern enum libbpf_tristate CONFIG_TRISTATE_ENUM __kconfig;

SEC("uprobe")
int test_kconfig_scalars(void *ctx) {
  return CONFIG_BYTE + CONFIG_TRIMMED + CONFIG_PADDED + CONFIG_TOO_LARGE +
         CONFIG_TOO_POSITIVE + CONFIG_TOO_NEGATIVE + CONFIG_BOOL_VALUE +
         CONFIG_CHAR_VALUE + CONFIG_TRISTATE_ENUM;
}

char _license[] SEC("license") = "GPL";
