// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#define CONFIG_BPF_INDEX 0
#define PANIC_TIMEOUT_INDEX 1
#define DEFAULT_HUNG_TASK_TIMEOUT_INDEX 2
#define BPF_JIT_INDEX 3
#define DEFAULT_HOSTNAME_INDEX 4
#define DEFAULT_HOSTNAME_LEN 64
#define FIRST_STRING_INDEX (DEFAULT_HOSTNAME_INDEX + DEFAULT_HOSTNAME_LEN)
#define FIRST_STRING_LEN 2
#define SECOND_STRING_INDEX (FIRST_STRING_INDEX + FIRST_STRING_LEN)
#define SECOND_STRING_LEN 6
#define OPTIONAL_INDEX (SECOND_STRING_INDEX + SECOND_STRING_LEN)
#define BYTE_INDEX (OPTIONAL_INDEX + 1)
#define TRIMMED_INDEX (BYTE_INDEX + 1)
#define PADDED_INDEX (TRIMMED_INDEX + 1)
#define BOOL_VALUE_INDEX (PADDED_INDEX + 1)
#define CHAR_VALUE_INDEX (BOOL_VALUE_INDEX + 1)
#define TRISTATE_ENUM_INDEX (CHAR_VALUE_INDEX + 1)
#define FUTURE_LINUX_INDEX (TRISTATE_ENUM_INDEX + 1)
#define TRUNCATED_STRING_INDEX (FUTURE_LINUX_INDEX + 1)
#define TRUNCATED_STRING_LEN 4
#define OPTIONAL_STRING_INDEX (TRUNCATED_STRING_INDEX + TRUNCATED_STRING_LEN)
#define OPTIONAL_STRING_LEN 1
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, OPTIONAL_STRING_INDEX + OPTIONAL_STRING_LEN);
} RESULTS SEC(".maps");

extern _Bool CONFIG_BPF __kconfig;
extern unsigned short CONFIG_PANIC_TIMEOUT __kconfig;
extern unsigned int CONFIG_DEFAULT_HUNG_TASK_TIMEOUT __kconfig;
extern _Bool CONFIG_BPF_JIT __kconfig;
extern unsigned int CONFIG_OPTIONAL __kconfig __weak;
extern unsigned char CONFIG_BYTE __kconfig;
extern unsigned int CONFIG_TRIMMED __kconfig;
extern unsigned int CONFIG_PADDED __kconfig;
extern _Bool CONFIG_BOOL_VALUE __kconfig;
extern char CONFIG_CHAR_VALUE __kconfig;
extern enum libbpf_tristate CONFIG_TRISTATE_ENUM __kconfig;
extern char CONFIG_DEFAULT_HOSTNAME[DEFAULT_HOSTNAME_LEN] __kconfig;
extern char CONFIG_FIRST_STRING[] __kconfig;
extern char CONFIG_SECOND_STRING[] __kconfig;
extern char CONFIG_TRUNCATED_STRING[TRUNCATED_STRING_LEN] __kconfig;
extern char CONFIG_OPTIONAL_STRING[] __kconfig __weak;
extern unsigned int LINUX_HAS_FUTURE_FEATURE __kconfig __weak;

static long set_result(__u32 key, __u64 value) {
  return bpf_map_update_elem(&RESULTS, &key, &value, BPF_ANY);
}

SEC("uprobe")
int test_kconfig(void *ctx) {
  if (set_result(CONFIG_BPF_INDEX, CONFIG_BPF) != 0) {
    return 1;
  }
  if (set_result(PANIC_TIMEOUT_INDEX, CONFIG_PANIC_TIMEOUT) != 0) {
    return 1;
  }
  if (set_result(DEFAULT_HUNG_TASK_TIMEOUT_INDEX,
                 CONFIG_DEFAULT_HUNG_TASK_TIMEOUT) != 0) {
    return 1;
  }
  if (set_result(BPF_JIT_INDEX, CONFIG_BPF_JIT) != 0) {
    return 1;
  }
  for (int i = 0; i < DEFAULT_HOSTNAME_LEN; i++) {
    if (set_result(DEFAULT_HOSTNAME_INDEX + i,
                   (__u64)(__u8)CONFIG_DEFAULT_HOSTNAME[i]) != 0) {
      return 1;
    }
  }
  return 0;
}

SEC("uprobe")
int test_kconfig_unsized_strings(void *ctx) {
  for (int i = 0; i < FIRST_STRING_LEN; i++) {
    if (set_result(FIRST_STRING_INDEX + i,
                   (__u64)(__u8)CONFIG_FIRST_STRING[i]) != 0) {
      return 1;
    }
  }
  for (int i = 0; i < SECOND_STRING_LEN; i++) {
    if (set_result(SECOND_STRING_INDEX + i,
                   (__u64)(__u8)CONFIG_SECOND_STRING[i]) != 0) {
      return 1;
    }
  }
  return 0;
}

SEC("uprobe")
int test_kconfig_semantics(void *ctx) {
  if (set_result(OPTIONAL_INDEX, CONFIG_OPTIONAL) != 0) {
    return 1;
  }
  if (set_result(BYTE_INDEX, CONFIG_BYTE) != 0) {
    return 1;
  }
  if (set_result(TRIMMED_INDEX, CONFIG_TRIMMED) != 0) {
    return 1;
  }
  if (set_result(PADDED_INDEX, CONFIG_PADDED) != 0) {
    return 1;
  }
  if (set_result(BOOL_VALUE_INDEX, CONFIG_BOOL_VALUE) != 0) {
    return 1;
  }
  if (set_result(CHAR_VALUE_INDEX, (__u64)(__u8)CONFIG_CHAR_VALUE) != 0) {
    return 1;
  }
  if (set_result(TRISTATE_ENUM_INDEX, CONFIG_TRISTATE_ENUM) != 0) {
    return 1;
  }
  if (set_result(FUTURE_LINUX_INDEX, LINUX_HAS_FUTURE_FEATURE) != 0) {
    return 1;
  }
  for (int i = 0; i < TRUNCATED_STRING_LEN; i++) {
    if (set_result(TRUNCATED_STRING_INDEX + i,
                   (__u64)(__u8)CONFIG_TRUNCATED_STRING[i]) != 0) {
      return 1;
    }
  }
  for (int i = 0; i < OPTIONAL_STRING_LEN; i++) {
    if (set_result(OPTIONAL_STRING_INDEX + i,
                   (__u64)(__u8)CONFIG_OPTIONAL_STRING[i]) != 0) {
      return 1;
    }
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
