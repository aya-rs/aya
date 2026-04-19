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
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __s64);
  __uint(max_entries, SECOND_STRING_INDEX + SECOND_STRING_LEN);
} RESULTS SEC(".maps");

extern _Bool CONFIG_BPF __kconfig;
extern int CONFIG_PANIC_TIMEOUT __kconfig;
extern unsigned long CONFIG_DEFAULT_HUNG_TASK_TIMEOUT __kconfig __weak;
extern _Bool CONFIG_BPF_JIT __kconfig;
extern char CONFIG_DEFAULT_HOSTNAME[DEFAULT_HOSTNAME_LEN] __kconfig;
extern char CONFIG_FIRST_STRING[] __kconfig __weak;
extern char CONFIG_SECOND_STRING[] __kconfig __weak;

static long set_result(__u32 key, __s64 value) {
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
                   (__s64)(__u8)CONFIG_DEFAULT_HOSTNAME[i]) != 0) {
      return 1;
    }
  }
  return 0;
}

SEC("uprobe")
int test_kconfig_unsized_strings(void *ctx) {
  for (int i = 0; i < FIRST_STRING_LEN; i++) {
    if (set_result(FIRST_STRING_INDEX + i,
                   (__s64)(__u8)CONFIG_FIRST_STRING[i]) != 0) {
      return 1;
    }
  }
  for (int i = 0; i < SECOND_STRING_LEN; i++) {
    if (set_result(SECOND_STRING_INDEX + i,
                   (__s64)(__u8)CONFIG_SECOND_STRING[i]) != 0) {
      return 1;
    }
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
