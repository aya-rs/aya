// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

// Omitting function info everywhere is valid.
static __noinline __attribute__((nodebug)) unsigned int callee(void) {
  return bpf_get_prandom_u32();
}

SEC("socket")
__attribute__((nodebug)) int entry(void *ctx) { return callee(); }

char _license[] SEC("license") = "GPL";
