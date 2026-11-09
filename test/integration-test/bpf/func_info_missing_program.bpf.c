// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

static __noinline unsigned int callee(void) { return bpf_get_prandom_u32(); }

// Model a program built without debug information calling a dependency with it.
SEC("socket")
__attribute__((nodebug)) int entry(void *ctx) { return callee(); }

char _license[] SEC("license") = "GPL";
