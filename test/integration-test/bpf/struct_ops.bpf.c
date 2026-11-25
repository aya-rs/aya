// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

// The bundled vmlinux.h predates sched_ext. Only the pointer type is needed.
struct scx_exit_info;

SEC("struct_ops.s/init")
int BPF_PROG(scx_init) { return 0; }

// Keep this global and void-returning to exercise loading without a linkage
// rewrite. Loading the callback does not activate a scheduler.
SEC("struct_ops/exit")
void BPF_PROG(scx_exit, struct scx_exit_info *ei) {}

char _license[] SEC("license") = "GPL";
