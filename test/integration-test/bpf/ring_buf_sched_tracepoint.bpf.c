#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

// This probe writes a zero to rb every time the sched_switch tracepoint is hit.
//
// TODO(https://github.com/aya-rs/aya/issues/375): This should be called something like
// "tracepoint/sched/sched_switch" but there's a bug related to loading tracepoints with such names.
// Fix that and rename this.
SEC("tracepoint")
int bpf_prog(struct switch_args* ctx)
{
    unsigned long long e = 0;
    bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
    return 0;
}
