#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

// This probe writes a zero to rb every time the sched_switch tracepoint is hit.
SEC("tracepoint/sched/sched_switch")
int sched_switch(struct switch_args* ctx)
{
    unsigned long long e = 0;
    bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
    return 0;
}
