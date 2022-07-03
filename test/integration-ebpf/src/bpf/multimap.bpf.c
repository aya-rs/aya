#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

const int XDP_ACTION_MAX = (XDP_TX + 1);

struct datarec {
	__u64 rx_packets;
};

// stats keyed by XDP Action
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

// tracks number of times called
struct bpf_map_def SEC("maps") prog_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};

SEC("xdp/stats")
int  xdp_stats(struct xdp_md *ctx)
{
    __u64 *stats;
	struct datarec *rec;
	__u32 key = XDP_PASS;
	__u32 k1 = 0;

    stats = bpf_map_lookup_elem(&prog_stats_map, &k1);
    if (!stats)
        return XDP_ABORTED;
    __sync_fetch_and_add(stats, 1);

	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;
	__sync_fetch_and_add(&rec->rx_packets, 1);
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
