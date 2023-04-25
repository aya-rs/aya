#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 2);
} RESULTS SEC(".maps");

static __u64
inc_cb(void *map, __u32 *key, void *val,
	       void *data)
{
	__u64 *value = val;
	*value += 1;
	return 0;
}

SEC("uprobe/test_text_64_64_reloc")
int test_text_64_64_reloc(struct pt_regs *ctx)
{
	bpf_for_each_map_elem(&RESULTS, inc_cb, NULL, 0);
    return 0;
}

