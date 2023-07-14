#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern unsigned int CONFIG_BPF __kconfig;

SEC("xdp/pass")
int xdp_pass(struct xdp_md *ctx)
{
    if (!CONFIG_BPF) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
