// clang-format off
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
                                         __u64 *timestamp) __ksym;

// XDP program that calls a device-bound metadata kfunc. Without
// BPF_F_XDP_DEV_BOUND_ONLY the kernel verifier rejects the load with
// "metadata kfuncs require device-bound program".
SEC("xdp")
int xdp_dev_bound_kfunc(struct xdp_md *ctx) {
  __u64 timestamp = 0;
  (void)bpf_xdp_metadata_rx_timestamp(ctx, &timestamp);
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
