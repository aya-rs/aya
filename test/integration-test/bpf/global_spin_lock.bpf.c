// clang-format off
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

char _license[] SEC("license") = "GPL";

// A lock and the counter it protects, in a data section of their own. The
// verifier only lets a program take the lock if the map created for the
// section has BTF that describes it.
#define locked SEC(".data.locked") __hidden __attribute__((aligned(8)))

locked struct bpf_spin_lock lock;
locked __u64 packets;

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  bpf_spin_lock(&lock);
  packets++;
  bpf_spin_unlock(&lock);
  return XDP_PASS;
}
