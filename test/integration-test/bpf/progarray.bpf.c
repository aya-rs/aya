// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(key_size, sizeof(uint32_t));
  __uint(value_size, sizeof(uint32_t));
  __uint(max_entries, 2);
  __array(values, int());
} jump_table SEC(".maps") = {
    .values =
        {
            [1] = &xdp_pass,
        },
};

SEC("xdp")
int prog_array_test(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &jump_table, 1);
  return XDP_ABORTED;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }
