// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

// Compiled with `-mcpu=v4 -mllvm -bpf-min-jump-table-entries=4` so that LLVM
// lowers the switch below to a jump table: the case targets land in a
// `.jumptables` section referenced by an `R_BPF_64_64` relocation against a
// `BPF.JT.*` symbol, and the dispatch is a `gotox` (indirect jump) instruction.
// The loader must turn that section into a BPF_MAP_TYPE_INSN_ARRAY map, which
// libbpf does in `create_jt_map`.

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 2);
} inputs SEC(".maps");

#define SELECTOR_KEY 0
#define OPERAND_KEY 1

// Each case applies a distinct operation to a runtime operand so that LLVM
// cannot fold the switch into arithmetic or a `.rodata` lookup table.
static __always_inline __u64 apply(__u64 selector, __u64 operand) {
  switch (selector) {
  case 0:
    return operand + 7;
  case 1:
    return operand * 3;
  case 2:
    return operand ^ 0x55;
  case 3:
    return operand >> 1;
  case 4:
    return (operand << 4) | 1;
  case 5:
    return ~operand;
  case 6:
    return operand - 11;
  case 7:
    return operand % 13;
  default:
    return 0xdead;
  }
}

// A global subprogram owning a jump table: its relocation lives in `.rel.text`
// and the table entries must be rebased to wherever the subprogram is linked in
// each program that calls it.
__noinline __u64 apply_subprog(__u64 selector, __u64 operand) {
  return apply(selector, operand);
}

static __always_inline int lookup(__u64 **selector, __u64 **operand) {
  __u32 selector_key = SELECTOR_KEY;
  __u32 operand_key = OPERAND_KEY;
  *selector = bpf_map_lookup_elem(&inputs, &selector_key);
  *operand = bpf_map_lookup_elem(&inputs, &operand_key);
  return *selector && *operand;
}

// The table lives in the program itself.
SEC("socket")
int jumptable(struct __sk_buff *skb) {
  __u64 *selector, *operand;
  if (!lookup(&selector, &operand))
    return 0;
  return (int)apply(*selector, *operand);
}

// The table lives in `apply_subprog`.
SEC("socket")
int jumptable_subprog(struct __sk_buff *skb) {
  __u64 *selector, *operand;
  if (!lookup(&selector, &operand))
    return 0;
  return (int)apply_subprog(*selector, *operand);
}

// Same subprogram, linked at a different offset: the two programs need
// different instruction array maps for the same table.
SEC("socket")
int jumptable_subprog_twice(struct __sk_buff *skb) {
  __u64 *selector, *operand;
  if (!lookup(&selector, &operand))
    return 0;
  return (int)apply_subprog(*selector, apply_subprog(*selector, *operand));
}

char _license[] SEC("license") = "GPL";
