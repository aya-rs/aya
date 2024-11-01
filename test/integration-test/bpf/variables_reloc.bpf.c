// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

volatile unsigned int key1 = 0;       // .bss
volatile unsigned int key2 = 1;       // .data
volatile const unsigned int key3 = 2; // .rodata

SEC("xdp")
int variables_reloc(struct xdp_md *ctx) {
  if (key1 == 0 && key2 != 1 && key3 != 2) {
    key1 += 1;
    key2 += 1;
    return XDP_DROP;
  } else {
    return XDP_PASS;
  }
}

char _license[] SEC("license") = "GPL";
