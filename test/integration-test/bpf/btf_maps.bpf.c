// Test that BTF maps can be loaded by libbpf.
// This C program uses the same BTF map structure that our Rust btf_maps
// produce.

// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

// BTF Array map - equivalent to aya_ebpf::btf_maps::Array
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 10);
} btf_array SEC(".maps");

// BTF RingBuf map - equivalent to aya_ebpf::btf_maps::RingBuf
// Note: value_size must be 0 for ring buffers
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 12);
} btf_ringbuf SEC(".maps");

SEC("uprobe")
int test_btf_array(void *ctx) {
  __u32 key = 0;
  __u32 value = 42;
  bpf_map_update_elem(&btf_array, &key, &value, 0);
  return 0;
}

SEC("uprobe")
int test_btf_ringbuf(void *ctx) {
  __u32 *data = bpf_ringbuf_reserve(&btf_ringbuf, sizeof(__u32), 0);
  if (data) {
    *data = 0xdeadbeef;
    bpf_ringbuf_submit(data, 0);
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
