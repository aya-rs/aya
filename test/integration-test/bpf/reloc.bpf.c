// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} output_map SEC(".maps");

long set_output(__u64 value) {
  __u32 key = 0;
  return bpf_map_update_elem(&output_map, &key, &value, BPF_ANY);
}

struct relocated_struct_with_scalars {
  __u8 a;
  __u8 b;
  __u8 c;
};

__attribute__((noinline)) int relocate_field_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
  return set_output(__builtin_preserve_access_index(s.b));
}

SEC("uprobe/relocate_field") int relocate_field(void *ctx) {
  return relocate_field_global();
}

struct relocated_struct_with_pointer {
  struct relocated_struct_with_pointer *first;
  struct relocated_struct_with_pointer *second;
};

__attribute__((noinline)) int relocate_pointer_global() {
  struct relocated_struct_with_pointer s = {
      (struct relocated_struct_with_pointer *)42,
      (struct relocated_struct_with_pointer *)21,
  };
  return set_output((__u64)__builtin_preserve_access_index(s.first));
}

SEC("uprobe/relocate_pointer") int relocate_pointer(void *ctx) {
  return relocate_pointer_global();
}

__attribute__((noinline)) int struct_flavors_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
  if (bpf_core_field_exists(s.a)) {
    return set_output(__builtin_preserve_access_index(s.a));
  } else {
    return set_output(__builtin_preserve_access_index(s.b));
  }
}

SEC("uprobe/struct_flavors") int struct_flavors(void *ctx) {
  return struct_flavors_global();
}

enum relocated_enum_unsigned_32 { U32 = 0xAAAAAAAA };

__attribute__((noinline)) int relocate_enum_unsigned_32_global() {
  return set_output(bpf_core_enum_value(enum relocated_enum_unsigned_32, U32));
}

SEC("uprobe/relocate_enum_unsigned_32")
int relocate_enum_unsigned_32(void *ctx) {
  return relocate_enum_unsigned_32_global();
}

enum relocated_enum_signed_32 { S32 = -0x7AAAAAAA };

__attribute__((noinline)) int relocate_enum_signed_32_global() {
  return set_output(bpf_core_enum_value(enum relocated_enum_signed_32, S32));
}

SEC("uprobe/relocate_enum_signed_32") int relocate_enum_signed_32(void *ctx) {
  return relocate_enum_signed_32_global();
}

enum relocated_enum_unsigned_64 { U64 = 0xAAAAAAAABBBBBBBB };

__attribute__((noinline)) int relocate_enum_unsigned_64_global() {
  return set_output(bpf_core_enum_value(enum relocated_enum_unsigned_64, U64));
}

SEC("uprobe/relocate_enum_unsigned_64")
int relocate_enum_unsigned_64(void *ctx) {
  return relocate_enum_unsigned_64_global();
}

enum relocated_enum_signed_64 { u64 = -0xAAAAAAABBBBBBBB };

__attribute__((noinline)) int relocate_enum_signed_64_global() {
  return set_output(bpf_core_enum_value(enum relocated_enum_signed_64, u64));
}

SEC("uprobe/relocate_enum_signed_64") int relocate_enum_signed_64(void *ctx) {
  return relocate_enum_signed_64_global();
}
