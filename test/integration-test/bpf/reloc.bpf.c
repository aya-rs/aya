// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

char _license[] SEC("license") = "GPL";

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
#ifndef TARGET
  __u8 a;
#endif
  __u8 b;
  __u8 c;
#ifdef TARGET
  __u8 d;
#endif
};

__noinline int field_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
  return set_output(__builtin_preserve_access_index(s.b));
}

SEC("uprobe") int field(void *ctx) { return field_global(); }

struct relocated_struct_with_pointer {
#ifndef TARGET
  struct relocated_struct_with_pointer *first;
#endif
  struct relocated_struct_with_pointer *second;
#ifdef TARGET
  struct relocated_struct_with_pointer *first;
#endif
};

__noinline int pointer_global() {
  struct relocated_struct_with_pointer s = {
      (struct relocated_struct_with_pointer *)42,
      (struct relocated_struct_with_pointer *)21,
  };
  return set_output((__u64)__builtin_preserve_access_index(s.first));
}

SEC("uprobe") int pointer(void *ctx) { return pointer_global(); }

__noinline int struct_flavors_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
#ifndef TARGET
  if (bpf_core_field_exists(s.a)) {
    return set_output(__builtin_preserve_access_index(s.a));
#else
  if (bpf_core_field_exists(s.d)) {
    return set_output(__builtin_preserve_access_index(s.d));
#endif
  } else {
    return set_output(__builtin_preserve_access_index(s.c));
  }
}

SEC("uprobe") int struct_flavors(void *ctx) { return struct_flavors_global(); }

enum relocated_enum_unsigned_32 {
  U32_VAL =
#ifndef TARGET
      0xAAAAAAAA
#else
      0xBBBBBBBB
#endif
};

__noinline int enum_unsigned_32_global() {
  return set_output(
      bpf_core_enum_value(enum relocated_enum_unsigned_32, U32_VAL));
}

SEC("uprobe") int enum_unsigned_32(void *ctx) {
  return enum_unsigned_32_global();
}

enum relocated_enum_unsigned_32_checked_variants {
#ifndef TARGET
  U32_VAL_A = 0xAAAAAAAA,
#endif
  U32_VAL_B = 0xBBBBBBBB,
#ifdef TARGET
  U32_VAL_C = 0xCCCCCCCC
#endif
};

__noinline int enum_unsigned_32_checked_variants_global() {
#ifndef TARGET
  if (bpf_core_enum_value_exists(
          enum relocated_enum_unsigned_32_checked_variants, U32_VAL_A)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_unsigned_32_checked_variants, U32_VAL_A));
#else
  if (bpf_core_enum_value_exists(
          enum relocated_enum_unsigned_32_checked_variants, U32_VAL_C)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_unsigned_32_checked_variants, U32_VAL_C));
#endif
  } else {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_unsigned_32_checked_variants, U32_VAL_B));
  }
}

SEC("uprobe") int enum_unsigned_32_checked_variants(void *ctx) {
  return enum_unsigned_32_checked_variants_global();
}

enum relocated_enum_signed_32 {
  S32_VAL =
#ifndef TARGET
      -0x7AAAAAAA
#else
      -0x7BBBBBBB
#endif
};

__noinline int enum_signed_32_global() {
  return set_output(
      bpf_core_enum_value(enum relocated_enum_signed_32, S32_VAL));
}

SEC("uprobe") int enum_signed_32(void *ctx) { return enum_signed_32_global(); }

enum relocated_enum_signed_32_checked_variants {
#ifndef TARGET
  S32_VAL_A = -0x7AAAAAAA,
#endif
  S32_VAL_B = -0x7BBBBBBB,
#ifdef TARGET
  S32_VAL_C = -0x7CCCCCCC
#endif
};

__noinline int enum_signed_32_checked_variants_global() {
#ifndef TARGET
  if (bpf_core_enum_value_exists(enum relocated_enum_signed_32_checked_variants,
                                 S32_VAL_A)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_signed_32_checked_variants, S32_VAL_A));
#else
  if (bpf_core_enum_value_exists(enum relocated_enum_signed_32_checked_variants,
                                 S32_VAL_C)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_signed_32_checked_variants, S32_VAL_C));
#endif
  } else {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_signed_32_checked_variants, S32_VAL_B));
  }
}

SEC("uprobe") int enum_signed_32_checked_variants(void *ctx) {
  return enum_signed_32_checked_variants_global();
}

enum relocated_enum_unsigned_64 {
  U64_VAL =
#ifndef TARGET
      0xAAAAAAAABBBBBBBB
#else
      0xCCCCCCCCDDDDDDDD
#endif
};

__noinline int enum_unsigned_64_global() {
  return set_output(
      bpf_core_enum_value(enum relocated_enum_unsigned_64, U64_VAL));
}

SEC("uprobe") int enum_unsigned_64(void *ctx) {
  return enum_unsigned_64_global();
}

enum relocated_enum_unsigned_64_checked_variants {
#ifndef TARGET
  U64_VAL_A = 0xAAAAAAAABBBBBBBB,
#endif
  U64_VAL_B = 0xCCCCCCCCDDDDDDDD,
#ifdef TARGET
  U64_VAL_C = 0xEEEEEEEEFFFFFFFF
#endif
};

__noinline int enum_unsigned_64_checked_variants_global() {
#ifndef TARGET
  if (bpf_core_enum_value_exists(
          enum relocated_enum_unsigned_64_checked_variants, U64_VAL_A)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_unsigned_64_checked_variants, U64_VAL_A));
#else
  if (bpf_core_enum_value_exists(
          enum relocated_enum_unsigned_64_checked_variants, U64_VAL_C)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_unsigned_64_checked_variants, U64_VAL_C));
#endif
  } else {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_unsigned_64_checked_variants, U64_VAL_B));
  }
}

SEC("uprobe") int enum_unsigned_64_checked_variants(void *ctx) {
  return enum_unsigned_64_checked_variants_global();
}

enum relocated_enum_signed_64 {
  S64_VAL =
#ifndef TARGET
      -0xAAAAAAABBBBBBBB
#else
      -0xCCCCCCCDDDDDDDD
#endif
};

__noinline int enum_signed_64_global() {
  return set_output(
      bpf_core_enum_value(enum relocated_enum_signed_64, S64_VAL));
}

SEC("uprobe") int enum_signed_64(void *ctx) { return enum_signed_64_global(); }

enum relocated_enum_signed_64_checked_variants {
#ifndef TARGET
  S64_VAL_A = -0xAAAAAAABBBBBBB,
#endif
  S64_VAL_B = -0xCCCCCCCDDDDDDD,
#ifdef TARGET
  S64_VAL_C = -0xEEEEEEEFFFFFFF
#endif
};

__noinline int enum_signed_64_checked_variants_global() {
#ifndef TARGET
  if (bpf_core_enum_value_exists(enum relocated_enum_signed_64_checked_variants,
                                 S64_VAL_A)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_signed_64_checked_variants, S64_VAL_A));
#else
  if (bpf_core_enum_value_exists(enum relocated_enum_signed_64_checked_variants,
                                 S64_VAL_C)) {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_signed_64_checked_variants, S64_VAL_C));
#endif
  } else {
    return set_output(bpf_core_enum_value(
        enum relocated_enum_signed_64_checked_variants, S64_VAL_B));
  }
}

SEC("uprobe") int enum_signed_64_checked_variants(void *ctx) {
  return enum_signed_64_checked_variants_global();
}
