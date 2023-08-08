// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// clang-format on

long set_output(__u64 value) { return 0; }

struct relocated_struct_with_scalars {
  __u8 b;
  __u8 c;
  __u8 d;
};

__attribute__((noinline)) int field_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
  return set_output(__builtin_preserve_access_index(s.b));
}

struct relocated_struct_with_pointer {
  struct relocated_struct_with_pointer *second;
  struct relocated_struct_with_pointer *first;
};

__attribute__((noinline)) int pointer_global() {
  struct relocated_struct_with_pointer s = {
      (struct relocated_struct_with_pointer *)42,
      (struct relocated_struct_with_pointer *)21,
  };
  return set_output((__u64)__builtin_preserve_access_index(s.first));
}

__attribute__((noinline)) int struct_flavors_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
  if (bpf_core_field_exists(s.b)) {
    return set_output(__builtin_preserve_access_index(s.b));
  } else {
    return set_output(__builtin_preserve_access_index(s.c));
  }
}

enum relocated_enum_unsigned_32 { MyU32 = 0xBBBBBBBB };

__attribute__((noinline)) int enum_unsigned_32_global() {
  return set_output(
      bpf_core_enum_value(enum relocated_enum_unsigned_32, MyU32));
}

enum relocated_enum_signed_32 { MyS32 = -0x7BBBBBBB };

__attribute__((noinline)) int enum_signed_32_global() {
  return set_output(bpf_core_enum_value(enum relocated_enum_signed_32, MyS32));
}

enum relocated_enum_unsigned_64 { MyU64 = 0xCCCCCCCCDDDDDDDD };

__attribute__((noinline)) int enum_unsigned_64_global() {
  return set_output(
      bpf_core_enum_value(enum relocated_enum_unsigned_64, MyU64));
}

enum relocated_enum_signed_64 { MyS64 = -0xCCCCCCCDDDDDDDD };

__attribute__((noinline)) int enum_signed_64_global() {
  return set_output(bpf_core_enum_value(enum relocated_enum_signed_64, MyS64));
}

// Avoids dead code elimination by the compiler.
int main() {
  field_global();
  pointer_global();
  struct_flavors_global();
  enum_unsigned_32_global();
  enum_signed_32_global();
  enum_unsigned_64_global();
  enum_signed_64_global();
}
