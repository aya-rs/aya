#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) {
  return enum_unsigned_32_checked_variants_global();
}
