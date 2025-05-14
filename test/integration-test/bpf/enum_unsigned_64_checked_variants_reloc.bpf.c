#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) {
  return enum_unsigned_64_checked_variants_global();
}
