#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) {
  return enum_signed_32_checked_variants_global();
}
