#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) {
  return enum_signed_64_checked_variants_global();
}
