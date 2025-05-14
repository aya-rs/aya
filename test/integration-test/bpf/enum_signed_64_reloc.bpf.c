#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) { return enum_signed_64_global(); }
