#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) { return enum_signed_32_global(); }
