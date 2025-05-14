#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) { return enum_unsigned_64_global(); }
