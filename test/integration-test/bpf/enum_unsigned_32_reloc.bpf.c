#include "reloc.h"

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

SEC("uprobe") int program(void *ctx) { return enum_unsigned_32_global(); }
