#include "reloc.h"
#include "struct_with_scalars.h"

__noinline int field_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
  return set_output(__builtin_preserve_access_index(s.b));
}

SEC("uprobe") int program(void *ctx) { return field_global(); }
