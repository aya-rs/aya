#include "reloc.h"

struct relocated_struct_with_pointer {
#ifndef TARGET
  struct relocated_struct_with_pointer *first;
#endif
  struct relocated_struct_with_pointer *second;
#ifdef TARGET
  struct relocated_struct_with_pointer *first;
#endif
};

__noinline int pointer_global() {
  struct relocated_struct_with_pointer s = {
      (struct relocated_struct_with_pointer *)42,
      (struct relocated_struct_with_pointer *)21,
  };
  return set_output((__u64)__builtin_preserve_access_index(s.first));
}

SEC("uprobe") int program(void *ctx) { return pointer_global(); }
