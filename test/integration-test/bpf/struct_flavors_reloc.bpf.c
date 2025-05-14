#include "reloc.h"
#include "struct_with_scalars.h"

__noinline int struct_flavors_global() {
  struct relocated_struct_with_scalars s = {1, 2, 3};
#ifndef TARGET
  if (bpf_core_field_exists(s.a)) {
    return set_output(__builtin_preserve_access_index(s.a));
#else
  if (bpf_core_field_exists(s.d)) {
    return set_output(__builtin_preserve_access_index(s.d));
#endif
  } else {
    return set_output(__builtin_preserve_access_index(s.c));
  }
}

SEC("uprobe") int program(void *ctx) { return struct_flavors_global(); }
