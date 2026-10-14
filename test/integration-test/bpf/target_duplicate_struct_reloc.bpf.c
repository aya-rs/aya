#include "reloc.h"

#ifndef TARGET
struct relocated_target_duplicate_struct {
  __u32 classic;
  __u32 extended;
};
#endif

__noinline int target_duplicate_struct_global() {
  __u64 out = 0;
#ifndef TARGET
  struct relocated_target_duplicate_struct s = {1, 2};
  if (bpf_core_field_exists(s.classic)) {
    out += 1;
  }
  if (bpf_core_field_exists(s.extended)) {
    out += 2;
  }
#else
  // The target BTF has two structs with this name, each with one of the
  // members. A block can shadow a struct tag, and the CO-RE builtin keeps the
  // type in the BTF. The padding gives the members different access strings,
  // otherwise clang merges the two relocations into one.
  {
    struct relocated_target_duplicate_struct {
      __u32 classic;
    } s = {1};
    if (bpf_core_field_exists(s.classic)) {
      out += 1;
    }
  }
  {
    struct relocated_target_duplicate_struct {
      __u32 padding;
      __u32 extended;
    } s = {0, 2};
    if (bpf_core_field_exists(s.extended)) {
      out += 2;
    }
  }
#endif
  return set_output(out);
}

SEC("uprobe") int program(void *ctx) {
  return target_duplicate_struct_global();
}
