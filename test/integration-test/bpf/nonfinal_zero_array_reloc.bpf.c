#include "reloc.h"

struct relocated_nonfinal_zero_array {
  __u64 args[0];
  __u64 tail;
};

SEC("uprobe") int program(void *ctx) {
  return set_output(
      bpf_core_field_offset(struct relocated_nonfinal_zero_array, args[1]));
}
