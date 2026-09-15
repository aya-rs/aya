#include "reloc.h"

struct relocated_flex_array {
#ifdef TARGET
  __u64 padding;
#endif
  __u64 args[0];
};

SEC("uprobe") int program(void *ctx) {
  return set_output(
      bpf_core_field_offset(struct relocated_flex_array, args[2]));
}
