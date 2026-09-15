#include "reloc.h"

struct relocated_target_fixed_array {
#ifdef TARGET
  __u64 args[1];
#else
  __u64 args[2];
#endif
};

SEC("uprobe") int program(void *ctx) {
  return set_output(
      bpf_core_field_exists(struct relocated_target_fixed_array, args[1]));
}
