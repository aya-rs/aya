#include "reloc.h"

struct relocated_target_nonfinal_zero_array {
#ifdef TARGET
  __u64 args[0];
#else
  __u64 args[2];
#endif
  __u64 tail;
};

SEC("uprobe") int program(void *ctx) {
  return set_output(bpf_core_field_exists(
      struct relocated_target_nonfinal_zero_array, args[1]));
}
