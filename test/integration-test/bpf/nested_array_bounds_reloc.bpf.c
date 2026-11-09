#include "reloc.h"

struct relocated_nested_array {
  struct {
    struct {
      __u64 args[1];
    } rows[2];
  };
};

SEC("uprobe") int program(void *ctx) {
  return set_output(
      bpf_core_field_offset(struct relocated_nested_array, rows[0].args[1]));
}
