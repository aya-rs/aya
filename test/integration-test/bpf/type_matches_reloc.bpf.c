#include "reloc.h"

struct relocated_type_matches_args {
  __u32 a;
  __u64 b;
};

union relocated_type_matches_unchanged {
  int (*hook)(struct relocated_type_matches_args *args, __u32 flags);
};

// The target gains a trailing parameter, so the prototypes no longer match.
union relocated_type_matches_changed {
  int (*hook)(struct relocated_type_matches_args *args, __u32 flags
#ifdef TARGET
              ,
              __u64 extra
#endif
  );
};

#ifndef TARGET
union relocated_type_matches_missing {
  int (*hook)(void);
};
#endif

__noinline int type_matches_global() {
  __u64 output = 0;

  if (bpf_core_type_matches(union relocated_type_matches_unchanged))
    output |= 1;
  if (bpf_core_type_matches(union relocated_type_matches_changed))
    output |= 2;
#ifndef TARGET
  if (bpf_core_type_matches(union relocated_type_matches_missing))
    output |= 4;
#endif
  return set_output(output);
}

SEC("uprobe") int program(void *ctx) { return type_matches_global(); }
