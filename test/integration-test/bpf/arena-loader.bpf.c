// clang-format off
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

extern void *bpf_arena_alloc_pages(void *map, void *addr, __u32 page_cnt,
                                   int node_id, __u64 flags) __ksym;
extern void bpf_arena_free_pages(void *map, void *ptr, __u32 page_cnt) __ksym;

struct {
  __uint(type, BPF_MAP_TYPE_ARENA);
  __uint(max_entries, 2);
  __uint(map_flags, BPF_F_MMAPABLE);
#ifdef __TARGET_ARCH_arm64
  __ulong(map_extra, 1ULL << 32);
#else
  __ulong(map_extra, 1ULL << 44);
#endif
} arena SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 6);
  __type(key, __u32);
  __type(value, __u64);
} arena_results SEC(".maps");

enum arena_result {
  COMMAND,
  ADDRESS,
  INITIAL_VALUE,
  VALUE_BEFORE_FREE,
  VALUE_AFTER_FREE,
  VALUE_AFTER_WRITE,
};

enum arena_command {
  ALLOCATE = 1,
  FREE = 2,
  PROBE_ACCESS = 3,
};

#define ARENA_TEST_VALUE 0x0123456789abcdefULL

// LLVM versions without native BPF address-space lowering still need to
// produce the canonical addr_space_cast instruction. This is the encoding
// used by the kernel BPF selftests.
// clang-format off
#define bpf_addr_space_cast(var, dst_as, src_as)                              \
  asm volatile(".byte 0xBF;"                                                 \
               ".ifc %[reg], r0; .byte 0x00; .endif;"                       \
               ".ifc %[reg], r1; .byte 0x11; .endif;"                       \
               ".ifc %[reg], r2; .byte 0x22; .endif;"                       \
               ".ifc %[reg], r3; .byte 0x33; .endif;"                       \
               ".ifc %[reg], r4; .byte 0x44; .endif;"                       \
               ".ifc %[reg], r5; .byte 0x55; .endif;"                       \
               ".ifc %[reg], r6; .byte 0x66; .endif;"                       \
               ".ifc %[reg], r7; .byte 0x77; .endif;"                       \
               ".ifc %[reg], r8; .byte 0x88; .endif;"                       \
               ".ifc %[reg], r9; .byte 0x99; .endif;"                       \
               ".short %[off];"                                             \
               ".long %[as]"                                                \
               : [reg] "+r"(var)                                            \
               : [off] "i"(BPF_ADDR_SPACE_CAST),                            \
                 [as] "i"(((dst_as) << 16) | (src_as)))
// clang-format on

#define cast_kern(ptr)                                                         \
  ({                                                                           \
    typeof(ptr) __ptr = (ptr);                                                 \
    bpf_addr_space_cast(__ptr, 0, 1);                                          \
    __ptr;                                                                     \
  })

#define cast_user(ptr)                                                         \
  ({                                                                           \
    typeof(ptr) __ptr = (ptr);                                                 \
    bpf_addr_space_cast(__ptr, 1, 0);                                          \
    __ptr;                                                                     \
  })

struct arena_node {
  __u64 value;
  __u64 next;
};

volatile __u64 arena_counter SEC(".addr_space.1") = 5;
volatile struct arena_node arena_head SEC(".addr_space.1") = {
    .value = 10,
    .next = 0,
};

SEC("xdp")
int arena_globals(struct xdp_md *ctx) {
  volatile struct arena_node *head = cast_kern(&arena_head);
  volatile __u64 *counter = cast_kern(&arena_counter);

  *counter += head->value;
  head->value += 1;
  return XDP_PASS;
}

static __always_inline __u64 *result(__u32 key) {
  return bpf_map_lookup_elem(&arena_results, &key);
}

static __always_inline void set_result(__u32 key, __u64 value) {
  bpf_map_update_elem(&arena_results, &key, &value, BPF_ANY);
}

SEC("uprobe.s")
int arena_pages(struct pt_regs *ctx) {
  __u64 *command = result(COMMAND);

  if (!command)
    return 0;

  if (*command == ALLOCATE) {
    volatile __u64 *page = bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
    if (!page) {
      set_result(ADDRESS, 0);
      return 0;
    }

    // Before 6.15 the kfunc return lacked KF_ARENA_RET and needed an explicit
    // cast; recasting is also valid on newer kernels.
    // https://github.com/torvalds/linux/blob/v6.14/kernel/bpf/arena.c#L580
    page = cast_kern(page);
    set_result(INITIAL_VALUE, *page);
    *page = ARENA_TEST_VALUE;
    set_result(ADDRESS, (__u64)cast_user(page));
    return 0;
  }

  __u64 *address = result(ADDRESS);
  if (!address || !*address)
    return 0;

  volatile __u64 *page = cast_kern((void *)*address);
  if (*command == FREE) {
    set_result(VALUE_BEFORE_FREE, *page);
    bpf_arena_free_pages(&arena, (void *)page, 1);

    page = cast_kern((void *)*address);
    set_result(VALUE_AFTER_FREE, *page);
  } else if (*command == PROBE_ACCESS) {
    set_result(INITIAL_VALUE, *page);
    *page = ARENA_TEST_VALUE;
    set_result(VALUE_AFTER_WRITE, *page);
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
