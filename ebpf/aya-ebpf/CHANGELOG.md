# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.2.0 (2026-06-24)

### Chore

 - <csr-id-f6c5cb2ad2b09760ae5434785ed5d4d195d3a765/> set clippy unused_trait_names = warn
   We have previously tried to import traits anonymously where possible but
   enforcing this manually was hard.
   
   Since Rust 1.83 clippy can now enforce this for us.
 - <csr-id-4f0559f2afeca1dfae120bacf1742d58268bca37/> Fix cippy errors

### New Features

 - <csr-id-c1eb42780c8e0eba340808eb4b75df15ac434e61/> add typos-cli configuration and CI
 - <csr-id-2fb19f3ee2c95a34382b33762e9fb8841ec8c048/> Add `set` for `Array<T>`
 - <csr-id-1ccac3c135f280eead50ff18cd4c4340001018c6/> Implement FromPtRegs for mips

### Other

 - <csr-id-79cdfd802eb6ba2259ffe87e0ca604130e418764/> document raw tracepoint args
 - <csr-id-46759c99560202091983e5741bdb06dce6c1d90b/> document FExit ret kernel range
   Kernel git bisect identified the upstream verifier fix:
 - <csr-id-a73f8642328adfc033ed879c1f3638e9c76ac7fe/> add FExitContext::ret
   FExit programs need a stable API for reading the return value of the
   function they are attached to. Add FExitContext::ret() so callers do
   not need to depend on the raw layout of the tracing context.
 - <csr-id-e7173fd7ce396d03c5af78ec463b80b367f277ad/> add BTF hash family and seal safe inner lookup
   BTF `.maps` support for `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_LRU_HASH`,
   `BPF_MAP_TYPE_PERCPU_HASH`, and `BPF_MAP_TYPE_LRU_PERCPU_HASH`. The
   four wrappers expose `get`, `get_ptr`, `get_ptr_mut`, `insert`, and
   `remove`; `get` is `unsafe` because, without `BPF_F_NO_PREALLOC`, an
   entry returned by reference can be aliased by an `insert`, `remove`,
   or eviction.
   
   Compile-time assertions enforce the kernel constraints from
   `htab_map_alloc_check`: non-zero key and value sizes, `max_entries`
   at least 1, the per-family flag rejection (`BPF_F_NO_PREALLOC` on LRU,
   `BPF_F_NO_COMMON_LRU` on non-LRU), and value alignment of at most 8
   bytes to match the hashtab slot layout.
   
   Adding a hash type as an `ArrayOfMaps` inner map would let
   `ArrayOfMaps::get_value` hand out a `&V` into reusable memory from safe
   code. A sealed `SafeInnerLookup` marker, implemented only for `Array`
   and `PerCpuArray`, gates that path; the hash family opts out.
   `get_value_ptr_mut` keeps the looser bound because dereferencing its
   raw pointer is already the caller's responsibility.
 - <csr-id-2b21599af72a56a432c9e1f823ca089defc1e3f3/> add BTF XskMap and CpuMap
   BTF `.maps` support for `BPF_MAP_TYPE_XSKMAP` and
   `BPF_MAP_TYPE_CPUMAP`. `XskMap` wraps `u32` socket file
   descriptors and exposes `get` (which reads the bound queue id
   via `bpf_xdp_sock`) and `redirect`. `CpuMap` wraps
   `struct bpf_cpumap_val` and exposes `redirect`; on kernels
   older than 5.9 aya truncates the value size to 4 bytes at map
   creation, matching the legacy ABI before `bpf_prog.fd` was
   added.
   
   The `bpf_redirect_map` wrapper shared by `DevMap`,
   `DevMapHash`, `CpuMap`, and `XskMap` moves to a single
   `try_redirect_map` in `btf_maps`; the previous
   `devmap_redirect` helper is gone.
 - <csr-id-51f732091cefd7dc0fac6449ab93e782bf98a458/> add BTF DevMap and DevMapHash
   BTF `.maps` support for `BPF_MAP_TYPE_DEVMAP` and
   `BPF_MAP_TYPE_DEVMAP_HASH`. Both wrap `struct bpf_devmap_val`,
   so each entry carries the target `ifindex` and an optional
   chained XDP program. `get` reads the entry back as a
   `DevMapValue`; `redirect` forwards to `bpf_redirect_map`.
   
   `DevMapValue` was previously unreachable by name outside the
   `maps::xdp` module; it is now re-exported there so the new
   BTF wrappers can refer to it in their public signatures.
 - <csr-id-32154c1725fad6ec9233abac58917b58a12a7b62/> add BTF queue/stack maps and propagate errno from legacy
   BTF `.maps` support for `BPF_MAP_TYPE_QUEUE` and `BPF_MAP_TYPE_STACK`.
   Both types are keyless and store values of type `T`; queues consume
   them in FIFO order, stacks in LIFO order. `push`, `pop`, and `peek`
   wrap `bpf_map_push_elem`, `bpf_map_pop_elem`, and `bpf_map_peek_elem`
   respectively.
   
   `pop` and `peek` return `Result<Option<T>, i32>` so callers can tell
   an empty queue (`Ok(None)`, `-ENOENT` from the kernel) apart from
   helper failures (`Err(errno)`, e.g. `-EBUSY` under lock contention).
   The legacy `aya_ebpf::maps::{Queue, Stack}::{pop, peek}` follow the
   same shape; previously they mapped any non-zero ret to `None`,
   swallowing `-EBUSY`.
   
   Compile-time assertions enforce the kernel constraints from
   `queue_stack_map_alloc_check`: the value must be non-zero sized,
   `max_entries` must be at least 1, and `BPF_F_NO_PREALLOC` is rejected.
 - <csr-id-f404bb7bb0484f238ea8ebe93db684f807fcc4b9/> add BTF SockMap/SockHash, preserve redirect_sk_lookup errno
   Add `SockMap<MAX_ENTRIES, FLAGS>` and `SockHash<K, MAX_ENTRIES, FLAGS>`
   to `aya_ebpf::btf_maps`. Compile-time assertions enforce max_entries
   > 0 and, for SockHash, a key size in 1..=512.
   
   Switch `redirect_sk_lookup` to return `Result<(), i32>` so the actual
   `bpf_sk_assign` errno is propagated; lookup misses return `-ENOENT`.
   Apply the same change to the legacy `SockMap`/`SockHash` for
   consistency. Document the 5.9 SK_LOOKUP requirement on the BTF
   methods.
 - <csr-id-418555942721919273015522bee48538ee99bf3f/> introduce StackIdContext sealed trait
   Add a sealed `StackIdContext` trait that wraps `bpf_get_stackid` as a
   safe default method, with a blanket impl over the sealed supertrait
   covering the nine context types whose `BPF_PROG_TYPE_*` reaches
   `bpf_get_stackid_proto` in kernel v6.17.
   
   The map argument is gated by a sealed `StackTraceMap` trait
   implemented for both the legacy `maps::StackTrace` and the BTF
   `btf_maps::StackTrace`. The BTF impl forces `Self::_CHECK` to
   preserve the compile-time guards on `DEPTH`, `MAX_ENTRIES`, and
   `BPF_F_STACK_BUILD_ID`.
 - <csr-id-ee8110a50fe91c0c5553954fbef4d14ca3bd10cd/> add BTF map definition for perf event array
   BTF `.maps` support for `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. Keys
   and values are `u32`; userspace populates slots with perf-event
   file descriptors from `perf_event_open(2)`. Both `PerfEventArray`
   and `PerfEventByteArray` hardcode `max_entries` to 0 so aya's
   loader expands them to the number of online CPUs, matching the
   legacy types.
   
   The BTF `PerfEventArray` leaves the payload type to each
   `output` call site rather than binding it to the map. Callers
   that want the one-payload-per-map compile-time invariant should
   keep using the legacy `maps::PerfEventArray<T>`.
 - <csr-id-9c82966729f400ebf4d13c6d0308fd7e60acf54d/> add BTF map definition for stack trace
   BTF `.maps` support for `BPF_MAP_TYPE_STACK_TRACE`. Keys are `u32`
   stack IDs and values are `[u64; DEPTH]` with `DEPTH` defaulting to
   `PERF_MAX_STACK_DEPTH` (127).
   
   Compile-time assertions enforce non-zero `DEPTH` and
   `max_entries`, and reject `BPF_F_STACK_BUILD_ID`: the flag
   switches the kernel element layout to `struct bpf_stack_build_id`,
   which this type does not model. Declarations that never call a
   method bypass the check, but the runtime guard added in the
   previous commit catches the resulting map when opened from user
   space.
   
   Include an integration test, parameterized via `test_case` over
   the BTF and legacy map definitions, that records a stack id from
   a uprobe and verifies the trace has at least one non-zero IP
   frame.
 - <csr-id-4940ee6c69196634de9bf2f3c434cb5a57f194e5/> add BPF_PROG_TYPE_SK_REUSEPORT support
   Implement SK_REUSEPORT programs for programmable socket selection
   within SO_REUSEPORT groups.
   
   SkReuseport attaches and detaches via setsockopt rather than
   bpf_link, making it group-scoped: any socket in the group can
   attach or detach the program, and dropping SkReuseport does not
   detach it. Section parsing handles both sk_reuseport and
   sk_reuseport/migrate with the correct expected_attach_type.
   
   ReusePortSockArray is available in legacy and BTF variants.
   select_reuseport() is deduplicated across both via a pub(crate)
   trait. SkReuseportContext exposes sk_reuseport_md field
   accessors; sk() and migrating_sk() require Linux 5.14+.
   
   Integration tests verify socket steering, slot clearing with
   fallback, and migrate-path selection.
 - <csr-id-6f34b7955799dbf2f33f7030789bd470e019fc28/> add BTF map definition for program array
   BTF `.maps` support for `BPF_MAP_TYPE_PROG_ARRAY`. Keys and values
   are `u32`, so `ProgramArray` is the first `btf_map_def!` caller
   with no type parameters.
   
   `tail_call` mirrors the legacy contract fixed earlier in this series:
   the helper is `RET_VOID` and the wrapper returns unit since any
   return already implies failure.
   
   Exercise `tail_call` via two integration test cases: an empty slot
   (failure path) and a populated slot (success path, via a loaded but
   unattached target uprobe). Each is parameterized over the legacy
   and BTF variants, and a local macro shares the probe bodies.
 - <csr-id-4239f5f522efbae1bbdba3b026aa3b572edddb0d/> allow btf_map_def! with no type params
   BPF_MAP_TYPE_PROG_ARRAY hardcodes u32 keys and u32 values, so a
   BTF ProgramArray needs a btf_map_def! invocation with only const
   parameters. The current matcher requires at least one type
   parameter.
   
   Relax the type-parameter repetition from + to *, and rewrite the
   expansion sites to use comma-terminated generics lists so an empty
   list expands cleanly. Trailing commas in generics are accepted by
   rustc; existing callers produce equivalent code.
 - <csr-id-8edfe492cc4098fe4c9055f71f426f079421d2f0/> fix unsound fallthrough in ProgramArray::tail_call
   The bpf_tail_call helper is declared RET_VOID and does not write R0
   on failure. The previous wrapper returned Err(ret) when R0 was nonzero
   and reached unreachable_unchecked() otherwise, so a failure where R0
   held a leftover non-negative value hit the "impossible" branch: debug
   builds abort via the eBPF panic handler, release builds may delete the
   arm entirely.
   
   Discard the helper return and drop the Result return type. A successful
   tail call never returns here, so any return from the wrapper already
   implies failure; the kernel reports no reason code either way.
   
   Add an integration test that tail-calls into an empty slot and asserts
   the uprobe observes the failure.
 - <csr-id-3e755abd7e1957845c8dccc94a84ac9b433922db/> add BTF map definition for per-cpu array
   BTF `.maps` support for `BPF_MAP_TYPE_PERCPU_ARRAY`, matching the
   shape of `btf_maps::Array`.
   
   Compile-time assertions enforce the kernel-enforced non-zero value
   size, non-zero `max_entries`, and the per-CPU allocator alignment
   invariant that would otherwise let `get` hand out a misaligned `&T`.
   
   Include an integration test, parameterized via `test_case` over both
   the BTF and legacy map definitions, that exercises the read helpers
   against a uniform per-CPU value written from user space, and verifies
   that `set` mutates a single per-CPU slot by reading the array back
   from user space.
 - <csr-id-0bd9b18e62e5420d07c9546f61fe1a1c71764522/> add set to legacy PerCpuArray
   Legacy maps::PerCpuArray lacked a `set` method, unlike maps::Array
   and btf_maps::Array. Mirror maps::Array::set by forwarding to
   bpf_map_update_elem.
 - <csr-id-caa355d77707b6250653aa2f42311123fe04ee88/> add BTF map definition for LPM trie
   BTF `.maps` support for `BPF_MAP_TYPE_LPM_TRIE`. The `Key<K>` wrapper
   from `aya_ebpf::maps::lpm_trie` is reused to avoid duplication.
   
   Add compile-time assertions for the kernel-enforced key size (5..=260
   bytes), value size, max_entries, and the alignment invariant that
   prevents `get` from manufacturing a misaligned &V.
   
   Include an integration test, parameterized via `test_case` over both
   the BTF and legacy map definitions, that exercises longest-prefix-match,
   the None-return path, and the remove operation.
 - <csr-id-879925717b88957fcb71e1dd7df3022372dfb796/> add mips64 arch
   Wire up mips64 now that bindings are generated. MIPS64 uses the N64 ABI
   with the same pt_regs layout as MIPS (regs[4..11] for arguments, regs[2]
   for return value), so the PtRegsLayout impl is shared via cfg(any(...)).
 - <csr-id-df3da549cb3a9978f8f8113e13733887bff2add6/> use correct types for BPF helper return values
   Complete the i32 errno migration started in 8962fc79. Errno-only
   helpers now return Result<T, i32>, non-errno helpers (verdicts, byte
   counts) return c_long, and internal functions receiving raw helper
   returns use c_long. check_bounds_signed now takes T: Into<i64> to
   accept all signed/unsigned integer types without manual casts.
 - <csr-id-8c47886dea1a6ea7e3d167fdd5340d56532450f9/> fix bpf_printk variadic argument passing
   Change PrintkArg from wrapping [u8; 8] to wrapping u64 directly.
   
   The C ABI for variadic functions handles arrays differently than scalar
   types. When PrintkArg([u8; 8]) is passed to the variadic bpf_trace_printk
   helper, the array may be passed incorrectly (e.g., as a pointer or with
   wrong register usage), resulting in garbage values being printed.
   
   Using u64 directly ensures the value is passed by value in a register,
   matching what bpf_trace_printk expects for its %d, %u, %x, %lx format
   specifiers.
   
   An integration test is included that verifies various integer types
   (u8, u16, u32, u64, i32) are correctly passed through bpf_printk by
   attaching a uprobe and streaming trace_pipe output.
   
   ---------
 - <csr-id-8aeec41eec84ef0043ad11932d5f2d5f072c2c12/> Add `bpf_f_adj_room_encap_l2`
   This function is needed to properly add a L2 header when using `bpf_skb_adjust_room` [1].
   As it is originally a C macro, it isn't automatically generated in the `bindings` cratea
 - <csr-id-a826cc92c93d3d8132af55a588f2d2d9d8db5b89/> use &self for store, set_mark and set_reply
   Currently, the API for calling kernel helpers on `TcContext`, `SkBuff`,
   and `SockOpsContext` has inconsistent semantics. Methods like `store`,
   `set_mark`, and `set_reply` require a mutable reference (`&mut self`),
   while others that also modify the underlying state take a read-only
   reference (`&self`).
   
   This commit resolves the inconsistency reported in #1442 by changing
   `store`, `set_mark`, and `set_reply` to take `&self` across `SkBuff`,
   `SkBuffContext`, `TcContext`, and `SockOpsContext`.
   
   The `cb_mut` method is intentionally left unchanged because returning
   a mutable slice (`&mut [u32]`) from an immutable reference would
   violate Rust's aliasing rules.
 - <csr-id-ab7f96dafba47e12c328fddde14c58f2559c000d/> document nul termination
   See https://docs.ebpf.io/linux/helper-function/bpf_get_current_comm/.
 - <csr-id-0bf462d221af7f86b0f76da996f11445635a33e6/> Take `&self` in all methods of `BloomFilter`
 - <csr-id-8962fc79c11552ee5193a18663474039371e7671/> Use `i32` as a type for eBPF helper return codes
   The helpers always return a signed 64-bit r0 value, but the JIT that
   translates eBPF into native instructions differs by architecture. On
   x86_64 the generated code writes the helper result into a 64-bit
   register, so the CPU sign-extends negative errnos automatically. On
   aarch64 the JIT frequently uses 32-bit operations (w0) when copying the
   helper return and only zero-extends into the upper half of x0.
   
   That results in broken errno codes on aarch64. For example, when a map
   operation returns `-ENOENT`, which is supposed to be -2, the i64
   representation yields something like `0x0000_0000_FFFF_FFFE`
   (4294967294) instead of -2. In short: the ARM64 JIT doesn’t preserve the
   sign in the upper half of the 64-bit register, and the error code has to
   be cast to a 32-bit integer to make the sign visible.
   
   This makes it awkward for users, because that behavior prevents simply
   comparing helper error codes with constants like `libc::ENOENT` without
   manual casts.
   
   Given that the maximum error code limit `MAX_ERRNO` in the kernel is
   4095, which fits in a 32-bit integer, coerce the error codes to be `i32`
   and make all helpers return `Result<T, i32>`.
 - <csr-id-294e0c19413d5a7c073d17d79ad4d154283499ce/> Add helper for safe loading of globals
 - <csr-id-dd9bb520d26d7b86d8ba38119ab52d0252bf4c18/> use read_kernel() for read_at()
   For most architectures just bpf_probe_read() works, but for those that
   have overlapping memory address spaces, like UML, we must use the
   specific helper.
 - <csr-id-998ad08ba0612fa5411d1f8bbdd7b07caaacf3b1/> Do not anonymize BTF maps
   See https://github.com/llvm/llvm-project/pull/164851. This fixup is
   not needed.
 - <csr-id-930fa7b8af9918d241779054f6dc5c52005e8f14/> generalize btf_map_def macro type parameters
   Modify the btf_map_def! macro to generate flat #[repr(C)] structs
   instead of UnsafeCell wrappers. This produces BTF that both aya
   and libbpf can parse.
   
   Support type parameters with optional defaults and const generics with
   configurable types. Allow trailing commas and improve formatting.
   
   Also remove UnsafeCell traversal code from aya-obj loader since
   it is no longer needed with flat struct layout.
 - <csr-id-394668806bd96f8f082ce70fe042fa17cdcb3e5e/> define hash maps via macro
 - <csr-id-3eb9cacef4cfefe0832aff36aad2a9e1daeb57ba/> add BTF ring buffer
 - <csr-id-1d10f8751d622b6ac85db228a30aa2bb7e60665e/> fix redirect_sk_lookup receiver type
   The `redirect_sk_lookup` method for SockMap and SockHash
   previously required exclusive references.
   
   The documentation for `bpf_map_lookup_elem` makes no
   mention of a requirement for exclusive references.
   
   Therefore, `redirect_sk_lookup` has been changed to
   receive shared references to SockMap and SockHash.
 - <csr-id-ab38afe95d16226f5a703bbb37c7842ee441c364/> support hardware breakpoints
   Implement `PerfEventConfig::Breakpoint`, allowing users to attach
   hardware breakpoints. Generate `HW_BREAKPOINT_*` and `struct
   bpf_perf_event_data` in support of this feature and update the type of
   `PerfEventContext` accordingly.
   
   Add a test exercising R, W, RW, and X breakpoints. Note that R
   breakpoints are unsupported on x86, and this is asserted in the test.
   
   Extend the VM integration test harness and supporting infrastructure
   (e.g. `download_kernel_images.sh`) to download kernel debug packages and
   mount `System.map` in initramfs. This is needed (at least) on the aarch
   6.1 Debian kernel which was not compiled with `CONFIG_KALLSYMS_ALL=y`
   for some reason, and the locations of globals are not available in
   kallsyms. To attach breakpoints to these symbols in the test pipeline,
   we need to read them from System.map and apply the KASLR offset to get
   their real address. The `System.map` file is not provided in the kernel
   package by default, so we need to extract it from the corresponding
   debug package. The KASLR offset is computed using `gunzip` which appears
   in kallsyms on all Debian kernels tested.
 - <csr-id-03fea9e3042009cc43a76f2d15769ded69532be3/> reduce duplication
 - <csr-id-17c7c7951cb45a5903134b21658df7e989e672ed/> enable clippy::as_underscore
 - <csr-id-778b447e3b75497198b567d733ca68d7981e5cde/> enable unsafe_op_in_unsafe_fn
 - <csr-id-f610453ec234921c07aeb4d5401d0a8940d513df/> extract CARGO_CFG_BPF_TARGET_ARCH logic
 - <csr-id-05250da20bffca7742fcdf681392cf17ff02866f/> reduce repetition and excessive traits
   The traits `FromBtfArgument`, `FromRawTracepointArgs`, `FromPtRegs` are
   all fancy ways of saying `Argument` - so replace these traits with it.
   
   This also removes the use of `bpf_probe_read` which was introduced in
   05c1586202ce8719ef92b9b83dd30032bfa11edd because I can't reproduce the
   need for it.
 - <csr-id-98e8c78376286bbdc8c7ee3f0292b878cec24b99/> Make use of `Borrow` and `BorrowMut` in map methods
   Let callers pass either owned objects or references. We do that already
   in the user-space methods.
 - <csr-id-de42b80c74883f512542875e7cfa96b8634a8991/> add BPF_MAP_TYPE_SK_STORAGE
   This map type requires BTF, and we can finally do it!
 - <csr-id-0013ff4e9eadd5e97126b0a1916e90772ed87114/> use null pointers at runtime
   The values here do not matter, this is just to get type information.
 - <csr-id-275c5b6bbc3cf3dfac79d5dacb46377e2d296fe7/> use `ptr::from_ref`
   This is consistent with other such conversions.
 - <csr-id-fe99fa1d2eee94c4bf60d698784cae3c43f3a71c/> run clippy with target=bpf
   This build warnings from integration tests and makes `aya-ebpf`'s build
   script stricter.
 - <csr-id-0b2a544ddd9df74ebcdb46128b6bcc48336b2762/> Add BTF array definition
   Before this change, Aya supported only legacy BPF map definitions, which
   are instances of the `bpf_map_def` struct and end up in the `maps` ELF
   section.
   
   This change introduces a BTF map definition for arrays, with custom
   structs indicating the metadata of the map, which end up in the `.maps`
   section.
 - <csr-id-d5e4e9270ae4214ced858582ecb7ec6fc979d77e/> Remove irrelevant `FIXME` comment
   eBPF verifier in recent kernels should be smart enough to track map
   map types and catch invalid pointer casts. Rust type system makes sure
   that the `get` method can return only the same type the map was created
   with. Therefore, safe usage of Aya map types shouldn't cause element
   type mismatches.
   
   Manual alignment checks (`pointer::is_aligned` or manual pointer
   arithmetic operations) cause the following verifier error:
   
   ```
   bitwise operator &= on pointer prohibited
   ```
   
   And it extremely unlikely `bpf_map_lookup_elem` ever returns a
   misaligned pointer.
 - <csr-id-3569c9afc3dc7babb6b44aa071828df7c8864834/> Take `c_void` instead of `bpf_map_def` in map helpers
   `bpf_map_def` is a legacy map definition. To be able to introduce BTF
   map definitions, make the `lookup` and `remove` helpers work with
   `c_void` and let the callers cast the map types to it.
 - <csr-id-3f60168d4bab042d26094f7962b96f0772b52ae7/> add RingBufBytes for raw byte slices
 - <csr-id-f537dc66845e70bc3af2dbb9944562cf38117bcb/> destructure, avoid `as` casts
 - <csr-id-53ec6164114bba84be145dc9659aaac917dd7a15/> add peak() method to Queue and Stack
   Add integration tests covering push,pop,peek for both types.
 - <csr-id-ccf6c4707f136e5c026f806774dac89efe7d78e3/> disable generic_const_exprs
   This has recently regressed on nightly.
   
   See https://github.com/rust-lang/rust/issues/141492.
 - <csr-id-4f654865e9e592a93e11feb8558a461c4b6865b5/> add a dedicated generic_const_exprs cfg
 - <csr-id-6004fcdb0fb5a6157ba5416f439e5807567c87a7/> put mem{set,move,cpy} behind cfg(target_arch = "bpf")
   Address some lints while I'm here.
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.
 - <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> hook up loongarch64
   This causes rustfmt to format those files.
   
   Squish some other conditional compilation to get rustfmt sorting.
 - <csr-id-e1cb4237bd1e8fdaa0d85f97684c63401ae0ed33/> add queue ID matching to AF_XDP test
 - <csr-id-601c89dd23d8ac34ebd7cd80af87a3e9ba6da255/> extract insert,remove,lookup
   These functions (and more) are duplicated all over the place.
 - <csr-id-dc543ae44aab09ea9ab550b164ca0711293e87fe/> add ifindex support to XdpContext
   This change exposes the ifindex field from the underlying xdp_md
   data structure to the XdpContext in Aya. The ifindex represents the
   unique OS-provided index for a network interface.
 - <csr-id-bdd8ae2d0b443513c73143da968d400df9b05464/> avoid `_`
   This can silently discard information, so we shouldn't do it.
 - <csr-id-f34d355d7d70f8f9ef0f0a01a4338e50cf0080b4/> Handle raw tracepoint arguments
   Provide an `arg()` method in `RawTracepointArgs` wrapper of
   `bpf_raw_tracepoint_args` and also in `RawTracepointContext`, so
   it's directly available in raw tracepoint programs.
   
   The methods and traits implemented here are unsafe. There is no
   way to reliably check the number of available arguments, so
   requesting a non-existing one leads to undefined behavior.
 - <csr-id-0b58d3eb6d399c812181d2d64de32cde1b44f6eb/> Add `bpf_strncmp` helper
   The `bpf_strncmp` helper allows for better string comparison in eBPF
   programs.
   
   Added in https://github.com/torvalds/linux/commit/c5fb19937455095573a19.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 93 commits contributed to the release.
 - 66 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 2 unique issues were worked on: [#1139](https://github.com/aya-rs/aya/issues/1139), [#1501](https://github.com/aya-rs/aya/issues/1501)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#1139](https://github.com/aya-rs/aya/issues/1139)**
    - Fix aya-ebpf-* riscv64 build ([`1fe12b9`](https://github.com/aya-rs/aya/commit/1fe12b99907dda6553a6069fa462d6241d3fa171))
 * **[#1501](https://github.com/aya-rs/aya/issues/1501)**
    - Aya, aya-ebpf, aya-obj: add BTF bloom filter support ([`904fbe2`](https://github.com/aya-rs/aya/commit/904fbe265e8a97c7c4869a0898bcfd71502aae62))
 * **Uncategorized**
    - Aya, aya-ebpf: add InodeStorage and CgrpStorage ([`bd397b6`](https://github.com/aya-rs/aya/commit/bd397b644723b13bc4397acb0c792546d5df7215))
    - Document raw tracepoint args ([`79cdfd8`](https://github.com/aya-rs/aya/commit/79cdfd802eb6ba2259ffe87e0ca604130e418764))
    - Aya, aya-ebpf: add CgroupStorage and PerCpuCgroupStorage ([`9ec80ac`](https://github.com/aya-rs/aya/commit/9ec80ac6a91b8edbc51a0476560d38d843bf8031))
    - Document FExit ret kernel range ([`46759c9`](https://github.com/aya-rs/aya/commit/46759c99560202091983e5741bdb06dce6c1d90b))
    - Add FExitContext::ret ([`a73f864`](https://github.com/aya-rs/aya/commit/a73f8642328adfc033ed879c1f3638e9c76ac7fe))
    - Aya, aya-ebpf: add CgroupArray ([`eb73f8c`](https://github.com/aya-rs/aya/commit/eb73f8ca9260e48141a1bdf1a492799826a85515))
    - Add typos-cli configuration and CI ([`c1eb427`](https://github.com/aya-rs/aya/commit/c1eb42780c8e0eba340808eb4b75df15ac434e61))
    - Add BTF hash family and seal safe inner lookup ([`e7173fd`](https://github.com/aya-rs/aya/commit/e7173fd7ce396d03c5af78ec463b80b367f277ad))
    - Add BTF XskMap and CpuMap ([`2b21599`](https://github.com/aya-rs/aya/commit/2b21599af72a56a432c9e1f823ca089defc1e3f3))
    - Aya, aya-ebpf, aya-obj: add HashOfMaps and ArrayOfMaps ([`4075b5e`](https://github.com/aya-rs/aya/commit/4075b5ec62beeb7b69c1d99847ec9c65ba85a49f))
    - Add BTF DevMap and DevMapHash ([`51f7320`](https://github.com/aya-rs/aya/commit/51f732091cefd7dc0fac6449ab93e782bf98a458))
    - Add BTF queue/stack maps and propagate errno from legacy ([`32154c1`](https://github.com/aya-rs/aya/commit/32154c1725fad6ec9233abac58917b58a12a7b62))
    - Add BTF SockMap/SockHash, preserve redirect_sk_lookup errno ([`f404bb7`](https://github.com/aya-rs/aya/commit/f404bb7bb0484f238ea8ebe93db684f807fcc4b9))
    - Aya-ebpf, integration-ebpf: migrate to StackIdContext::get_stackid ([`6e0ac98`](https://github.com/aya-rs/aya/commit/6e0ac985a085bd7958bf3ab880802b8049dd8415))
    - Introduce StackIdContext sealed trait ([`4185559`](https://github.com/aya-rs/aya/commit/418555942721919273015522bee48538ee99bf3f))
    - Add BTF map definition for perf event array ([`ee8110a`](https://github.com/aya-rs/aya/commit/ee8110a50fe91c0c5553954fbef4d14ca3bd10cd))
    - Add BTF map definition for stack trace ([`9c82966`](https://github.com/aya-rs/aya/commit/9c82966729f400ebf4d13c6d0308fd7e60acf54d))
    - Aya-ebpf-bindings, aya-ebpf: expose PERF_MAX_STACK_DEPTH ([`61eea8a`](https://github.com/aya-rs/aya/commit/61eea8ada7ac42270add8f0bf37ea12fed2dc44f))
    - Add BPF_PROG_TYPE_SK_REUSEPORT support ([`4940ee6`](https://github.com/aya-rs/aya/commit/4940ee6c69196634de9bf2f3c434cb5a57f194e5))
    - Add BTF map definition for program array ([`6f34b79`](https://github.com/aya-rs/aya/commit/6f34b7955799dbf2f33f7030789bd470e019fc28))
    - Allow btf_map_def! with no type params ([`4239f5f`](https://github.com/aya-rs/aya/commit/4239f5f522efbae1bbdba3b026aa3b572edddb0d))
    - Fix unsound fallthrough in ProgramArray::tail_call ([`8edfe49`](https://github.com/aya-rs/aya/commit/8edfe492cc4098fe4c9055f71f426f079421d2f0))
    - Add BTF map definition for per-cpu array ([`3e755ab`](https://github.com/aya-rs/aya/commit/3e755abd7e1957845c8dccc94a84ac9b433922db))
    - Add set to legacy PerCpuArray ([`0bd9b18`](https://github.com/aya-rs/aya/commit/0bd9b18e62e5420d07c9546f61fe1a1c71764522))
    - Add BTF map definition for LPM trie ([`caa355d`](https://github.com/aya-rs/aya/commit/caa355d77707b6250653aa2f42311123fe04ee88))
    - Add mips64 arch ([`8799257`](https://github.com/aya-rs/aya/commit/879925717b88957fcb71e1dd7df3022372dfb796))
    - Use correct types for BPF helper return values ([`df3da54`](https://github.com/aya-rs/aya/commit/df3da549cb3a9978f8f8113e13733887bff2add6))
    - Fix bpf_printk variadic argument passing ([`8c47886`](https://github.com/aya-rs/aya/commit/8c47886dea1a6ea7e3d167fdd5340d56532450f9))
    - Add `bpf_f_adj_room_encap_l2` ([`8aeec41`](https://github.com/aya-rs/aya/commit/8aeec41eec84ef0043ad11932d5f2d5f072c2c12))
    - Use &self for store, set_mark and set_reply ([`a826cc9`](https://github.com/aya-rs/aya/commit/a826cc92c93d3d8132af55a588f2d2d9d8db5b89))
    - Remove no-longer-firing lint expectations ([`d43d8a9`](https://github.com/aya-rs/aya/commit/d43d8a9674217dc1fc91f4747f3c92a8c9d5e3f7))
    - Use plain arrays in ring buf tests ([`b93ee8c`](https://github.com/aya-rs/aya/commit/b93ee8c26e96af85d77b040fa4fae8447c8fd7f8))
    - Rename EbpfGlobal to Global ([`b9cb76b`](https://github.com/aya-rs/aya/commit/b9cb76b302bdd1288b6486fb3a0627ea40cc3dbc))
    - Document nul termination ([`ab7f96d`](https://github.com/aya-rs/aya/commit/ab7f96dafba47e12c328fddde14c58f2559c000d))
    - Take `&self` in all methods of `BloomFilter` ([`0bf462d`](https://github.com/aya-rs/aya/commit/0bf462d221af7f86b0f76da996f11445635a33e6))
    - Use `i32` as a type for eBPF helper return codes ([`8962fc7`](https://github.com/aya-rs/aya/commit/8962fc79c11552ee5193a18663474039371e7671))
    - Add helper for safe loading of globals ([`294e0c1`](https://github.com/aya-rs/aya/commit/294e0c19413d5a7c073d17d79ad4d154283499ce))
    - Use read_kernel() for read_at() ([`dd9bb52`](https://github.com/aya-rs/aya/commit/dd9bb520d26d7b86d8ba38119ab52d0252bf4c18))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
    - Do not anonymize BTF maps ([`998ad08`](https://github.com/aya-rs/aya/commit/998ad08ba0612fa5411d1f8bbdd7b07caaacf3b1))
    - Generalize btf_map_def macro type parameters ([`930fa7b`](https://github.com/aya-rs/aya/commit/930fa7b8af9918d241779054f6dc5c52005e8f14))
    - Enable unused_qualifications lint ([`e746618`](https://github.com/aya-rs/aya/commit/e746618143f010fe7f05635a1a6e1a8b723bfd31))
    - Define hash maps via macro ([`3946688`](https://github.com/aya-rs/aya/commit/394668806bd96f8f082ce70fe042fa17cdcb3e5e))
    - Aya, aya-ebpf: reduce duplication ([`f35f7a3`](https://github.com/aya-rs/aya/commit/f35f7a3610d8296d97c6f0a47e75dbb4188f5212))
    - Add BTF ring buffer ([`3eb9cac`](https://github.com/aya-rs/aya/commit/3eb9cacef4cfefe0832aff36aad2a9e1daeb57ba))
    - Fix redirect_sk_lookup receiver type ([`1d10f87`](https://github.com/aya-rs/aya/commit/1d10f8751d622b6ac85db228a30aa2bb7e60665e))
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Support hardware breakpoints ([`ab38afe`](https://github.com/aya-rs/aya/commit/ab38afe95d16226f5a703bbb37c7842ee441c364))
    - Add clippy coverage for doctests ([`112ab47`](https://github.com/aya-rs/aya/commit/112ab47fcdf8ba4765e6f6416cbb7000c96292f8))
    - Reduce duplication ([`03fea9e`](https://github.com/aya-rs/aya/commit/03fea9e3042009cc43a76f2d15769ded69532be3))
    - Enable clippy::as_underscore ([`17c7c79`](https://github.com/aya-rs/aya/commit/17c7c7951cb45a5903134b21658df7e989e672ed))
    - Enable unsafe_op_in_unsafe_fn ([`778b447`](https://github.com/aya-rs/aya/commit/778b447e3b75497198b567d733ca68d7981e5cde))
    - Extract CARGO_CFG_BPF_TARGET_ARCH logic ([`f610453`](https://github.com/aya-rs/aya/commit/f610453ec234921c07aeb4d5401d0a8940d513df))
    - Reduce repetition and excessive traits ([`05250da`](https://github.com/aya-rs/aya/commit/05250da20bffca7742fcdf681392cf17ff02866f))
    - Enable bpf_target_arch = loongarch64 ([`4b4b9f8`](https://github.com/aya-rs/aya/commit/4b4b9f83bd6c1762a5366d2d89353adf4364f76e))
    - Make use of `Borrow` and `BorrowMut` in map methods ([`98e8c78`](https://github.com/aya-rs/aya/commit/98e8c78376286bbdc8c7ee3f0292b878cec24b99))
    - Add BPF_MAP_TYPE_SK_STORAGE ([`de42b80`](https://github.com/aya-rs/aya/commit/de42b80c74883f512542875e7cfa96b8634a8991))
    - Use null pointers at runtime ([`0013ff4`](https://github.com/aya-rs/aya/commit/0013ff4e9eadd5e97126b0a1916e90772ed87114))
    - Use `ptr::from_ref` ([`275c5b6`](https://github.com/aya-rs/aya/commit/275c5b6bbc3cf3dfac79d5dacb46377e2d296fe7))
    - Run clippy with target=bpf ([`fe99fa1`](https://github.com/aya-rs/aya/commit/fe99fa1d2eee94c4bf60d698784cae3c43f3a71c))
    - Lint all crates; enable strict pointer lints ([`5f5305c`](https://github.com/aya-rs/aya/commit/5f5305c2a8ca0a739219093599dd57182d440ac1))
    - Add BTF array definition ([`0b2a544`](https://github.com/aya-rs/aya/commit/0b2a544ddd9df74ebcdb46128b6bcc48336b2762))
    - Remove irrelevant `FIXME` comment ([`d5e4e92`](https://github.com/aya-rs/aya/commit/d5e4e9270ae4214ced858582ecb7ec6fc979d77e))
    - Take `c_void` instead of `bpf_map_def` in map helpers ([`3569c9a`](https://github.com/aya-rs/aya/commit/3569c9afc3dc7babb6b44aa071828df7c8864834))
    - Add RingBufBytes for raw byte slices ([`3f60168`](https://github.com/aya-rs/aya/commit/3f60168d4bab042d26094f7962b96f0772b52ae7))
    - Destructure, avoid `as` casts ([`f537dc6`](https://github.com/aya-rs/aya/commit/f537dc66845e70bc3af2dbb9944562cf38117bcb))
    - Add peak() method to Queue and Stack ([`53ec616`](https://github.com/aya-rs/aya/commit/53ec6164114bba84be145dc9659aaac917dd7a15))
    - Disable generic_const_exprs ([`ccf6c47`](https://github.com/aya-rs/aya/commit/ccf6c4707f136e5c026f806774dac89efe7d78e3))
    - Add a dedicated generic_const_exprs cfg ([`4f65486`](https://github.com/aya-rs/aya/commit/4f654865e9e592a93e11feb8558a461c4b6865b5))
    - Put mem{set,move,cpy} behind cfg(target_arch = "bpf") ([`6004fcd`](https://github.com/aya-rs/aya/commit/6004fcdb0fb5a6157ba5416f439e5807567c87a7))
    - Merge pull request #1224 from dave-tucker/unused_trait_names ([`9eecbe9`](https://github.com/aya-rs/aya/commit/9eecbe9d0e9dc1fdbbc87d41512d4202e26d4687))
    - Add support for Flow Dissector programs ([`77b1c61`](https://github.com/aya-rs/aya/commit/77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f))
    - Set clippy unused_trait_names = warn ([`f6c5cb2`](https://github.com/aya-rs/aya/commit/f6c5cb2ad2b09760ae5434785ed5d4d195d3a765))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Hook up loongarch64 ([`6252b4c`](https://github.com/aya-rs/aya/commit/6252b4c9722c7c2ee2458741ae328dcc0c3c5234))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Reduce the scope of expected warnings ([`ea5f7e3`](https://github.com/aya-rs/aya/commit/ea5f7e3015477717fc4a96fed2e5e7e496d2dd66))
    - Use #[expect(...)] rather than #[allow(...)] ([`4101a5a`](https://github.com/aya-rs/aya/commit/4101a5a55d43cd9ead56497820c4d43018f74cbb))
    - Add queue ID matching to AF_XDP test ([`e1cb423`](https://github.com/aya-rs/aya/commit/e1cb4237bd1e8fdaa0d85f97684c63401ae0ed33))
    - Merge pull request #1141 from gth828r/1140.xdp-context-if-index-support ([`0fa300f`](https://github.com/aya-rs/aya/commit/0fa300f696ebd98fe2b70f5680fff50a0d02bf42))
    - Add `set` for `Array<T>` ([`2fb19f3`](https://github.com/aya-rs/aya/commit/2fb19f3ee2c95a34382b33762e9fb8841ec8c048))
    - Extract insert,remove,lookup ([`601c89d`](https://github.com/aya-rs/aya/commit/601c89dd23d8ac34ebd7cd80af87a3e9ba6da255))
    - Add ifindex support to XdpContext ([`dc543ae`](https://github.com/aya-rs/aya/commit/dc543ae44aab09ea9ab550b164ca0711293e87fe))
    - Avoid `_` ([`bdd8ae2`](https://github.com/aya-rs/aya/commit/bdd8ae2d0b443513c73143da968d400df9b05464))
    - Merge pull request #482 from ishanjain28/add_mips_support ([`2f757b2`](https://github.com/aya-rs/aya/commit/2f757b2091d28a17c90495ee2955e7f8d1bc5ec5))
    - Implement FromPtRegs for mips ([`1ccac3c`](https://github.com/aya-rs/aya/commit/1ccac3c135f280eead50ff18cd4c4340001018c6))
    - Handle raw tracepoint arguments ([`f34d355`](https://github.com/aya-rs/aya/commit/f34d355d7d70f8f9ef0f0a01a4338e50cf0080b4))
    - Fix cippy errors ([`4f0559f`](https://github.com/aya-rs/aya/commit/4f0559f2afeca1dfae120bacf1742d58268bca37))
    - Allow aya-ebpf to clippy with stable rust ([`1de7e72`](https://github.com/aya-rs/aya/commit/1de7e728b64c1fc706b1802b4eb5d2642570a1f3))
    - Add `bpf_strncmp` helper ([`0b58d3e`](https://github.com/aya-rs/aya/commit/0b58d3eb6d399c812181d2d64de32cde1b44f6eb))
</details>

## v0.1.2 (2025-11-17)

<csr-id-3569c9afc3dc7babb6b44aa071828df7c8864834/>
<csr-id-4f654865e9e592a93e11feb8558a461c4b6865b5/>
<csr-id-4b4b9f83bd6c1762a5366d2d89353adf4364f76e/>

### Breaking Changes

 - <csr-id-3569c9afc3dc7babb6b44aa071828df7c8864834/> Map helper functions now take `*mut c_void`, matching the kernel’s prototypes. Any out-of-tree helpers should update their signatures accordingly.

### New Features

 - <csr-id-0b58d3eb6d399c812181d2d64de32cde1b44f6eb/> Added a `bpf_strncmp` helper binding.
 - <csr-id-f34d355d7d70f8f9ef0f0a01a4338e50cf0080b4/> Raw tracepoints now expose their arguments so programs no longer need to guess register layouts.
 - <csr-id-1ccac3c135f280eead50ff18cd4c4340001018c6/> , <csr-id-6252b4c9722c7c2ee2458741ae328dcc0c3c5234/> Added mips/loongarch register helpers so those targets can implement `FromPtRegs`.
 - <csr-id-dc543ae44aab09ea9ab550b164ca0711293e87fe/> `XdpContext` exposes the interface index, simplifying multi-interface programs.
 - <csr-id-2fb19f3ee2c95a34382b33762e9fb8841ec8c048/> Added `Array::set()` to update array contents from eBPF code.
 - <csr-id-77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f/> Introduced Flow Dissector program support on the eBPF side.
 - <csr-id-3f60168d4bab042d26094f7962b96f0772b52ae7/> Added `RingBufBytes` so probes can emit raw byte slices efficiently.
 - <csr-id-0b2a544ddd9df74ebcdb46128b6bcc48336b2762/> , <csr-id-53ec6164114bba84be145dc9659aaac917dd7a15/> Added BTF array definitions plus `Queue`/`Stack::peek()` helpers for safer data-structure inspection.

### Bug Fixes

 - <csr-id-1fe12b99907dda6553a6069fa462d6241d3fa171/> Fixed riscv64 builds by updating the generated bindings.
 - <csr-id-f537dc66845e70bc3af2dbb9944562cf38117bcb/> Cleaned up ring-buffer code to avoid reliance on `as` casts, preventing UB on strict architectures.
 - <csr-id-6004fcdb0fb5a6157ba5416f439e5807567c87a7/> Guarded the libc `mem*` shims behind `cfg(target_arch = "bpf")`, ensuring CPU builds stay well-defined.

### Maintenance

 - <csr-id-4f654865e9e592a93e11feb8558a461c4b6865b5/>, <csr-id-4b4b9f83bd6c1762a5366d2d89353adf4364f76e/> Added configuration flags for `generic_const_exprs` and the loongarch target, plus the usual lint/documentation refresh.

## v0.1.1 (2024-10-09)

<csr-id-95e1763e30e0dcfe1256ecd9e32ca27dd65342b4/>
<csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/>
<csr-id-2d38b23b99cd259f7a249f4c63b12da909c67015/>

### New Features

 - <csr-id-7ad3926d996f6471da05a8f3cab0283bb38c1498/> Implement memmove
   The compiler will emit this function for certain operations, but aya
   currently does not provide an implementation.
   This leads to ebpf loading failures as the kernel can't find the symbol when
   loading the program.
   
   The implementation is based on https://github.com/rust-lang/compiler-builtins/blob/master/src/mem/mod.rs#L29-L40
   and https://github.com/rust-lang/compiler-builtins/blob/master/src/mem/impls.rs#L128-L135
   Only the simplest case has been implemented, none of the word optimizations,
   since memcpy also doesn't seem to have them.

### Bug Fixes

 - <csr-id-ef0d1253efcc5a385afc74668d4f28580d328822/> Remove PerfEventArray::with_max_entries
   This API doesn't make sense as the max_entries needs to be set to the
   number of online CPUs by the loader.

### Other

 - <csr-id-95e1763e30e0dcfe1256ecd9e32ca27dd65342b4/> Add set_reply accessor to SockOpsContext
 - <csr-id-b513af12e8baa5c5097eaf0afdae61a830c3f877/> add archs powerpc64 and s390x to aya
   bpfman, a project using aya, has a requirement to support powerpc64 and
   s390x architectures. Adding these two architectures to aya.
 - <csr-id-2d38b23b99cd259f7a249f4c63b12da909c67015/> moved ret from ProbeContext into new RetProbeContext
   Created retprobe.rs to hold RetProbeContext and moved the ret from
   ProbeContext in probe.rs into RetProbeContext. Now, only kprobe (which
   uses ProbeContext) can access args, and kretprobe (which uses
   RetProbeContext) can access ret.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 12 commits contributed to the release.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf-cty v0.2.2, aya-ebpf-bindings v0.1.1, aya-ebpf-macros v0.1.1, aya-ebpf v0.1.1 ([`59082f5`](https://github.com/aya-rs/aya/commit/59082f572c01e8356312ed53bdb818cfbea944b5))
    - Merge pull request #1020 from l2dy/sockops-ctx ([`635ed3b`](https://github.com/aya-rs/aya/commit/635ed3baed5442c1364a360d7234b72c4ffe3fd8))
    - Add set_reply accessor to SockOpsContext ([`95e1763`](https://github.com/aya-rs/aya/commit/95e1763e30e0dcfe1256ecd9e32ca27dd65342b4))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Add archs powerpc64 and s390x to aya ([`b513af1`](https://github.com/aya-rs/aya/commit/b513af12e8baa5c5097eaf0afdae61a830c3f877))
    - Appease nightly clippy ([`bce3c4f`](https://github.com/aya-rs/aya/commit/bce3c4fb1d0cd6e8f9f64420c59e02a42c96b2c8))
    - Remove PerfEventArray::with_max_entries ([`ef0d125`](https://github.com/aya-rs/aya/commit/ef0d1253efcc5a385afc74668d4f28580d328822))
    - Implement memmove ([`7ad3926`](https://github.com/aya-rs/aya/commit/7ad3926d996f6471da05a8f3cab0283bb38c1498))
    - Allowlist expected cfgs ([`e4f9ed8`](https://github.com/aya-rs/aya/commit/e4f9ed8d79e4cd19ab5124352fca9e6cbdc1030b))
    - Deny warnings ([`b603c66`](https://github.com/aya-rs/aya/commit/b603c665a9a2ec48de2c4b412876bd015e5ead15))
    - Moved ret from ProbeContext into new RetProbeContext ([`2d38b23`](https://github.com/aya-rs/aya/commit/2d38b23b99cd259f7a249f4c63b12da909c67015))
    - Appease clippy ([`57cd351`](https://github.com/aya-rs/aya/commit/57cd35172f1534444a548460de6eae4680488711))
</details>

## v0.1.0 (2024-04-06)

<csr-id-d7af6acb42055ed1e0571bdc4d7dbbfa46c5835e/>
<csr-id-ea8073793e44c593e983e69eaa43a4f72799bfc5/>
<csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/>
<csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/>
<csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/>

### Chore

 - <csr-id-d7af6acb42055ed1e0571bdc4d7dbbfa46c5835e/> Rename BpfContext -> EbpfContext
 - <csr-id-ea8073793e44c593e983e69eaa43a4f72799bfc5/> Rename bpf -> ebpf
 - <csr-id-41c61560eae01a30c703ea22c5bfeeff0ecf6b1b/> Rename bpf -> ebpf

### Chore

 - <csr-id-a4ae8adb0db75f2b82b10b0740447a1dbead62c0/> add version keys to Cargo.toml(s)

### Chore

 - <csr-id-c7fe60d47e0cc32fc7123e37532d104eaa392b50/> add changelogs

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 10 commits contributed to the release.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-ebpf v0.1.0 ([`c3ae6f9`](https://github.com/aya-rs/aya/commit/c3ae6f90d8d3be8b31d1de9ccc042133f9ac8f44))
    - Release aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`eb3947b`](https://github.com/aya-rs/aya/commit/eb3947bf14e8e7ab0f70e12306e38fb8056edf57))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`a34c5e4`](https://github.com/aya-rs/aya/commit/a34c5e43b85dd176b9b18f1cc9c9d80d52f10a1f))
    - Add version keys to Cargo.toml(s) ([`a4ae8ad`](https://github.com/aya-rs/aya/commit/a4ae8adb0db75f2b82b10b0740447a1dbead62c0))
    - Release aya-ebpf-bindings v0.1.0, aya-ebpf-macros v0.1.0, aya-ebpf v0.1.0 ([`b8964d3`](https://github.com/aya-rs/aya/commit/b8964d3fd27353beb9054dd18fe8d16251f9164b))
    - Add changelogs ([`c7fe60d`](https://github.com/aya-rs/aya/commit/c7fe60d47e0cc32fc7123e37532d104eaa392b50))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Rename BpfContext -> EbpfContext ([`d7af6ac`](https://github.com/aya-rs/aya/commit/d7af6acb42055ed1e0571bdc4d7dbbfa46c5835e))
    - Rename bpf -> ebpf ([`ea80737`](https://github.com/aya-rs/aya/commit/ea8073793e44c593e983e69eaa43a4f72799bfc5))
    - Rename bpf -> ebpf ([`41c6156`](https://github.com/aya-rs/aya/commit/41c61560eae01a30c703ea22c5bfeeff0ecf6b1b))
</details>

