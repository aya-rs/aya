# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.14.0 (2026-06-24)

### Chore

 - <csr-id-269dfaf4a20b99f2e3d384e3e5d13b226f507360/> Release aya-obj v0.3.0
 - <csr-id-745065a74241ae8c39180c0cdc1a5444b5605dfb/> Add a docstring for `NetlinkError::raw_os_error()`
 - <csr-id-23a5e06c75dd418f9e0956db18cbed3b80670440/> Use BPF_ADD from bindings
   We should use the generated one, not the one provided by the libc crate.
 - <csr-id-e8e268ba768e6fc34567aedb5206ff20a958f04e/> Fix clippy unused cfg_attr
   clippy complained that cfg_attr is applied to the macro invocation and
   therefore will not be expanded. This was a false-positive, however
   when playing with cargo expand I did notice that the cfg and cfg_attr
   section weren't propagating as I would expect them to.
   
   Adding a meta matcher to the impl_try_from_map macro allows us to
   remove the need for AsyncPerfEventArray to be in a separate invocation
   of the macro while also making sure that attributes do get propagated
   to the generated functions.
 - <csr-id-f6c5cb2ad2b09760ae5434785ed5d4d195d3a765/> set clippy unused_trait_names = warn
   We have previously tried to import traits anonymously where possible but
   enforcing this manually was hard.
   
   Since Rust 1.83 clippy can now enforce this for us.
 - <csr-id-665d4f20bb53de0aa10545bb897ab73f0661a337/> remove aya_obj -> obj alias
   When `aya::obj` was migrated to be its own crate `aya-obj`, the `obj`
   alias was created to preserve existing imports that relied on
   `crate::obj`.
   
   This resulted in 3 ways to import `aya-obj` objects:
   - `use aya_obj::*`
   - `use obj::*`
   - `use crate::obj::*`
   
   The `obj` alias is now removed to avoid confusion, and all `obj` imports
   are funneled through `aya_obj`.
 - <csr-id-4f0559f2afeca1dfae120bacf1742d58268bca37/> Fix cippy errors

### Documentation

 - <csr-id-df053f095b67f8984ae31fd0ca1042f4e38c3378/> update docs for load to mention include_bytes_aligned
   * docs: update docs for load to mention include_bytes_aligned
   
   This macro is required if you are bundling programs statically into your binary, which is not an uncommon thing to do.
   
   This change updates the documentation for the load function to mention this macro and the need for alignment.

### New Features

 - <csr-id-c1eb42780c8e0eba340808eb4b75df15ac434e61/> add typos-cli configuration and CI
 - <csr-id-d8f5497884a23bd63f9264dbe3f80081b76f360d/> add `Ebpf::maps_disjoint_mut`
   Implemented using `HashMap::get_disjoint_mut` introduced in Rust 1.86.0.
 - <csr-id-7dba5a41ade97a3744c4cb71a22d7c81699a69e3/> Make LinkInfo and loaded_links public
   We have had loaded_links in the API as `#[doc(hidden)]` for a while.
   I've been using it in bpfman and it's been fine. This commit does the
   minimal work required to make the API stable.
   
   We expose a `LinkInfo` type - similar to `ProgInfo` - which wraps the
   generated type. In this case, `bpf_link_info`.
   
   A few accessor functions have been added for `id`, `link_type` and
   `program_id`. There are many more fields that could be (eventually)
   made public.
   
   As a convenience, `LinkInfo` can be retrieved from an existing FdLink
   by using `FdLink::info()`.
 - <csr-id-2b0dcfbd0938252f8ee8752e26abe7581561f9af/> Allow conversions to Program from ProgramInfo
   Allow for a ProgramInfo to be converted into one of the program types
   that we support. This allows for a user of Aya access to reattach,
   pin or unload a program that was either, previously loaded, or was
   loaded by another process.
 - <csr-id-39cf6c12f27f02c945e70efb24b89c1bc372aac0/> Return error messages from netlink
   This returns error strings from netlink since they are more informative
   than the raw os error. For example:
   
   "Device or Resource Busy" vs. "XDP program already attached".
 - <csr-id-bf2164c92f5280e8b9c7178b9cbf338931ce778d/> Add iterator program type
   BPF iterators[0] are a way to dump kernel data into user-space and an
   alternative to `/proc` filesystem.
   
   This change adds support for BPF iterators on the user-space side. It
   provides a possibility to retrieve the outputs of BPF iterator programs
   both from sync and async Rust code.
   
   [0] https://docs.kernel.org/bpf/bpf_iterators.html

### Bug Fixes

 - <csr-id-bf1899471bda7a97691876a379f3e04ceda685b3/> Prevent `NetNsGuard` from crossing threads
   Dropping the guard on another thread would restore the wrong thread's
   network namespace. Prevent this by marking `NetNsGuard` as `!Send`.
 - <csr-id-e2ab3ee0e2ec85116f4529bcc97a5da4f7043e70/> Clean up after errors in `NetNsGuard::new()`
 - <csr-id-215048bf9078af298072bf5ef8f36843e08b7799/> simplify BTF map detection and fix peek syscall name
   Use `btf_value_type_id` alone to detect BTF maps in `parse_map_info`.
   
   Checking both type IDs here is redundant. Keyless BTF maps such as bloom
   filters may leave `btf_key_type_id` unset, while `btf_value_type_id` still
   reliably identifies the map as BTF-backed. Using the value type keeps the
   logic smaller and avoids misclassifying keyless maps as legacy maps.
   
   Also update `BloomFilter::contains` to report `bpf_map_peek_elem` and adjust
   the unit test to expect the correct syscall name.

### Other

 - <csr-id-7277a57ea8cdb74918d3096a4b22b6d814481973/> fix consumer ordering
   RingBuf publishes the consumer position and then reads producer state to
   decide whether to wait. The kernel commits a record and then reads the
   consumer position to decide whether to notify. Without a full StoreLoad
   barrier, both sides can read stale positions and leave a committed
   record queued without a notification.
   
   The consumer store is SeqCst, but the later producer and record-header
   loads are Acquire. Rust does not require that pair to provide StoreLoad
   ordering. It happens to do so on tested x86-64 systems because LLVM
   emits xchg for the store, and on AArch64 because its STLR and LDAR
   instructions provide RCsc ordering. On powerpc64, however, LLVM places
   sync before the store and isync after the load, leaving no full barrier
   between them.
   
   Publish the consumer position with a Release store, then issue an
   explicit SeqCst fence before checking the producer position or retrying
   a busy record. This provides the StoreLoad barrier on every target while
   retaining the Release ordering needed when the kernel reuses consumed
   records.
 - <csr-id-6fbf4c751d3e7093379a2f64cdf38b7265ca3c18/> support socket filter reuseport attach
   Add ReusePortSocketFilter as the aya program abstraction for
   attaching a BPF_PROG_TYPE_SOCKET_FILTER program as a SO_REUSEPORT
   selector. Regular socket filters and reuseport selectors use different
   attachment paths, different kernel slots, and different return-value
   semantics, so modeling them as separate aya program views makes the
   user-facing API explicit.
   
   Aya still follows libbpf section rules: socket filter programs load
   from SEC("socket"), and aya does not introduce a socket/reuseport
   section. Since the section cannot distinguish the two views,
   ReusePortSocketFilter is selected by the user's try_into target type
   over the same loaded program type.
 - <csr-id-b5c672c69bf667dd6a0929c6712b535e1b3b3495/> properly check tracing support
   Some arm64 kernels can load tracing programs but cannot attach BPF
   trampolines until 6.4.
 - <csr-id-3d0c7b839e09399fb64aaff40342fc2a3395563a/> support test-run for fexit
   Add TestRun support for fexit programs so userspace can invoke the
   kernel tracing test-run path.
   
   The tracing test-run path has no caller-provided input and no
   meaningful program result for fentry/fexit, so the API reports only
   success or syscall failure instead of exposing empty option or result
   types.
 - <csr-id-4bd00c569ef291b20a63a6892a4aae05d6a268d8/> add uprobe virtual address helper
   Add a fallible `UProbeAttachLocation` constructor for callers that
   have already resolved a symbol or instruction to an ELF virtual
   address. The helper converts that address, together with the
   containing section's address and file offset, into the target object
   file offset expected by uprobes.
   
   Return typed errors when the instruction address cannot be in the
   containing section or when the computed file offset overflows.
 - <csr-id-1412bb3747801644abc773d8a1d7c5123fe7aec7/> relax SkReuseport receivers
   SkReuseport attach and detach do not mutate program state. Change attach
   to take &self, and make detach an associated function that only needs
   a socket from the reuseport group.
 - <csr-id-1ade96f5f87519c6e879b35412c68ec76759019f/> remove SocketFilter link abstraction
   Socket filters follow the kernel's per-socket filter-slot model. A
   socket has one filter slot, so attaching another socket filter replaces
   the current filter instead of creating a second attachment.
   
   The detach API has the same shape: it clears the socket's current
   filter slot and does not identify the program that installed it. That
   makes a link-level RAII abstraction unsafe for SocketFilter, because an
   old link or dropped program can detach a replacement filter.
   
   Stop returning a link handle from SocketFilter::attach and add an
   explicit SocketFilter::detach(socket) operation instead. Document that
   dropping SocketFilter or Ebpf does not detach socket filters.
 - <csr-id-98d8feb63325c9576caf6aa2040c465c985ef5ee/> add classid to SchedClassifier netlink attach
   Add `classid: Option<TcHandle>` to `NlOptions` and write it as
   `TCA_BPF_CLASSID` inside `TCA_OPTIONS` when set. In direct-action
   mode this attribute provides the major 16 bits of the resulting
   class id; the minor 16 bits are written by the program at run time
   via `__sk_buff::tc_classid`.
   
   The kernel encodes both `tcm_handle` and `TCA_BPF_CLASSID` as
   `(major << 16) | minor`, so the same `TcHandle` type covers both
   roles; the field name on `NlOptions` documents which role each
   value plays.
   
   Store the value on `NlLink` so program replacement through
   `SchedClassifierLink::attach_to_link` preserves the binding.
   `cls_bpf_change` allocates a fresh `cls_bpf_prog` on every netlink
   replace and conditionally binds `prog->res.classid` to the qdisc;
   omitting the attribute on replace would silently clear the
   binding.
   
   Expose `SchedClassifierLink::classid` for introspection and extend
   `SchedClassifierLink::attached` to accept the classid alongside
   the existing priority and handle.
   
   Reject `prog_name` longer than `CLS_BPF_NAME_LEN` explicitly. The
   extra `TCA_BPF_CLASSID` slot leaves enough buffer slack to
   serialize oversized names when `classid` is `None`, which the
   implicit buffer overflow previously caught.
 - <csr-id-d82050acac6fd803f51caa0cba7cb63b59076146/> introduce TcHandle newtype
   Replace the raw u32 filter handle in NlOptions, NlLink, and the
   netlink helpers with a TcHandle newtype encoding the kernel's
   (major << 16) | minor layout. TcHandle::new(major, minor) mirrors
   the M:N syntax accepted by tc(8).
   
   Expose TcHandle::AUTO_ASSIGN for the sentinel that asks the kernel
   to allocate a handle, so callers can express intent at the type
   level instead of passing a magic 0.
 - <csr-id-bed496b37bd9969372d3263bfd2b02f61bef8def/> reuse helper probe internally
   Use the helper feature probe for probe_read_kernel and attach-cookie
   feature detection.
 - <csr-id-faae977ae953a23839357e1a53f7419b3781c3a8/> add eBPF helper feature probe
   Add a public probe for eBPF helper availability per program type. The
   new API lets callers check whether a selected `(ProgramType,
   BpfHelper)` pair is supported by the running kernel. Helper availability
   is program-type specific, so this provides a more precise answer than
   probing helper IDs or program types independently.
   
   For simplicity, expose the generated `bpf_func_id` type as `BpfHelper`
   instead of introducing a separate Aya wrapper. This makes the public API
   surface depend on generated platform bindings, but Aya's public API
   checks already run with the same x86_64 assumption.
 - <csr-id-df1e81c1302a29c51b6d21a92ee645d637e271ff/> fix program type constants
   Correct the SkMsg and SockOps PROGRAM_TYPE constants so
   from_program_info validates against the right kernel program type and
   feature probes using these constants check the intended program type.
 - <csr-id-d10c87e2506dfc78de9f79ae443999ae0a05e8e6/> implement BPF_PROG_TEST_RUN
 - <csr-id-53cda5ffa0934f72f9828833c5dc376517adfd24/> add acquire fence on perf data_head load
   The kernel publishes new perf records via smp_store_release on
   data_head, so userspace must issue an acquire barrier after the
   data_head load and before reading the record bytes. Without it,
   weakly ordered targets (arm64, ppc64, riscv) may speculatively
   read bytes that have not yet been published.
   
   The existing SeqCst fence before the data_tail store is the
   release-side barrier; it does nothing for head-side ordering.
   
   See the comment on `data_head` in include/uapi/linux/perf_event.h
   and perf_event_open(2).
 - <csr-id-073912689c6c842bba594eae349b8ddd3b0c2d91/> Remove the `no_std` support
   The original motivation for `no_std` support in `aya-obj` was to keep it
   closer to `object`. In practice, though, one of `aya-obj`'s main jobs is
   sanitizing bytecode and BTF, and that logic relies on dynamic data
   structures.
   
   Given that, keeping `no_std` support no longer reflects how the crate is
   actually used and only adds maintenance overhead.
 - <csr-id-11b7b0982dede7f0f5ff4b3e0f0b8e4c0e2e3101/> cover BTF type-id strip for blocklisted map types
   `bpf_create_map` zeroes `btf_key_type_id`, `btf_value_type_id`,
   and `btf_fd` before `BPF_MAP_CREATE` for fourteen map types
   whose kernel ops set `.map_check_btf` to `map_check_no_btf`.
   Add a `test_case`-driven regression test covering every entry
   in the strip list.
 - <csr-id-18153c74fa12c8771e4f7904ed6abcb85261ac96/> tighten uprobe basename target check
   is_basename_only currently accepts any path whose normalized
   component count is one, which incorrectly includes `/`, `.`,
   `..`, and paths with trailing separators such as `foo/`.
   Those inputs are not bare basenames and can still trigger
   ProcMap and ld.so resolution during scoped attaches.
   
   Use Path::file_name() equality to restrict basename-only
   detection to paths consisting solely of a file name. Add
   regression tests for the excluded edge cases.
   
   Also clarify that UProbe::attach accepts relative paths for
   binary and shared library targets; the docs previously only
   mentioned absolute paths and library names.
 - <csr-id-e25040ffe14de4521fdcdb539ce0b234aa966e1c/> skip ProcMap for path-like uprobe targets
 - <csr-id-759087ba7bd75267097b5d891a5d2a8be6ccf993/> replace pid Option<u32> with UProbeScope
   Replace the pid Option in UProbe::attach with UProbeScope so the
   all-processes, calling-process, and explicit-pid cases are all
   expressed directly in the type.
   
   This removes pid=0 as a magic value from the public API, keeps the
   calling-process case explicit, and uses the current pid for ProcMap
   resolution introduced in the previous commit. Update docs and
   integration tests to use the new scope-based API.
 - <csr-id-8912e413f36b9839e514f475e8b47029706e9a35/> fix pid=0 handling in uprobe attach
   perf_event_open treats pid=0 as the calling process/thread, so
   Some(0) should carry that meaning in UProbe::attach. However,
   aya unconditionally reads /proc/<pid>/maps when pid is Some, but
   /proc/0/maps does not exist.
   
   Use the current pid only for the ProcMap lookup, and keep pid=0 for
   the actual attach semantics. Add documentation and an integration test.
 - <csr-id-decfe44005b4b10cf3a241b21c2c35bdf53fd045/> reject BPF_F_STACK_BUILD_ID in StackTraceMap
   `BPF_F_STACK_BUILD_ID` switches stack entries to
   `struct bpf_stack_build_id` (32 bytes), but `StackTraceMap::get`
   unconditionally decodes values as `[u64]`, silently corrupting
   reads of any stack map that sets the flag.
   
   Reject the flag in `StackTraceMap::new` with the new
   `MapError::UnsupportedMapFlags` variant. Derive `max_stack_depth`
   from the declared `value_size`; the sysctl previously consulted
   is redundant with the kernel's own map_create check.
   
   Name the per-entry layout `StackEntry = u64` so the stride check
   in `new` and the lookup buffer in `get` reference the same type.
   
   Report stride violations with a new
   `MapError::InvalidValueStride { size, stride }` variant; the
   existing `InvalidValueSize` displays "expected 8" when any
   non-zero multiple of 8 would be valid.
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
 - <csr-id-85246f00e984b0b3b0ccdaa422d301b31e109881/> fix TryFrom<FdLink> link type checks
   Fix wrong bpf_link_type checks in TryFrom<FdLink> for UProbeLink,
   KProbeLink and TracePointLink. Consolidate all TryFrom<FdLink>
   implementations into an impl_try_from_fdlink! macro.
   
   Strengthen pin_lifecycle tests to verify the FdLink to link
   conversion, covering this previously untested path.
   
   Found while working on #1417.
 - <csr-id-48f9e00c2e148182172367d26b7e1b9095af16d5/> make Align not pub
   This has no effect, so drop it. Tidy up a bit while I'm here and explain
   the use of const refernces.
 - <csr-id-98960db18a01fe4fa932423e22a712b37d21b03a/> avoid some allocations
 - <csr-id-ed516b3ec040aa5f3b1fc4c5aa174fd0f8484355/> advance through write buffers
   Refactor netlink attribute writers to consume and return the remaining
   buffer instead of passing offsets through helper calls.
 - <csr-id-52c33ebdf84d0d3f0dcd13d861216d1a052005a3/> use constants more consistently
   Use returned lengths where possible rather than hard coding constants.
 - <csr-id-68be4b7297ce1533904fc54b281aa2e796ad2a6f/> use checked accessors
 - <csr-id-f49ef401a794789e1187bb06d506bd8742b66fcc/> avoid repeating NLA_ALIGNTO everywhere
 - <csr-id-cdfa52de6ed7fb766b3139cf42fcbab06ce12ad3/> fix attach on 6.17
   For LSM programs the target_btf_id is set at load time not attach time.
   
   Starting from
   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1209339844601ec1766f4ff430673fbcfe42bb51
   setting it at attach time results in EINVAL, because it happens to be
   interpreted as bits of the mprog part of the union.
 - <csr-id-c42157f0b566940b849b699109d1c660a0733fd3/> fix attachment failure with long program names
   The netlink attribute buffer in TcRequest was only 64 bytes, which is
   not enough when TC program names get close to the kernel's 256-byte
   limit. This led to a misleading no space left error when attaching
   programs with longer names.
   
   Bump the buffer size so it can precisely fit all the netlink attributes
   and the max-length name.
 - <csr-id-ae8c76d03757de8a7c07d2f3022362be179cbb07/> Fix `BloomFilter::contains` method
   Require the caller to pass a reference, not the owned value. That makes
   sure that the pointer is valid from the beginning.
 - <csr-id-294e0c19413d5a7c073d17d79ad4d154283499ce/> Add helper for safe loading of globals
 - <csr-id-7cbd816a7701ea414b6367abdee6cae878755d34/> document tcx link pinning for atomic program replacement
   Add documentation and integration test for SchedClassifier link pinning,
   which enables zero-downtime program updates in production environments.
   
   - Add link pinning example to SchedClassifier::attach_with_options()
     showing atomic replacement workflow for TCX mode (kernel >= 6.6).
   - Add pin_tcx_link() integration test verifying link persistence
     across program unload and atomic replacement capability.
 - <csr-id-775f42d781c9379016647f0abf1d42f57522d84d/> avoid trying to parse paths in proc maps
   There are various oddities in how the kernel prints path including
   "(deleted)" suffix, bracketed properties e.g. "[vdso]", ashmem and memfd
   paths, and possibly others. Rather than try to handle these in
   `ProcMapEntry::parse` just leave them as they appear and let the caller
   deal with them.
   
   Change splitting behavior to any number of consecutive whitespace
   characters between columns to account for padding.
   
   This allows uprobe attachment to succeed in the presence of deleted
   mapped files and in more cases of android special attributes.
   
   Rewrite tests using `test_case`.
 - <csr-id-eb25e6af2a14ef65075e75e06d6d7a78b3bc6d82/> avoid some allocations
   Use `Path::display` in test assertions for better errors.
 - <csr-id-efecc088b37a9438cb79f234fbfa735356816a64/> trim whitespace just once
   Update tests to include the expected trailing newline.
 - <csr-id-d1f72a580c640b7ad2ae71c3acd2ff4ef2bf02c0/> improve `ParseLine as Debug`
   Print human-readable strings rather than sequences of bytes.
 - <csr-id-80d79526a6fe3fff0ea07b018d0eed03f6d8de71/> move test_resolve_attach_path to tests module
 - <csr-id-4984ddc0467a3e0fef92fd8ee6edb83a1274700a/> use integer::next_multiple_of
   See https://github.com/rust-lang/rust-clippy/issues/14144.
 - <csr-id-eb99da3cbb4bcf2b20c8d0797566dd330261aadb/> bundle attach location+cookie via UProbeAttachPoint
   This follows the #1417 review discussion: by bundling location
   + cookie into a UProbeAttachPoint we get a more idiomatic Into<_>
   entry point, keep the one-to-one relationship enforced by the type
   system, and make it easier to extend attach with multi-location
   support without introducing parallel arrays or a brand new API.
 - <csr-id-46221ad11dfb44fc0cc46425e1648c6750d98a5e/> use RAII to clean up in the error path
 - <csr-id-72810f095f1461d5d254d37e7174bb47bd15f691/> ProbeKind is Entry/Return
   We already have separate types for KProbe and UProbe.
 - <csr-id-a4a3c1641f8b6006363be6c66516daf73a94aec7/> use exhaustive matches
 - <csr-id-1944c4aa008d685053bb617b728e3e4f723d7672/> refactor perf_event_open_trace_point
   Rewrite it in terms of perf_event_open.
 - <csr-id-d4b2dde78ac88b0e7e9141e0675bd8888f23c1f6/> inline `perf_event_open_bpf`
   This function has one caller and provides no abstraction.
 - <csr-id-7e07f85edcbdbe2f5d1c49a872e56d1ff458991e/> privatize PerfLink
   There's no way to obtain this type externally.
 - <csr-id-27c7f1c84f29a6f5e775ce6761a87859a351d95d/> disambiguate `fd` names
 - <csr-id-1791d497d3af39bd8da4eb666dece22c60e97281/> remove superfluous type ascription
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
 - <csr-id-18c7f7ccd6d462516d94b8720d18f8b7b5d98361/> push down type safety
   This makes it more difficult to mishandle callers of `perf_event_open`.
   
   Change `wakeup_events = 0` to 1; per `man 2 perf_event_open`:
   
     Prior to Linux 3.0, setting wakeup_events to 0 resulted in
     no overflow notifications; more recent kernels treat 0 the
     same as 1.
 - <csr-id-7e405c216e0d806f96c76f2554d069722f97bec3/> simplify PerfEventScope
 - <csr-id-4fbce44b6a49dd189a7a3520c66db45baf3832ea/> tolerate proc map trailing newline
   Proc maps terminate with a newline so split(b'\n') yields an empty
   slice at the end. Filter it out before parsing so the absolute-path
   fallback for pid-scoped attach doesn't get short-circuited by a
   ProcMap::ParseLine error.
 - <csr-id-3a3c45100942c903c21e69595eff9e4289910835/> restore must_exist argument to set_global
   In
   https://github.com/aya-rs/aya/commit/03e84871773e09badf08bdef8e83b4f1256850a4
   we deprecated set_global but accidentally broke its API by deleting the
   must_exist argument.
 - <csr-id-17c7c7951cb45a5903134b21658df7e989e672ed/> enable clippy::as_underscore
 - <csr-id-03e84871773e09badf08bdef8e83b4f1256850a4/> rename `set_` methods on `EbpfLoader`
   This loader is more of a builder, so these `set_` methods didn't
   quite fit. See [this discussion][1] for the motivation.
 - <csr-id-17171647f7e447698f0d4733a3dbb144ded53466/> fix producer position initialization
   The RingBuf caches the last value it read of the producer so it doesn't
   need to constantly contend on the actual producer cache line if lots of
   messages have yet to be consumed. It was bogus to initialize this cache
   at 0. This patch initializes it properly and adds testing.
 - <csr-id-5802dc7a23ac878105b55710df6c75cb5e030c3a/> allow specifying a pin path for a named map
   This commit extends the EbpfLoader with set_map_pin_path that allows the
   caller to associate a named map with a pin path.
   
   One note is that this path is an absolute path, not relative to
   `map_pin_path`, and it forces the map to be loaded from that path.
 - <csr-id-1c924bb421dd731a7557ae4140f3bed7982894d2/> rename map_pin_path to default_map_pin_path
   This is the path in which pinned maps are created or resolved. It
   isn't actually the path for any specific map itself. This rename
   makes way for a method `set_map_pin_path` that actually specifies
   the pin path for a specific map.
 - <csr-id-0144c0eb22d08b29ab6f9f5e97e1ea1d9866fd41/> defer cleanup to ensure unpin
 - <csr-id-2e5f5efbf13c71dc1462d1221e77055c7c3e857a/> make ProgramInfo a proper enum
   This allows us to distinguish between LSM and LSM_CGROUP programs and do
   the proper capability check in is_program_supported.
 - <csr-id-7224efcad8726439e9ac9ccdc28e19116bf00606/> patch up 0-size datasec
   Use OnceCell for ENUM64 while I'm here as well.
 - <csr-id-4c974d33a3b5728b49c82183666153aa20e14b30/> replace kernel version check with fallback
 - <csr-id-3d7fbaad28fc8ad49f0a5afb08c686011ed25c5c/> enforce valid perf_event type & config combos
   Add guardrails for when setting event type and config for perf_event
   programs. The `PerfEventConfig` enum now defines the event `type` and
   `config` of interest.
   
   Remove public re-exports, and add idiomatic Rust types for:
   - perf_hw_id => HardwareEvent
   - perf_sw_ids => SoftwareEvent
   - perf_hw_cache_id => HwCacheEvent
   - perf_hw_cache_op_id => HwCacheOp
   - perf_hw_cache_op_result_id => HwCacheResult
   
   The motivation behind this is mainly for the `type` and `config` fields
   of `bpf_link_info.perf_event.event`. The newly added enums are planned
   to also be used in the `bpf_link_info` metadata.
   
   Although `Breakpoint`/`PERF_TYPE_BREAKPOINT` variant exists, it is not
   fully implemented. It's only usage at the moment is in link info.
 - <csr-id-82aec2696394f953c886f146f02673753a94cb0d/> add missing impl_try_into_fdlink
 - <csr-id-fc5387c80626957017ceeb988322bc288f438059/> cgroup attachment type support
 - <csr-id-8e752148155b49e3732a6563ee7ce1f8ecbf6307/> properly check for LSM support
   Turns out this is not supported in aarch64 until 6.4.
 - <csr-id-de42b80c74883f512542875e7cfa96b8634a8991/> add BPF_MAP_TYPE_SK_STORAGE
   This map type requires BTF, and we can finally do it!
 - <csr-id-6babf1796988af742711cdcdae691e4dbdd1641e/> use shared helpers
 - <csr-id-75edc3d2948bea7b63edc60365e4cc10e414921b/> downcase log strings
 - <csr-id-742f700dcc43fe9ad5ccdd23d1b6e55673807c06/> add newline between doc and imports
 - <csr-id-263e864cd9e09848a9861a967763cf1069ae01c8/> add Map::from_map_data() for pinned map access
   Enables creation of Map enum variants directly from MapData instances,
   allowing user-space handles to pinned BPF maps without requiring the
   original BPF object.
   
   Supports multiple BPF map types.
 - <csr-id-0d1193720bc0e5915eff32b5d4edd21178a98991/> generate docs in macro
   Remove a bunch of repetition and missing links.
 - <csr-id-8ee12d337fbc1662350815dbde620f2f1b23f962/> fix rustdoc link in macro
   `$wrapper` is not visible to rustdoc before expansion. Build the link
   after expansion.
 - <csr-id-35332f2288b0bbb8981233ae464715ea9217b081/> remove `AsyncPerfEventArray{,Buffer}`
   Rather than support N async runtimes, push this to the user. The
   relevant types (`PerfEventArrayBuffer` and `RingBuffer`) implement
   `As{,Raw}Fd` which is sufficient with integration with tokio, smol, and
   other async runtimes.
 - <csr-id-ab182be622acb245db0adef58591978208bcdb2c/> `construct_debuglink_path()` should be infallible
   `construct_debuglink_path()` returns a `Result`, but it doesn't actually
   do anything that can fail. This means callers must do a useless
   `unwrap()` to get at the return value.
   
   This fixes the signature to reflect that the function is infallible.
 - <csr-id-3f02127b6b16f618aa2ccb444fcd1402c887ffaf/> `impl AsFd for RingBuf`
   This bound is needed for e.g. `smol::Async`.
 - <csr-id-4b5ba53a36b0c920969bbb9016330cd195e457dc/> implement TryFrom<[Program Type]> for FdLink for various program types
   Implements TryFrom for FdLink for CgroupSkb, CgroupSock, CgroupSockAddr
   and SockOps program types. This allows support for link pinning for
   these program types, aligning with the documentation for FdLink.
 - <csr-id-7a0dabc295a0d856f6c3611331c9434b83f63ae8/> short-circuit info field if non-zero
   Short-circuits `CACHE` to true if the field is non-zero.
   
   This saves from executing the probing logic since the logic essentially
   checks if the field can process (or doesn't error) non-zero value.
 - <csr-id-23bc5b5836c3b8383f2f8a78bd3902e193a7a176/> cache feat probed info fields
   Cached probed for ProgramInfo fields instead of exposing it through
   global FEATURE. Probing occurs on cache miss, which happens when first
   accessing the field, *and* if the field is 0.
 - <csr-id-bd492860f585ad8b9612ef9c8addde2fb8d5e814/> add feature probing for map type
   Add API that probes whether kernel supports a map type.
 - <csr-id-ab77decd9a708147e679a12ba6be3774f8946dd8/> add feature probing program type
   Adds API that probes whether kernel supports a program type.
 - <csr-id-33c9f2b2b2cf5587139e36c0e05de13e72cf77fa/> uprobe: use PathBuf for ResolveSymbolError::DebuglinkAccessError
   Makes no sense to use a string, as it's a path.
   This breaks the public API.
 - <csr-id-90d56048777ff571293a99450201562532fcaa7f/> uprobe attach: use mmap instead of reading whole binaries to memory
 - <csr-id-647100faa7f4dff819642183c94b5a05389eb2af/> clean up resolve_symbol a bit
   Instead of using intermediate values to extend the lifetime of the
   object::File, we just separate the branches.
 - <csr-id-3aded0e0a5c644569b0a268ea31c6c0edddea3b2/> move Mmap struct to aya::util
 - <csr-id-fc69a069727475060ee6d9895ac2745b8965237f/> fix is_probe_read_kernel_supported in aarch64 kernels 5.5
   In aarch64, with kernel 5.5, my programs that use `bpf_probe_read_user`
   don't work successfully because `aya` is mistakenly re-writting it
   `bpf_probe_read` because it falsely detects that the kernel doesn't
   support `bpf_probe_read_user`.
   
   I hadn't updated my `aya` version in a while, but while updating it to
   fix a separate issue (panics when parsing kernel versions of PVE
   kernels) and running my test suite I saw tests failing on aarch64 5.5
   kernels. A git bisect led me to this commit:
   942ea51906fea4e3152e1bd3ef5832bc0df5b205 and further investigation in the
   difference of the new and old assembly showed that the only difference
   was subtracting 8 vs adding -8. When I put it back as adding 8 (but
   without handwritten assembly) then things work as expected. Since it
   used to be `BPF_ADD` and the commit that changed it was just about no
   longer handwriting assembly without any reason for the switch to
   `BPF_SUB` putting it back as `BPF_ADD` seems reasonable. 
   
   When using `BPF_SUB` 8, the handwritten program in this function
   returns a permission error which is treated by this function as
   `bpf_probe_read_kernel` not being supported when it is but for some
   reason `BPF_SUB` is not. My guess is that it might be an early verifier
   error but I am not 100% sure as I thought verifier errors are normally
   `EINVAL` not `EPERM` but I have a vague memory of seeing `EPERM` in the
   past for errors that happened very early in the verifier.
 - <csr-id-3edc36af9d2a6a90a57d449e66267ca081aa6a86/> remove unhelpful comment
 - <csr-id-49a828ec5655f6ecd0c38083c6c0dca217bad777/> reorder-keys
   Group non-workspace keys before workspace ones for readability.
 - <csr-id-f48b5a4a84a858dd3a24101a83a3b03c314f1c5c/> Ensure that truncated map names are NULL terminated
   Limit of map names in eBPF is 16 bytes and they have to be NULL
   terminated.
   
   Before this change, long names were truncated to 16 bytes.
   `MAP_WITH_LOOOONG_NAAAAAAAAME` would become `MAP_WITH_LOOOONG`, which
   doesn't contain the NULL byte.
   
   This change fixes that by truncating the name to 15 bytes, ensuring
   that the 16th byte is NULL. `MAP_WITH_LOOOONG_NAAAAAAAAME` is truncated
   to `MAP_WITH_LOOOON\0`.
 - <csr-id-22c8f783e7d5dd2ddc8d973885e1895a6e842440/> allow program names to be static strings
 - <csr-id-73a34e1571a606124c7e89ecf71ff001508643dc/> Add `XskMap::unset`
 - <csr-id-ea76e0f62dbdff618789dfc9a9d8604a89f61f13/> parse complete entries from /proc/$pid/maps
 - <csr-id-27d69c35f030dda687664af8dc2d2fd52d238c6b/> remove panics on indeterminate kernel version
   Cache the current kernel version in a thread-local while I'm here.
   
   Closes https://github.com/aya-rs/aya/issues/1024.
   Closes https://github.com/aya-rs/aya/pull/1042.
 - <csr-id-9eefb48a0ad90831c09c7bd941d035b34e1f1771/> remove some copies
   Replace truncation with proper NULL termination at the site of use.
 - <csr-id-89aa638e05795be0ab86711d6e2ade2a8dbafcae/> add TODO to remove once_cell
 - <csr-id-de1e80c1d1bab7fd73acc97e5adb0985712c35c7/> encode perf_event ioctl contract
   Enumerate the possible ioctls in an enum and bake in the knowledge that
   they all return 0 on success and -1 on error.
 - <csr-id-eee7975ce42520513acda16977b21e19a1cd159d/> remove redundant TEST_SYSCALL use
   This is already done in `syscall`.
 - <csr-id-055e36e8d92c79c1a9cf61f1a08d2d9be4e74d14/> encode perf_event_open(2) contract
   Per man 2 perf_event_open:
   
   > RETURN VALUE
   >   On success, perf_event_open() returns the new file descriptor.  On
   >   error, -1 is returned and errno is set to indicate the error.
   
   Bake this into our syscalls so we stop using `_` so much which can hide
   information loss. Remove the type parameter to SysResult.
 - <csr-id-bdd8ae2d0b443513c73143da968d400df9b05464/> avoid `_`
   This can silently discard information, so we shouldn't do it.
 - <csr-id-f6df60fa7072dfd7cfb09d0bc3bb1dad0f965940/> encode bpf(2) contract
   Per man 2 bpf:
   
   > RETURN VALUE
   >   For a successful call, the return value depends on the operation:
   >
   >   BPF_MAP_CREATE
   >     The new file descriptor associated with the eBPF map.
   >
   >   BPF_PROG_LOAD
   >     The new file descriptor associated with the eBPF program.
   >
   >   All other commands
   >     Zero.
   >
   >   On error, -1 is returned, and errno is set to indicate the error.
   
   Bake this into our syscalls so we stop using `_` so much which can hide
   information loss.
 - <csr-id-2d782606fe984cb2ffebe7b98807a58494441a4c/> avoid Result::is_{ok,err}
   These methods discard information. Discarding information is bad.
 - <csr-id-dab1aa4e291e4301eca0bd6532449dc7079ff10a/> avoid retagging in tests
 - <csr-id-f51ab800758689a67c312742ffdf9116e1e178c0/> attempt to preserve provenance
   In tests, provide write provenance.
 - <csr-id-888701425bbfc48365edd6f03d9872d5c86a3e18/> use MMap from ring_buf
 - <csr-id-ff82c244f77f46da9245b42ede56c0500cd6b56f/> avoiding casting pointers to usize
 - <csr-id-e17feca2d6d45365fc1d717f0735ee4dd9664ec3/> remove some stale comments
 - <csr-id-9a47495227a03400fa2549b07fe8af131f21e759/> preserve pointer provenance
 - <csr-id-122c49fca4ea1cdf89bbffbb48a440dfd3744937/> appease clippy
   While I'm here convert a String to a PathBuf in an error to avoid lossy
   conversions.
   
   See https://rust-lang.github.io/rust-clippy/master/index.html#io_other_error.
 - <csr-id-9e1bcd0ab87f69bcd323eef680957a534b655fac/> Fix PerCpuHashMap NotFound
   PerCpuHashMap was never returning MapError::KeyNotFound because
   bpf_map_lookup_elem_per_cpu was replacing Ok(None) with
   Ok(Some(zeroed_value)).
   
   Update bpf_map_lookup_elem_per_cpu to map the Option value.
 - <csr-id-919833510095cfc49d1b9874429f403167227fbd/> remove outdated workaround
   bindgen can handle these macros now.
 - <csr-id-628b7fb0221321aa0cc649cd738c449a7dbb0108/> :programs::uprobe: add support for cookies
 - <csr-id-85c73af1feb8d0b227ca2e7b61b8542c4eb8b918/> Improve the description of `take_link` methods
   Don't mix the tenses.

### Refactor

 - <csr-id-8d1d15b7dabe29e3349327f6657e4def391dfe3f/> Return an error instead of panicking
   Given that the test helpers are now exposed to users, avoid panicking
   and return an error.
   
   Make `NetlinkError` public, making it possible for downstream users to
   refer to the type while matching on the `AyaTestError::Netlink` variant.
 - <csr-id-b9b92ce197171717d99cd9ea1eed29b1cfa0666b/> Move `utils.rs` from the `integration-test` crate to `aya`
   Agave [0] has interest in using test helpers (e.g. `NetNsGuard`) outside
   of Aya monorepo for testing their eBPF programs. Move `utils.rs` from
   the `integration-test` crate to `test_helpers.rs` in the aya crate, to
   make that possible. Guard that module with the `test-helpers` feature.
   
   [0] https://github.com/anza-xyz/agave

### Test

 - <csr-id-f10988d56a2ac7575cfd79c0eaec66b62a9b6227/> replace test-case with rstest
   test-case relies on cooperating attribute macros when wrapping
   generated parameterized tests. Stacking it with test_log can register
   each generated case twice, so passing tests may run more than once and
   mask order-sensitive or flaky behavior.
   
   Move the parameterized tests to rstest, but do not rely on rstest's
   implicit test-attribute detection. rstest treats attributes whose path
   ends in test as test attributes; that has its own failure mode if a
   non-test decorator matches, potentially producing cases that do not run
   as intended.
   
   Use explicit #[test_attr(...)] wrappers for every rstest case that
   needs test_log or tokio, so generated tests get the intended harness
   attribute instead of depending on implicit detection.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 196 commits contributed to the release.
 - 133 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 4 unique issues were worked on: [#1119](https://github.com/aya-rs/aya/issues/1119), [#1235](https://github.com/aya-rs/aya/issues/1235), [#1443](https://github.com/aya-rs/aya/issues/1443), [#1501](https://github.com/aya-rs/aya/issues/1501)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#1119](https://github.com/aya-rs/aya/issues/1119)**
    - Update docs for load to mention include_bytes_aligned ([`df053f0`](https://github.com/aya-rs/aya/commit/df053f095b67f8984ae31fd0ca1042f4e38c3378))
 * **[#1235](https://github.com/aya-rs/aya/issues/1235)**
    - Fix is_probe_read_kernel_supported in aarch64 kernels 5.5 ([`fc69a06`](https://github.com/aya-rs/aya/commit/fc69a069727475060ee6d9895ac2745b8965237f))
 * **[#1443](https://github.com/aya-rs/aya/issues/1443)**
    - Set value_size to 0 if loading ringbuffer ([`d022b8d`](https://github.com/aya-rs/aya/commit/d022b8dce40fb60271a1270b13efb60951208328))
 * **[#1501](https://github.com/aya-rs/aya/issues/1501)**
    - Aya, aya-ebpf, aya-obj: add BTF bloom filter support ([`904fbe2`](https://github.com/aya-rs/aya/commit/904fbe265e8a97c7c4869a0898bcfd71502aae62))
 * **Uncategorized**
    - Release aya-obj v0.3.0 ([`269dfaf`](https://github.com/aya-rs/aya/commit/269dfaf4a20b99f2e3d384e3e5d13b226f507360))
    - Prevent `NetNsGuard` from crossing threads ([`bf18994`](https://github.com/aya-rs/aya/commit/bf1899471bda7a97691876a379f3e04ceda685b3))
    - Clean up after errors in `NetNsGuard::new()` ([`e2ab3ee`](https://github.com/aya-rs/aya/commit/e2ab3ee0e2ec85116f4529bcc97a5da4f7043e70))
    - Return an error instead of panicking ([`8d1d15b`](https://github.com/aya-rs/aya/commit/8d1d15b7dabe29e3349327f6657e4def391dfe3f))
    - Add a docstring for `NetlinkError::raw_os_error()` ([`745065a`](https://github.com/aya-rs/aya/commit/745065a74241ae8c39180c0cdc1a5444b5605dfb))
    - Move `utils.rs` from the `integration-test` crate to `aya` ([`b9b92ce`](https://github.com/aya-rs/aya/commit/b9b92ce197171717d99cd9ea1eed29b1cfa0666b))
    - Fix consumer ordering ([`7277a57`](https://github.com/aya-rs/aya/commit/7277a57ea8cdb74918d3096a4b22b6d814481973))
    - Aya, aya-ebpf: add InodeStorage and CgrpStorage ([`bd397b6`](https://github.com/aya-rs/aya/commit/bd397b644723b13bc4397acb0c792546d5df7215))
    - Aya, aya-ebpf: add CgroupStorage and PerCpuCgroupStorage ([`9ec80ac`](https://github.com/aya-rs/aya/commit/9ec80ac6a91b8edbc51a0476560d38d843bf8031))
    - Support socket filter reuseport attach ([`6fbf4c7`](https://github.com/aya-rs/aya/commit/6fbf4c751d3e7093379a2f64cdf38b7265ca3c18))
    - Replace test-case with rstest ([`f10988d`](https://github.com/aya-rs/aya/commit/f10988d56a2ac7575cfd79c0eaec66b62a9b6227))
    - Properly check tracing support ([`b5c672c`](https://github.com/aya-rs/aya/commit/b5c672c69bf667dd6a0929c6712b535e1b3b3495))
    - Support test-run for fexit ([`3d0c7b8`](https://github.com/aya-rs/aya/commit/3d0c7b839e09399fb64aaff40342fc2a3395563a))
    - Aya, aya-ebpf: add CgroupArray ([`eb73f8c`](https://github.com/aya-rs/aya/commit/eb73f8ca9260e48141a1bdf1a492799826a85515))
    - Add typos-cli configuration and CI ([`c1eb427`](https://github.com/aya-rs/aya/commit/c1eb42780c8e0eba340808eb4b75df15ac434e61))
    - Add uprobe virtual address helper ([`4bd00c5`](https://github.com/aya-rs/aya/commit/4bd00c569ef291b20a63a6892a4aae05d6a268d8))
    - Relax SkReuseport receivers ([`1412bb3`](https://github.com/aya-rs/aya/commit/1412bb3747801644abc773d8a1d7c5123fe7aec7))
    - Remove SocketFilter link abstraction ([`1ade96f`](https://github.com/aya-rs/aya/commit/1ade96f5f87519c6e879b35412c68ec76759019f))
    - Add classid to SchedClassifier netlink attach ([`98d8feb`](https://github.com/aya-rs/aya/commit/98d8feb63325c9576caf6aa2040c465c985ef5ee))
    - Introduce TcHandle newtype ([`d82050a`](https://github.com/aya-rs/aya/commit/d82050acac6fd803f51caa0cba7cb63b59076146))
    - Reuse helper probe internally ([`bed496b`](https://github.com/aya-rs/aya/commit/bed496b37bd9969372d3263bfd2b02f61bef8def))
    - Add eBPF helper feature probe ([`faae977`](https://github.com/aya-rs/aya/commit/faae977ae953a23839357e1a53f7419b3781c3a8))
    - Fix program type constants ([`df1e81c`](https://github.com/aya-rs/aya/commit/df1e81c1302a29c51b6d21a92ee645d637e271ff))
    - Aya, aya-ebpf, aya-obj: add HashOfMaps and ArrayOfMaps ([`4075b5e`](https://github.com/aya-rs/aya/commit/4075b5ec62beeb7b69c1d99847ec9c65ba85a49f))
    - Make XDP attach mode type-safe ([`ae94e9e`](https://github.com/aya-rs/aya/commit/ae94e9e10719860fefd6199f95ad87ff5367e1db))
    - Implement BPF_PROG_TEST_RUN ([`d10c87e`](https://github.com/aya-rs/aya/commit/d10c87e2506dfc78de9f79ae443999ae0a05e8e6))
    - Aya, integration-test: replace read_events with try_fold/fold/for_each ([`be9d3fa`](https://github.com/aya-rs/aya/commit/be9d3faf26115e6ab4a00e41fb6aee966d12743e))
    - Add acquire fence on perf data_head load ([`53cda5f`](https://github.com/aya-rs/aya/commit/53cda5ffa0934f72f9828833c5dc376517adfd24))
    - Remove the `no_std` support ([`0739126`](https://github.com/aya-rs/aya/commit/073912689c6c842bba594eae349b8ddd3b0c2d91))
    - Cover BTF type-id strip for blocklisted map types ([`11b7b09`](https://github.com/aya-rs/aya/commit/11b7b0982dede7f0f5ff4b3e0f0b8e4c0e2e3101))
    - Tighten uprobe basename target check ([`18153c7`](https://github.com/aya-rs/aya/commit/18153c74fa12c8771e4f7904ed6abcb85261ac96))
    - Skip ProcMap for path-like uprobe targets ([`e25040f`](https://github.com/aya-rs/aya/commit/e25040ffe14de4521fdcdb539ce0b234aa966e1c))
    - Replace pid Option<u32> with UProbeScope ([`759087b`](https://github.com/aya-rs/aya/commit/759087ba7bd75267097b5d891a5d2a8be6ccf993))
    - Fix pid=0 handling in uprobe attach ([`8912e41`](https://github.com/aya-rs/aya/commit/8912e413f36b9839e514f475e8b47029706e9a35))
    - Reject BPF_F_STACK_BUILD_ID in StackTraceMap ([`decfe44`](https://github.com/aya-rs/aya/commit/decfe44005b4b10cf3a241b21c2c35bdf53fd045))
    - Add BPF_PROG_TYPE_SK_REUSEPORT support ([`4940ee6`](https://github.com/aya-rs/aya/commit/4940ee6c69196634de9bf2f3c434cb5a57f194e5))
    - Fix TryFrom<FdLink> link type checks ([`85246f0`](https://github.com/aya-rs/aya/commit/85246f00e984b0b3b0ccdaa422d301b31e109881))
    - Simplify BTF map detection and fix peek syscall name ([`215048b`](https://github.com/aya-rs/aya/commit/215048bf9078af298072bf5ef8f36843e08b7799))
    - Set fixed expected attach types ([`2ed3531`](https://github.com/aya-rs/aya/commit/2ed3531463d4d7ece84b973f0521d954c629191d))
    - Remove duplicate attach type state ([`7b6b752`](https://github.com/aya-rs/aya/commit/7b6b752dc1536d6d13bebc939ce404781810fcbd))
    - Make Align not pub ([`48f9e00`](https://github.com/aya-rs/aya/commit/48f9e00c2e148182172367d26b7e1b9095af16d5))
    - Align by 8b in include_bytes_aligned. ([`a7144b9`](https://github.com/aya-rs/aya/commit/a7144b9a6efc963e1fdcc0716990846a9d407ae1))
    - Avoid some allocations ([`98960db`](https://github.com/aya-rs/aya/commit/98960db18a01fe4fa932423e22a712b37d21b03a))
    - Advance through write buffers ([`ed516b3`](https://github.com/aya-rs/aya/commit/ed516b3ec040aa5f3b1fc4c5aa174fd0f8484355))
    - Use constants more consistently ([`52c33eb`](https://github.com/aya-rs/aya/commit/52c33ebdf84d0d3f0dcd13d861216d1a052005a3))
    - Use checked accessors ([`68be4b7`](https://github.com/aya-rs/aya/commit/68be4b7297ce1533904fc54b281aa2e796ad2a6f))
    - Avoid repeating NLA_ALIGNTO everywhere ([`f49ef40`](https://github.com/aya-rs/aya/commit/f49ef401a794789e1187bb06d506bd8742b66fcc))
    - Rename EbpfGlobal to Global ([`b9cb76b`](https://github.com/aya-rs/aya/commit/b9cb76b302bdd1288b6486fb3a0627ea40cc3dbc))
    - Fix attach on 6.17 ([`cdfa52d`](https://github.com/aya-rs/aya/commit/cdfa52de6ed7fb766b3139cf42fcbab06ce12ad3))
    - Fix attachment failure with long program names ([`c42157f`](https://github.com/aya-rs/aya/commit/c42157f0b566940b849b699109d1c660a0733fd3))
    - Fix `BloomFilter::contains` method ([`ae8c76d`](https://github.com/aya-rs/aya/commit/ae8c76d03757de8a7c07d2f3022362be179cbb07))
    - Add helper for safe loading of globals ([`294e0c1`](https://github.com/aya-rs/aya/commit/294e0c19413d5a7c073d17d79ad4d154283499ce))
    - Dial the lints to 100 ([`2f8759c`](https://github.com/aya-rs/aya/commit/2f8759cc62e2a420eef463e271d354fcf65eca9d))
    - Enable unused_qualifications lint ([`e746618`](https://github.com/aya-rs/aya/commit/e746618143f010fe7f05635a1a6e1a8b723bfd31))
    - Use usize::next_multiple_of ([`be872b1`](https://github.com/aya-rs/aya/commit/be872b1cff07365362925acc875a20609720f646))
    - Aya, aya-ebpf: reduce duplication ([`f35f7a3`](https://github.com/aya-rs/aya/commit/f35f7a3610d8296d97c6f0a47e75dbb4188f5212))
    - Document tcx link pinning for atomic program replacement ([`7cbd816`](https://github.com/aya-rs/aya/commit/7cbd816a7701ea414b6367abdee6cae878755d34))
    - Avoid trying to parse paths in proc maps ([`775f42d`](https://github.com/aya-rs/aya/commit/775f42d781c9379016647f0abf1d42f57522d84d))
    - Avoid some allocations ([`eb25e6a`](https://github.com/aya-rs/aya/commit/eb25e6af2a14ef65075e75e06d6d7a78b3bc6d82))
    - Trim whitespace just once ([`efecc08`](https://github.com/aya-rs/aya/commit/efecc088b37a9438cb79f234fbfa735356816a64))
    - Improve `ParseLine as Debug` ([`d1f72a5`](https://github.com/aya-rs/aya/commit/d1f72a580c640b7ad2ae71c3acd2ff4ef2bf02c0))
    - Move test_resolve_attach_path to tests module ([`80d7952`](https://github.com/aya-rs/aya/commit/80d79526a6fe3fff0ea07b018d0eed03f6d8de71))
    - Use integer::next_multiple_of ([`4984ddc`](https://github.com/aya-rs/aya/commit/4984ddc0467a3e0fef92fd8ee6edb83a1274700a))
    - Bundle attach location+cookie via UProbeAttachPoint ([`eb99da3`](https://github.com/aya-rs/aya/commit/eb99da3cbb4bcf2b20c8d0797566dd330261aadb))
    - Release crates ([`d238b2e`](https://github.com/aya-rs/aya/commit/d238b2ea6f1b2c1aa09a9050415b1c96329af0aa))
    - Use RAII to clean up in the error path ([`46221ad`](https://github.com/aya-rs/aya/commit/46221ad11dfb44fc0cc46425e1648c6750d98a5e))
    - ProbeKind is Entry/Return ([`72810f0`](https://github.com/aya-rs/aya/commit/72810f095f1461d5d254d37e7174bb47bd15f691))
    - Use exhaustive matches ([`a4a3c16`](https://github.com/aya-rs/aya/commit/a4a3c1641f8b6006363be6c66516daf73a94aec7))
    - Refactor perf_event_open_trace_point ([`1944c4a`](https://github.com/aya-rs/aya/commit/1944c4aa008d685053bb617b728e3e4f723d7672))
    - Inline `perf_event_open_bpf` ([`d4b2dde`](https://github.com/aya-rs/aya/commit/d4b2dde78ac88b0e7e9141e0675bd8888f23c1f6))
    - Privatize PerfLink ([`7e07f85`](https://github.com/aya-rs/aya/commit/7e07f85edcbdbe2f5d1c49a872e56d1ff458991e))
    - Disambiguate `fd` names ([`27c7f1c`](https://github.com/aya-rs/aya/commit/27c7f1c84f29a6f5e775ce6761a87859a351d95d))
    - Remove superfluous type ascription ([`1791d49`](https://github.com/aya-rs/aya/commit/1791d497d3af39bd8da4eb666dece22c60e97281))
    - Support hardware breakpoints ([`ab38afe`](https://github.com/aya-rs/aya/commit/ab38afe95d16226f5a703bbb37c7842ee441c364))
    - Add `Ebpf::maps_disjoint_mut` ([`d8f5497`](https://github.com/aya-rs/aya/commit/d8f5497884a23bd63f9264dbe3f80081b76f360d))
    - Add clippy coverage for doctests ([`112ab47`](https://github.com/aya-rs/aya/commit/112ab47fcdf8ba4765e6f6416cbb7000c96292f8))
    - Push down type safety ([`18c7f7c`](https://github.com/aya-rs/aya/commit/18c7f7ccd6d462516d94b8720d18f8b7b5d98361))
    - Simplify PerfEventScope ([`7e405c2`](https://github.com/aya-rs/aya/commit/7e405c216e0d806f96c76f2554d069722f97bec3))
    - Tolerate proc map trailing newline ([`4fbce44`](https://github.com/aya-rs/aya/commit/4fbce44b6a49dd189a7a3520c66db45baf3832ea))
    - Restore must_exist argument to set_global ([`3a3c451`](https://github.com/aya-rs/aya/commit/3a3c45100942c903c21e69595eff9e4289910835))
    - Add some type ascription ([`d73c65c`](https://github.com/aya-rs/aya/commit/d73c65caae5b494630a47119bcc571971f227c5a))
    - Enable clippy::as_underscore ([`17c7c79`](https://github.com/aya-rs/aya/commit/17c7c7951cb45a5903134b21658df7e989e672ed))
    - Rename `set_` methods on `EbpfLoader` ([`03e8487`](https://github.com/aya-rs/aya/commit/03e84871773e09badf08bdef8e83b4f1256850a4))
    - Fix producer position initialization ([`1717164`](https://github.com/aya-rs/aya/commit/17171647f7e447698f0d4733a3dbb144ded53466))
    - Allow specifying a pin path for a named map ([`5802dc7`](https://github.com/aya-rs/aya/commit/5802dc7a23ac878105b55710df6c75cb5e030c3a))
    - Rename map_pin_path to default_map_pin_path ([`1c924bb`](https://github.com/aya-rs/aya/commit/1c924bb421dd731a7557ae4140f3bed7982894d2))
    - Defer cleanup to ensure unpin ([`0144c0e`](https://github.com/aya-rs/aya/commit/0144c0eb22d08b29ab6f9f5e97e1ea1d9866fd41))
    - Skip `cpumap_chain` when attachment fails ([`907920a`](https://github.com/aya-rs/aya/commit/907920a6293af62f2db6accce5a52649731ec2d9))
    - Skip `lsm_cgroup` when loading fails ([`54bd3ac`](https://github.com/aya-rs/aya/commit/54bd3ac202f4825bbb43719f3d9c350ab3e1513e))
    - Make ProgramInfo a proper enum ([`2e5f5ef`](https://github.com/aya-rs/aya/commit/2e5f5efbf13c71dc1462d1221e77055c7c3e857a))
    - Patch up 0-size datasec ([`7224efc`](https://github.com/aya-rs/aya/commit/7224efcad8726439e9ac9ccdc28e19116bf00606))
    - Promote BTF loading failure to error on BTF relocs ([`3ade19b`](https://github.com/aya-rs/aya/commit/3ade19b869dd3aa746d17e52bb3c7b683859e413))
    - Replace kernel version check with fallback ([`4c974d3`](https://github.com/aya-rs/aya/commit/4c974d33a3b5728b49c82183666153aa20e14b30))
    - Raise RLIMIT_MEMLOCK on kernel version < 5.11.0 ([`984a050`](https://github.com/aya-rs/aya/commit/984a0501c62251f4813a6758ddda69b5a9cb2325))
    - Enforce valid perf_event type & config combos ([`3d7fbaa`](https://github.com/aya-rs/aya/commit/3d7fbaad28fc8ad49f0a5afb08c686011ed25c5c))
    - Remove useless impl ([`c2fb7fe`](https://github.com/aya-rs/aya/commit/c2fb7fed6c4cc2b75a0188cddd8480789e99e0d5))
    - Improve error output ([`f76fdf9`](https://github.com/aya-rs/aya/commit/f76fdf9da51852f5e13011b2d3ba6f9204943de7))
    - Add missing impl_try_into_fdlink ([`82aec26`](https://github.com/aya-rs/aya/commit/82aec2696394f953c886f146f02673753a94cb0d))
    - Remove unused error variant ([`6fc06b9`](https://github.com/aya-rs/aya/commit/6fc06b9fcf073447438b41a066497946293825d5))
    - Cgroup attachment type support ([`fc5387c`](https://github.com/aya-rs/aya/commit/fc5387c80626957017ceeb988322bc288f438059))
    - Properly check for LSM support ([`8e75214`](https://github.com/aya-rs/aya/commit/8e752148155b49e3732a6563ee7ce1f8ecbf6307))
    - Add BPF_MAP_TYPE_SK_STORAGE ([`de42b80`](https://github.com/aya-rs/aya/commit/de42b80c74883f512542875e7cfa96b8634a8991))
    - Use shared helpers ([`6babf17`](https://github.com/aya-rs/aya/commit/6babf1796988af742711cdcdae691e4dbdd1641e))
    - Downcase log strings ([`75edc3d`](https://github.com/aya-rs/aya/commit/75edc3d2948bea7b63edc60365e4cc10e414921b))
    - Add newline between doc and imports ([`742f700`](https://github.com/aya-rs/aya/commit/742f700dcc43fe9ad5ccdd23d1b6e55673807c06))
    - Lint all crates; enable strict pointer lints ([`5f5305c`](https://github.com/aya-rs/aya/commit/5f5305c2a8ca0a739219093599dd57182d440ac1))
    - Deny clippy::unnecessary_cast ([`d1bb7bc`](https://github.com/aya-rs/aya/commit/d1bb7bcc38a45a3d2e4bcfd6959075e0a035bbca))
    - Deny clippy::fn_to_numeric_cast{,_with_truncation} ([`be4d74f`](https://github.com/aya-rs/aya/commit/be4d74fd06b0b58313daba2ffa845b0d53ec9e11))
    - Deny clippy::char_lit_as_u8 ([`fa03dbd`](https://github.com/aya-rs/aya/commit/fa03dbdb46493255bf9cc0aff33e5b79520f14e8))
    - Deny clippy::cast_precision_loss ([`a7206b9`](https://github.com/aya-rs/aya/commit/a7206b9098c33b8f81255df1d19822ebb0e67a9b))
    - Deny clippy::cast_lossless ([`72104c4`](https://github.com/aya-rs/aya/commit/72104c4076b8b7b63155b72ef7053d42cd36f1e2))
    - Add Map::from_map_data() for pinned map access ([`263e864`](https://github.com/aya-rs/aya/commit/263e864cd9e09848a9861a967763cf1069ae01c8))
    - Remove superfluous commas ([`a3aa387`](https://github.com/aya-rs/aya/commit/a3aa387a2e8035660425cefb4f6171d5fdb7537e))
    - Generate docs in macro ([`0d11937`](https://github.com/aya-rs/aya/commit/0d1193720bc0e5915eff32b5d4edd21178a98991))
    - Fix rustdoc link in macro ([`8ee12d3`](https://github.com/aya-rs/aya/commit/8ee12d337fbc1662350815dbde620f2f1b23f962))
    - Remove `AsyncPerfEventArray{,Buffer}` ([`35332f2`](https://github.com/aya-rs/aya/commit/35332f2288b0bbb8981233ae464715ea9217b081))
    - `construct_debuglink_path()` should be infallible ([`ab182be`](https://github.com/aya-rs/aya/commit/ab182be622acb245db0adef58591978208bcdb2c))
    - `impl AsFd for RingBuf` ([`3f02127`](https://github.com/aya-rs/aya/commit/3f02127b6b16f618aa2ccb444fcd1402c887ffaf))
    - Implement TryFrom<[Program Type]> for FdLink for various program types ([`4b5ba53`](https://github.com/aya-rs/aya/commit/4b5ba53a36b0c920969bbb9016330cd195e457dc))
    - Short-circuit info field if non-zero ([`7a0dabc`](https://github.com/aya-rs/aya/commit/7a0dabc295a0d856f6c3611331c9434b83f63ae8))
    - Cache feat probed info fields ([`23bc5b5`](https://github.com/aya-rs/aya/commit/23bc5b5836c3b8383f2f8a78bd3902e193a7a176))
    - Add feature probing for map type ([`bd49286`](https://github.com/aya-rs/aya/commit/bd492860f585ad8b9612ef9c8addde2fb8d5e814))
    - Add feature probing program type ([`ab77dec`](https://github.com/aya-rs/aya/commit/ab77decd9a708147e679a12ba6be3774f8946dd8))
    - Merge pull request #1262 from dave-tucker/stabilize-links ([`f74a157`](https://github.com/aya-rs/aya/commit/f74a1579074016168e4e64a32e902e8b50a75b85))
    - Make LinkInfo and loaded_links public ([`7dba5a4`](https://github.com/aya-rs/aya/commit/7dba5a41ade97a3744c4cb71a22d7c81699a69e3))
    - Uprobe: use PathBuf for ResolveSymbolError::DebuglinkAccessError ([`33c9f2b`](https://github.com/aya-rs/aya/commit/33c9f2b2b2cf5587139e36c0e05de13e72cf77fa))
    - Uprobe attach: use mmap instead of reading whole binaries to memory ([`90d5604`](https://github.com/aya-rs/aya/commit/90d56048777ff571293a99450201562532fcaa7f))
    - Clean up resolve_symbol a bit ([`647100f`](https://github.com/aya-rs/aya/commit/647100faa7f4dff819642183c94b5a05389eb2af))
    - Move Mmap struct to aya::util ([`3aded0e`](https://github.com/aya-rs/aya/commit/3aded0e0a5c644569b0a268ea31c6c0edddea3b2))
    - Appease `clippy::uninlined-format-args` ([`583709f`](https://github.com/aya-rs/aya/commit/583709f6a09c432b4e06ab9353bb4e397d58c451))
    - Merge pull request #1240 from dave-tucker/use-gen-bpf-add ([`4c5fbef`](https://github.com/aya-rs/aya/commit/4c5fbef8691ce36c547fdf07b7ef8aecf9062c79))
    - Use BPF_ADD from bindings ([`23a5e06`](https://github.com/aya-rs/aya/commit/23a5e06c75dd418f9e0956db18cbed3b80670440))
    - Merge pull request #1209 from dave-tucker/from_prog_info ([`1db534d`](https://github.com/aya-rs/aya/commit/1db534defafa3d9529c38dcb165435273c6a827d))
    - Merge pull request #1225 from dave-tucker/fix-clippy ([`d9ef2df`](https://github.com/aya-rs/aya/commit/d9ef2df2f0cfb402f6781c4684a752435cd309e8))
    - Fix clippy unused cfg_attr ([`e8e268b`](https://github.com/aya-rs/aya/commit/e8e268ba768e6fc34567aedb5206ff20a958f04e))
    - Allow conversions to Program from ProgramInfo ([`2b0dcfb`](https://github.com/aya-rs/aya/commit/2b0dcfbd0938252f8ee8752e26abe7581561f9af))
    - Merge pull request #1224 from dave-tucker/unused_trait_names ([`9eecbe9`](https://github.com/aya-rs/aya/commit/9eecbe9d0e9dc1fdbbc87d41512d4202e26d4687))
    - Add support for Flow Dissector programs ([`77b1c61`](https://github.com/aya-rs/aya/commit/77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f))
    - Set clippy unused_trait_names = warn ([`f6c5cb2`](https://github.com/aya-rs/aya/commit/f6c5cb2ad2b09760ae5434785ed5d4d195d3a765))
    - Remove unhelpful comment ([`3edc36a`](https://github.com/aya-rs/aya/commit/3edc36af9d2a6a90a57d449e66267ca081aa6a86))
    - Reorder-keys ([`49a828e`](https://github.com/aya-rs/aya/commit/49a828ec5655f6ecd0c38083c6c0dca217bad777))
    - Ensure that truncated map names are NULL terminated ([`f48b5a4`](https://github.com/aya-rs/aya/commit/f48b5a4a84a858dd3a24101a83a3b03c314f1c5c))
    - Introduce workspace lints, warn on unused crates ([`a43e40a`](https://github.com/aya-rs/aya/commit/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8))
    - Allow program names to be static strings ([`22c8f78`](https://github.com/aya-rs/aya/commit/22c8f783e7d5dd2ddc8d973885e1895a6e842440))
    - Add `XskMap::unset` ([`73a34e1`](https://github.com/aya-rs/aya/commit/73a34e1571a606124c7e89ecf71ff001508643dc))
    - Parse complete entries from /proc/$pid/maps ([`ea76e0f`](https://github.com/aya-rs/aya/commit/ea76e0f62dbdff618789dfc9a9d8604a89f61f13))
    - Destructure ([`de0b7ce`](https://github.com/aya-rs/aya/commit/de0b7cee8d2de005bf09c26f4d549036607f6f51))
    - Add punctuation ([`7084df6`](https://github.com/aya-rs/aya/commit/7084df68aa738f720c94a593ec72935f5a2e356e))
    - Avoid allocations when parsing /proc/{pid}/maps ([`50ae0ee`](https://github.com/aya-rs/aya/commit/50ae0ee099385d9b8a743ea26529e0dd10dda18e))
    - Revert "ci: remove cross toolchain" ([`e16f048`](https://github.com/aya-rs/aya/commit/e16f0482f8aafabd65836570ff55293a0681b145))
    - Bump edition to 2024 ([`f0a9f19`](https://github.com/aya-rs/aya/commit/f0a9f19ddc7f02143a02dcc2bf6be88fa2d84063))
    - Reduce the scope of expected warnings ([`ea5f7e3`](https://github.com/aya-rs/aya/commit/ea5f7e3015477717fc4a96fed2e5e7e496d2dd66))
    - Use #[expect(...)] rather than #[allow(...)] ([`4101a5a`](https://github.com/aya-rs/aya/commit/4101a5a55d43cd9ead56497820c4d43018f74cbb))
    - Remove panics on indeterminate kernel version ([`27d69c3`](https://github.com/aya-rs/aya/commit/27d69c35f030dda687664af8dc2d2fd52d238c6b))
    - Remove some copies ([`9eefb48`](https://github.com/aya-rs/aya/commit/9eefb48a0ad90831c09c7bd941d035b34e1f1771))
    - Add TODO to remove once_cell ([`89aa638`](https://github.com/aya-rs/aya/commit/89aa638e05795be0ab86711d6e2ade2a8dbafcae))
    - Encode perf_event ioctl contract ([`de1e80c`](https://github.com/aya-rs/aya/commit/de1e80c1d1bab7fd73acc97e5adb0985712c35c7))
    - Remove redundant TEST_SYSCALL use ([`eee7975`](https://github.com/aya-rs/aya/commit/eee7975ce42520513acda16977b21e19a1cd159d))
    - Encode perf_event_open(2) contract ([`055e36e`](https://github.com/aya-rs/aya/commit/055e36e8d92c79c1a9cf61f1a08d2d9be4e74d14))
    - Avoid `_` ([`bdd8ae2`](https://github.com/aya-rs/aya/commit/bdd8ae2d0b443513c73143da968d400df9b05464))
    - Encode bpf(2) contract ([`f6df60f`](https://github.com/aya-rs/aya/commit/f6df60fa7072dfd7cfb09d0bc3bb1dad0f965940))
    - Avoid Result::is_{ok,err} ([`2d78260`](https://github.com/aya-rs/aya/commit/2d782606fe984cb2ffebe7b98807a58494441a4c))
    - Avoid retagging in tests ([`dab1aa4`](https://github.com/aya-rs/aya/commit/dab1aa4e291e4301eca0bd6532449dc7079ff10a))
    - Attempt to preserve provenance ([`f51ab80`](https://github.com/aya-rs/aya/commit/f51ab800758689a67c312742ffdf9116e1e178c0))
    - Use MMap from ring_buf ([`8887014`](https://github.com/aya-rs/aya/commit/888701425bbfc48365edd6f03d9872d5c86a3e18))
    - Avoiding casting pointers to usize ([`ff82c24`](https://github.com/aya-rs/aya/commit/ff82c244f77f46da9245b42ede56c0500cd6b56f))
    - Remove some stale comments ([`e17feca`](https://github.com/aya-rs/aya/commit/e17feca2d6d45365fc1d717f0735ee4dd9664ec3))
    - Enable test under miri ([`935ba20`](https://github.com/aya-rs/aya/commit/935ba20224e4e777087151e521b1354f2a9245cd))
    - Preserve pointer provenance ([`9a47495`](https://github.com/aya-rs/aya/commit/9a47495227a03400fa2549b07fe8af131f21e759))
    - Appease clippy ([`122c49f`](https://github.com/aya-rs/aya/commit/122c49fca4ea1cdf89bbffbb48a440dfd3744937))
    - Fix PerCpuHashMap NotFound ([`9e1bcd0`](https://github.com/aya-rs/aya/commit/9e1bcd0ab87f69bcd323eef680957a534b655fac))
    - Remove outdated workaround ([`9198335`](https://github.com/aya-rs/aya/commit/919833510095cfc49d1b9874429f403167227fbd))
    - Avoid handwritten assembly ([`942ea51`](https://github.com/aya-rs/aya/commit/942ea51906fea4e3152e1bd3ef5832bc0df5b205))
    - Remove duplication ([`8ea11ef`](https://github.com/aya-rs/aya/commit/8ea11ef9e84832de6a1f12468e5d93d900ff31f3))
    - Avoid raw slice construction ([`b010b0f`](https://github.com/aya-rs/aya/commit/b010b0f028409272bf65238834ed625693c0cb09))
    - Remove aya_obj -> obj alias ([`665d4f2`](https://github.com/aya-rs/aya/commit/665d4f20bb53de0aa10545bb897ab73f0661a337))
    - Merge pull request #690 from dave-tucker/netlink-errors ([`921e457`](https://github.com/aya-rs/aya/commit/921e45747bd96840b849637468b723ce25e15345))
    - Return error messages from netlink ([`39cf6c1`](https://github.com/aya-rs/aya/commit/39cf6c12f27f02c945e70efb24b89c1bc372aac0))
    - Appease clippy ([`0429ed2`](https://github.com/aya-rs/aya/commit/0429ed2fa299636428b65573456cffe0aac2beca))
    - Use Set (instead of Map) to hold links ([`356cf45`](https://github.com/aya-rs/aya/commit/356cf45914408b1372d33f27a20ebd3ef75759ca))
    - Appease clippy ([`69144a9`](https://github.com/aya-rs/aya/commit/69144a977ef33613610f0f7b9a94e432da3a2d59))
    - Merge pull request #1133 from ajwerner/uprobe-cookie ([`114e7a6`](https://github.com/aya-rs/aya/commit/114e7a69069e610f5bdd840dd2f0d4d5de5b0694))
    - :programs::uprobe: add support for cookies ([`628b7fb`](https://github.com/aya-rs/aya/commit/628b7fb0221321aa0cc649cd738c449a7dbb0108))
    - Avoid useless conversions ([`78ee9a4`](https://github.com/aya-rs/aya/commit/78ee9a463429a1eda706f8974f965892ad86a6dd))
    - Clean up C type imports ([`4257643`](https://github.com/aya-rs/aya/commit/4257643354263d69ed02b1e9385675560927da79))
    - Narrow clippy allowances ([`41706d7`](https://github.com/aya-rs/aya/commit/41706d74e44f2c3589c28a7149beb4db185594f2))
    - Fix cippy errors ([`4f0559f`](https://github.com/aya-rs/aya/commit/4f0559f2afeca1dfae120bacf1742d58268bca37))
    - Define `{detach,take_link}` in macro when possible ([`119049f`](https://github.com/aya-rs/aya/commit/119049f2a21045b4f990523ccc95265ef4233d41))
    - Improve the description of `take_link` methods ([`85c73af`](https://github.com/aya-rs/aya/commit/85c73af1feb8d0b227ca2e7b61b8542c4eb8b918))
    - Add iterator program type ([`bf2164c`](https://github.com/aya-rs/aya/commit/bf2164c92f5280e8b9c7178b9cbf338931ce778d))
    - Cargo fmt ([`a77db17`](https://github.com/aya-rs/aya/commit/a77db17ec8dac1ac75c0d0175a1e25749acb44b3))
    - Avoid warning with `allow_unsupported_maps` ([`a167550`](https://github.com/aya-rs/aya/commit/a16755089bb642ded73a592ac25c6e21771b5792))
</details>

## v0.13.2 (2025-11-17)

<csr-id-35332f2288b0bbb8981233ae464715ea9217b081/>
<csr-id-1c924bb421dd731a7557ae4140f3bed7982894d2/>
<csr-id-03e84871773e09badf08bdef8e83b4f1256850a4/>
<csr-id-f6df60fa7072dfd7cfb09d0bc3bb1dad0f965940/>
<csr-id-055e36e8d92c79c1a9cf61f1a08d2d9be4e74d14/>
<csr-id-de1e80c1d1bab7fd73acc97e5adb0985712c35c7/>

### Breaking Changes

 - <csr-id-35332f2288b0bbb8981233ae464715ea9217b081/> Removed `AsyncPerfEventArray{,Buffer}` so Aya no longer needs to juggle multiple async runtimes. Use `PerfEventArrayBuffer`, which still implements `As{,Raw}Fd`, when integrating with an executor.
 - <csr-id-1c924bb421dd731a7557ae4140f3bed7982894d2/> `EbpfLoader::map_pin_path` is now `EbpfLoader::default_map_pin_directory`, clarifying that the value represents a base directory.
 - <csr-id-03e84871773e09badf08bdef8e83b4f1256850a4/> The loader’s `set_*` helpers were renamed to builder-style APIs (`override_global`/`map_max_entries`). Deprecated shims remain for one release to ease migration.

### New Features

 - <csr-id-bf2164c92f5280e8b9c7178b9cbf338931ce778d/> , <csr-id-119049f2a21045b4f990523ccc95265ef4233d41/> Added the iterator program type and auto-generated `take_link`/`detach` helpers so iterator programs can be loaded and detached like any other attachment.
 - <csr-id-77b1c6194c8f9bb69ffc6a60c3b8189b73e00e8f/> , <csr-id-82aec2696394f953c886f146f02673753a94cb0d/> Added Flow Dissector program support, including ordered link attachment and full `FdLink` conversions for the new program type.
 - <csr-id-263e864cd9e09848a9861a967763cf1069ae01c8/> , <csr-id-73a34e1571a606124c7e89ecf71ff001508643dc/>, <csr-id-5802dc7a23ac878105b55710df6c75cb5e030c3a/> Made pinned maps easier to manage with `Map::from_map_data()`, `XskMap::unset()`, and the ability to pick a custom map pin directory.
 - <csr-id-7dba5a41ade97a3744c4cb71a22d7c81699a69e3/> , <csr-id-22c8f783e7d5dd2ddc8d973885e1895a6e842440/>, <csr-id-3f02127b6b16f618aa2ccb444fcd1402c887ffaf/> Exposed additional metadata and handles: `LinkInfo`/`loaded_links` are now public, program names can be `&'static str`, and ring buffers implement `AsFd`.
 - <csr-id-23bc5b5836c3b8383f2f8a78bd3902e193a7a176/> , <csr-id-bd492860f585ad8b9612ef9c8addde2fb8d5e814/>, <csr-id-de42b80c74883f512542875e7cfa96b8634a8991/> Expanded and cached feature probing, reducing redundant syscalls and adding built-in support for `BPF_MAP_TYPE_SK_STORAGE`.
 - <csr-id-d8f5497884a23bd63f9264dbe3f80081b76f360d/> , <csr-id-ab38afe95d16226f5a703bbb37c7842ee441c364/> Added `Ebpf::maps_disjoint_mut()` plus perf-event hardware breakpoint support to give loaders safer and more capable instrumentation hooks.

### Bug Fixes

 - <csr-id-39cf6c12f27f02c945e70efb24b89c1bc372aac0/> Netlink helpers now surface the kernel’s error message instead of returning opaque failures.
 - <csr-id-9e1bcd0ab87f69bcd323eef680957a534b655fac/> Fixed `PerCpuHashMap::get()` returning `KeyNotFound` when CPU slots were missing; Flow Dissector links now always convert into `FdLink` thanks to <csr-id-82aec2696394f953c886f146f02673753a94cb0d/>.
 - <csr-id-17171647f7e447698f0d4733a3dbb144ded53466/> Stabilised ring-buffer producer tracking so first events are no longer dropped, and `/proc/$pid/maps` parsing now tolerates trailing newlines (<csr-id-ea76e0f62dbdff618789dfc9a9d8604a89f61f13/>, <csr-id-4fbce44b6a49dd189a7a3520c66db45baf3832ea/>).
 - <csr-id-f48b5a4a84a858dd3a24101a83a3b03c314f1c5c/> , <csr-id-ab182be622acb245db0adef58591978208bcdb2c/> Map names are forced to be NULL-terminated and `construct_debuglink_path()` no longer fails due to missing components.

### Maintenance

 - <csr-id-f6df60fa7072dfd7cfb09d0bc3bb1dad0f965940/>, <csr-id-055e36e8d92c79c1a9cf61f1a08d2d9be4e74d14/>, <csr-id-de1e80c1d1bab7fd73acc97e5adb0985712c35c7/> Documented the exact bpf/perf syscall contracts inside Aya and automatically raise `RLIMIT_MEMLOCK` on kernels <5.11 to smooth out program loading.
 - Continued to invest in documentation, resolver clean-ups, and lint/clippy hygiene across the crate so day-to-day maintenance stays manageable.

## 0.13.1 (2024-11-01)

<csr-id-e575712c596d03b93f75d160e3d95241eb895d39/>
<csr-id-70ac91dc1e6f209a701cd868db215763d65efa73/>
<csr-id-481b73b6d8dd9a796d891bba137400c2a43a0afe/>
<csr-id-c44f8b0f5bddd820a4a98cff293126c0146b827a/>
<csr-id-02d1db5fc043fb7af90c14d13de6419ec5b9bcb5/>
<csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/>
<csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/>
<csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/>
<csr-id-cb8e47880082ccfcd75b02209b686e15426e9b6a/>
<csr-id-cd1db86fd490b3c0f03229bd8999a2e67ccecfc4/>
<csr-id-a25f501ecebaceaacdd1212fac34f528b51ad0fd/>
<csr-id-fa6af6a20439cccd8ab961f83dce545fb5884dd4/>
<csr-id-d413e2f285643cbeb665fd3c517e2c9d93d45825/>
<csr-id-462514ed4c4c06e9618d029a57708c7fa14ab748/>
<csr-id-e6e1bfeb58ac392637061640365b057182ee1b39/>
<csr-id-b06ff402780b80862933791831c578e4c339fc96/>
<csr-id-a4e68ebdbf0e0b591509f36316d12d9689d23f89/>
<csr-id-e38eac6352ccb5c2b44d621161a27898744ea397/>
<csr-id-eef7346fb2231f8741410381198015cceeebfac9/>

### Chore

 - <csr-id-e575712c596d03b93f75d160e3d95241eb895d39/> Add comments in `*_wrong_map` tests
 - <csr-id-70ac91dc1e6f209a701cd868db215763d65efa73/> Rename bpf -> ebpf
 - <csr-id-481b73b6d8dd9a796d891bba137400c2a43a0afe/> Fix unused_qualifications lints
   This was failing the docs build.

### Documentation

 - <csr-id-f1773d5af43f5f29b100572e65a60d58f2ce7fac/> fix typo
 - <csr-id-57a69fe9d28e858562a429bacd9a0a7700b96726/> Use `Ebpf` instead of `Bpf`

### New Features

 - <csr-id-5478cac008471bdb80aa30733e4456b70ec1a5bd/> Implement TCX
   This commit adds the initial support for TCX
   bpf links. This is a new, multi-program, attachment
   type allows for the caller to specify where
   they would like to be attached relative to other
   programs at the attachment point using the LinkOrder
   type.
 - <csr-id-110a76cb9a1b2ab5c5ad3b6c0828a4ae670e67a0/> Provide a deprecated `BpfError` alias
 - <csr-id-8c79b71bd5699a686f33360520aa95c1a2895fa5/> Rename Bpf to Ebpf
   And BpfLoader to EbpfLoader.
   This also adds type aliases to preserve the use of the old names, making
   updating to a new Aya release less of a burden. These aliases are marked
   as deprecated since we'll likely remove them in a later release.

### Bug Fixes

 - <csr-id-ca0c32d1076af81349a52235a4b6fb3937a697b3/> Fill bss maps with zeros
   The loader should fill bss maps with zeros according to the size of the
   ELF section.
   Failure to do so yields weird verifier messages as follows:
   
   ```
   cannot access ptr member ops with moff 0 in struct bpf_map with off 0 size 4
   ```
   
   Reference to this in the cilium/ebpf code is here [1].
   I could not find a reference in libbpf.
 - <csr-id-3d57d358e40591acf23dfde740697fbfff026410/> Fix PerfEventArray resize logic
   There was a logic bug in the previously merged patch where we
   set the correctly calculated max_entries size with the original.
   
   To fix this and prevent regressions a unit test was added.
   This highlighted that the original map definition needs to be
   mutated in order for the max_entries change to be properly applied.
   
   As such, this resize logic moved out of aya::sys into aya::maps
 - <csr-id-25d986a26d9c88cd499a8b795054d583f01476b2/> Set PerfEventArray max_entries to nCPUs
   Both libbpf and cilium/ebpf have will set the max_entries of a
   BPF_MAP_TYPE_PERF_EVENT_ARRAY to the number of online CPUs if
   it was omitted at map definition time. This adds that same
   logic to Aya.
 - <csr-id-38d8e32baa5a4538de9daa6fae634aea6372573c/> fix panic when creating map on custom ubuntu kernel
 - <csr-id-5e13283f59b0c3b4cb47de1e31d8d0960e80b4cc/> fix rustdocs-args ordering in taplo to -D warnings
   This fixes the current rustdoc build error by correcting the ordering of
   `rustdoc-args` to `-D warnings`. Additionally, this also removes the
   `recorder_arrays` field (defaults to false) so that the order is not
   modified, which is what caused the error in the first place.

### Other

 - <csr-id-c44f8b0f5bddd820a4a98cff293126c0146b827a/> use FdLink in SockOps programs
 - <csr-id-02d1db5fc043fb7af90c14d13de6419ec5b9bcb5/> remove unwrap and NonZero* in info
   Addresses the feedback from #1007:
   - remove panic from `unwrap` and `expect`
   - Option<NonZero*> => Option<int> with `0` mapping to `None`
 - <csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/> revamp MapInfo be more friendly with older kernels
   Adds detection for whether a field is available in `MapInfo`:
   - For `map_type()`, we treturn new enum `MapType` instead of the integer
     representation.
   - For fields that can't be zero, we return `Option<NonZero*>` type.
   - For `name_as_str()`, it now uses the feature probe `bpf_name()` to
     detect if field is available.
     Although the feature probe checks for program name, it can also be
     used for map name since they were both introduced in the same commit.
 - <csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/> revamp ProgramInfo be more friendly with older kernels
   Purpose of this commit is to add detections for whether a field is
   available in `ProgramInfo`.
   - For `program_type()`, we return the new enum `ProgramType` instead of
     the integer representation.
   - For fields that we know cannot be zero, we return `Option<NonZero*>`
     type.
   - For `name_as_str()`, it now also uses the feature probe `bpf_name()`
     to detect if field is available or not.
   - Two additional feature probes are added for the fields:
     - `prog_info_map_ids()` probe -> `map_ids()` field
     - `prog_info_gpl_compatible()` probe -> `gpl_compatible()` field
   
   With the `prog_info_map_ids()` probe, the previous implementation that
   I had for `bpf_prog_get_info_by_fd()` is shortened to use the probe
   instead of having to make 2 potential syscalls.
   
   The `test_loaded_at()` test is also moved into info tests since it is
   better related to the info tests.
 - <csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/> add conversion u32 to enum type for prog, link, & attach type
   Add conversion from u32 to program type, link type, and attach type.
   Additionally, remove duplicate match statement for u32 conversion to
   `BPF_MAP_TYPE_BLOOM_FILTER` & `BPF_MAP_TYPE_CGRP_STORAGE`.
   
   New error `InvalidTypeBinding<T>` is created to represent when a
   parsed/received value binding to a type is invalid.
   This is used in the new conversions added here, and also replaces
   `InvalidMapTypeError` in `TryFrom` for `bpf_map_type`.
 - <csr-id-cb8e47880082ccfcd75b02209b686e15426e9b6a/> improve integration tests for info API
   Improves the existing integraiton tests for `loaded_programs()` and
   `loaded_maps()` in consideration for older kernels:
     - Opt for `SocketFilter` program in tests since XDP requires v4.8 and
       fragments requires v5.18.
     - For assertion tests, first perform the assertion, if the assertion
       fails, then it checks the host kernel version to see if it is above
       the minimum version requirement. If not, then continue with test,
       otherwise fail.
       For assertions that are skipped, they're logged in stderr which can
       be observed with `-- --nocapture`.
   
   This also fixes the `bpf_prog_get_info_by_fd()` call for kernels below
   v4.15. If calling syscall  on kernels below v4.15, it can produce an
   `E2BIG` error  because `check_uarg_tail_zero()` expects the entire
   struct to all-zero bytes (which is caused from the map info).
   
   Instead, we first attempt the syscall with the map info filled, if it
   returns `E2BIG`, then perform syscall again with empty closure.
   
   Also adds doc for which version a kernel feature was introduced for
   better  awareness.
   
   The tests have been verified kernel versions:
     - 4.13.0
     - 4.15.0
     - 6.1.0
 - <csr-id-cd1db86fd490b3c0f03229bd8999a2e67ccecfc4/> adjust bpf programs for big endian
   In aya/src/sys/bpf.rs, there are several simple bpf programs written as
   byte arrays. These need to be adjusted to account for big endian.
 - <csr-id-a25f501ecebaceaacdd1212fac34f528b51ad0fd/> expose run_time_ns and run_cnt fields in ProgramInfo
   Added functions to expose `run_time_ns` & `run_cnt` statistics from
   ProgramInfo/bpf_prog_info.
 - <csr-id-fa6af6a20439cccd8ab961f83dce545fb5884dd4/> add BPF_ENABLE_STATS syscall function
   Add bpf syscall function for BPF_ENABLE_STATS to enable stats tracking
   for benchmarking purposes.
   
   Additionally, move `#[cfg(test)]` annotation around the `Drop` trait
   instead. Having separate functions causes some complications when
   needing ownership/moving of the inner value `OwnedFd` when `Drop` is
   manually implemented.
 - <csr-id-d413e2f285643cbeb665fd3c517e2c9d93d45825/> :programs::uprobe: fix bad variable name
   The variable fn_name was very much *not* the fn_name, but rather the
   object file path.
 - <csr-id-462514ed4c4c06e9618d029a57708c7fa14ab748/> adjust symbol lookup tests for object crate alignment requirements
   The object::File::parse API requires parameter to be aligned with 8 bytes.
   Adjusted the Vec in the tests with miri to meet this requirement.
 - <csr-id-e6e1bfeb58ac392637061640365b057182ee1b39/> add symbol lookup in associated debug files
   This change enhances the logic for symbol lookup in uprobe or uretprobe.
   If the symbol is not found in the original binary, the search continues
   in the debug file associated through the debuglink section. Before
   searching the symbol table, it compares the build IDs of the two files.
   The symbol lookup will only be terminated if both build IDs exist and do
   not match. This modification does not affect the existing symbol lookup
   logic.
 - <csr-id-b06ff402780b80862933791831c578e4c339fc96/> Generate new bindings
 - <csr-id-a4e68ebdbf0e0b591509f36316d12d9689d23f89/> include license in crate workspace
   This PR includes the licenses files in the crate workspace subdirectory.
   Without this, they won't be showing on crates.io and would be giving out
   errors on tooling such as rust2rpm.
 - <csr-id-e38eac6352ccb5c2b44d621161a27898744ea397/> appease new nightly clippy lints
   ```
     error: unnecessary qualification
        --> aya/src/maps/ring_buf.rs:434:22
         |
     434 |                 ptr: ptr::NonNull::new(ptr).ok_or(
         |                      ^^^^^^^^^^^^^^^^^
         |
     note: the lint level is defined here
        --> aya/src/lib.rs:72:5
         |
     72  |     unused_qualifications,
         |     ^^^^^^^^^^^^^^^^^^^^^
     help: remove the unnecessary path segments
         |
     434 -                 ptr: ptr::NonNull::new(ptr).ok_or(
     434 +                 ptr: NonNull::new(ptr).ok_or(
         |
   
     error: unnecessary qualification
        --> aya/src/maps/mod.rs:225:21
         |
     225 |     let mut limit = std::mem::MaybeUninit::<rlimit>::uninit();
         |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         |
     help: remove the unnecessary path segments
         |
     225 -     let mut limit = std::mem::MaybeUninit::<rlimit>::uninit();
     225 +     let mut limit = mem::MaybeUninit::<rlimit>::uninit();
         |
   
     error: unnecessary qualification
        --> aya/src/programs/mod.rs:614:9
         |
     614 |         crate::obj::Program {
         |         ^^^^^^^^^^^^^^^^^^^
         |
     help: remove the unnecessary path segments
         |
     614 -         crate::obj::Program {
     614 +         obj::Program {
         |
   
     error: unnecessary qualification
        --> aya/src/util.rs:373:14
         |
     373 |     unsafe { std::slice::from_raw_parts(bpf_name.as_ptr() as
         *const _, length) }
         |              ^^^^^^^^^^^^^^^^^^^^^^^^^^
         |
     help: remove the unnecessary path segments
         |
     373 -     unsafe { std::slice::from_raw_parts(bpf_name.as_ptr() as
         *const _, length) }
     373 +     unsafe { slice::from_raw_parts(bpf_name.as_ptr() as *const _,
         length) }
         |
   
     error: unnecessary qualification
         --> aya/src/maps/mod.rs:1130:47
          |
     1130 |                     .copy_from_slice(unsafe {
          std::mem::transmute(TEST_NAME) });
          |                                               ^^^^^^^^^^^^^^^^^^^
          |
     note: the lint level is defined here
         --> aya/src/lib.rs:72:5
          |
     72   |     unused_qualifications,
          |     ^^^^^^^^^^^^^^^^^^^^^
     help: remove the unnecessary path segments
          |
     1130 -                     .copy_from_slice(unsafe {
          std::mem::transmute(TEST_NAME) });
     1130 +                     .copy_from_slice(unsafe {
          mem::transmute(TEST_NAME) });
          |
   ```

### Performance

 - <csr-id-d05110fd86f9b317d47ffb7cf5c00e588635d4cd/> cache `nr_cpus` in a thread_local

### Test

 - <csr-id-eef7346fb2231f8741410381198015cceeebfac9/> adjust test byte arrays for big endian
   Adding support for s390x (big endian architecture) and found that some
   of the unit tests have structures and files implemented as byte arrays.
   They are all coded as little endian and need a bug endian version to
   work properly.

### New Features (BREAKING)

 - <csr-id-fd48c55466a23953ce7a4912306e1acf059b498b/> Rename BpfRelocationError -> EbpfRelocationError
 - <csr-id-cf3e2ca677c81224368fb2838ebc5b10ee98419a/> Rename BpfSectionKind to EbpfSectionKind

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 70 commits contributed to the release over the course of 241 calendar days.
 - 247 days passed between releases.
 - 32 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya v0.13.1 ([`2791bad`](https://github.com/aya-rs/aya/commit/2791badd947e3abb459e5339a23a66d0a56c42d0))
    - Release aya-obj v0.2.1 ([`c6a34ca`](https://github.com/aya-rs/aya/commit/c6a34cade195d682e1eece5b71e3ab48e48f3cda))
    - Merge pull request #1073 from dave-tucker/reloc-bug ([`b2ac9fe`](https://github.com/aya-rs/aya/commit/b2ac9fe85db6c25d0b8155a75a2df96a80a19811))
    - Fill bss maps with zeros ([`ca0c32d`](https://github.com/aya-rs/aya/commit/ca0c32d1076af81349a52235a4b6fb3937a697b3))
    - Release aya-obj v0.2.0, aya v0.13.0, safety bump aya v0.13.0 ([`c169b72`](https://github.com/aya-rs/aya/commit/c169b727e6b8f8c2dda57f54b8c77f8b551025c6))
    - Implement TCX ([`5478cac`](https://github.com/aya-rs/aya/commit/5478cac008471bdb80aa30733e4456b70ec1a5bd))
    - Cache `nr_cpus` in a thread_local ([`d05110f`](https://github.com/aya-rs/aya/commit/d05110fd86f9b317d47ffb7cf5c00e588635d4cd))
    - Clarify `Arc` usage ([`afd777b`](https://github.com/aya-rs/aya/commit/afd777b705312b7bafec2a116041a2318d3aa70f))
    - Replace `Arc` with `&'static` ([`e992c28`](https://github.com/aya-rs/aya/commit/e992c280cbae7af7e484767a0b79314b14a4de84))
    - Avoid intermediate allocations in parse_cpu_ranges ([`0e86757`](https://github.com/aya-rs/aya/commit/0e867572ff8e009bbcd1a63037b4ab5b80e35549))
    - Reduce duplication in `{nr,possible}_cpus` ([`f3b2744`](https://github.com/aya-rs/aya/commit/f3b27440725a0eb2f1615c92cb0047e3b1548d66))
    - Replace `lazy_static` with `std::sync::LazyLock` ([`2b299d4`](https://github.com/aya-rs/aya/commit/2b299d4fba1ddda70c2e8af324f999cb23683559))
    - Appease clippy ([`0f16363`](https://github.com/aya-rs/aya/commit/0f163633e3d73c59f857880c967c27e9f52e8610))
    - Merge pull request #1023 from l2dy/fdlink/sockops ([`2cd3576`](https://github.com/aya-rs/aya/commit/2cd35769dce05b46a4dd07381c990c6acd4cfe0d))
    - Use FdLink in SockOps programs ([`c44f8b0`](https://github.com/aya-rs/aya/commit/c44f8b0f5bddd820a4a98cff293126c0146b827a))
    - Remove unwrap and NonZero* in info ([`02d1db5`](https://github.com/aya-rs/aya/commit/02d1db5fc043fb7af90c14d13de6419ec5b9bcb5))
    - Merge pull request #985 from reyzell/main ([`40f3032`](https://github.com/aya-rs/aya/commit/40f303205f7a800877fe3f9a4fb1893141741e13))
    - Add the option to support multiple and overrideable programs per cgroup ([`f790685`](https://github.com/aya-rs/aya/commit/f790685d759cbd97cb09ad48d87cdece28fbe579))
    - Merge pull request #1007 from tyrone-wu/aya/info-api ([`15eb935`](https://github.com/aya-rs/aya/commit/15eb935bce6d41fb67189c48ce582b074544e0ed))
    - Revamp MapInfo be more friendly with older kernels ([`fbb0930`](https://github.com/aya-rs/aya/commit/fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41))
    - Revamp ProgramInfo be more friendly with older kernels ([`88f5ac3`](https://github.com/aya-rs/aya/commit/88f5ac31142f1657b41b1ee0f217dcd9125b210a))
    - Add conversion u32 to enum type for prog, link, & attach type ([`1634fa7`](https://github.com/aya-rs/aya/commit/1634fa7188e40ed75da53517f1fdb7396c348c34))
    - Improve integration tests for info API ([`cb8e478`](https://github.com/aya-rs/aya/commit/cb8e47880082ccfcd75b02209b686e15426e9b6a))
    - Merge pull request #959 from tyrone-wu/aya/program_info_stats ([`ab000ad`](https://github.com/aya-rs/aya/commit/ab000ad7c3b0715c3cdd9798bd08fc834b114f1a))
    - Merge pull request #974 from Billy99/billy99-arch-ppc64-s390x ([`ab5e688`](https://github.com/aya-rs/aya/commit/ab5e688fd49fcfb402ad47d51cb445437fbd8cb7))
    - Adjust bpf programs for big endian ([`cd1db86`](https://github.com/aya-rs/aya/commit/cd1db86fd490b3c0f03229bd8999a2e67ccecfc4))
    - Adjust test byte arrays for big endian ([`eef7346`](https://github.com/aya-rs/aya/commit/eef7346fb2231f8741410381198015cceeebfac9))
    - Simplify doctest ([`4362020`](https://github.com/aya-rs/aya/commit/43620206918facbf003d8b878ae28c5b07955167))
    - Appease nightly clippy ([`bce3c4f`](https://github.com/aya-rs/aya/commit/bce3c4fb1d0cd6e8f9f64420c59e02a42c96b2c8))
    - Expose run_time_ns and run_cnt fields in ProgramInfo ([`a25f501`](https://github.com/aya-rs/aya/commit/a25f501ecebaceaacdd1212fac34f528b51ad0fd))
    - Add BPF_ENABLE_STATS syscall function ([`fa6af6a`](https://github.com/aya-rs/aya/commit/fa6af6a20439cccd8ab961f83dce545fb5884dd4))
    - Fix PerfEventArray resize logic ([`3d57d35`](https://github.com/aya-rs/aya/commit/3d57d358e40591acf23dfde740697fbfff026410))
    - Add comments in `*_wrong_map` tests ([`e575712`](https://github.com/aya-rs/aya/commit/e575712c596d03b93f75d160e3d95241eb895d39))
    - Set PerfEventArray max_entries to nCPUs ([`25d986a`](https://github.com/aya-rs/aya/commit/25d986a26d9c88cd499a8b795054d583f01476b2))
    - Use MockableFd everywhere ([`e12fcf4`](https://github.com/aya-rs/aya/commit/e12fcf46cb1e0856a8105ed43fda184fa4648713))
    - Merge pull request #991 from l2dy/typo-1 ([`2cd9858`](https://github.com/aya-rs/aya/commit/2cd9858ea9381232acaffcb5a08bc74e90a8863e))
    - Fix typo ([`f1773d5`](https://github.com/aya-rs/aya/commit/f1773d5af43f5f29b100572e65a60d58f2ce7fac))
    - Merge pull request #983 from ajwerner/fix-variable-name ([`d5414bf`](https://github.com/aya-rs/aya/commit/d5414bf10c80ae8cef757f0cdf06bfdd38746daa))
    - :programs::uprobe: fix bad variable name ([`d413e2f`](https://github.com/aya-rs/aya/commit/d413e2f285643cbeb665fd3c517e2c9d93d45825))
    - Fix panic when creating map on custom ubuntu kernel ([`38d8e32`](https://github.com/aya-rs/aya/commit/38d8e32baa5a4538de9daa6fae634aea6372573c))
    - Appease clippy ([`78acd74`](https://github.com/aya-rs/aya/commit/78acd74badb6aa2463f89fbdf713325dad75dc9e))
    - Don't deny unused_qualifications ([`781914f`](https://github.com/aya-rs/aya/commit/781914f058ef805bd0780ff72a2a66c63255bc07))
    - Fix rustdocs-args ordering in taplo to -D warnings ([`5e13283`](https://github.com/aya-rs/aya/commit/5e13283f59b0c3b4cb47de1e31d8d0960e80b4cc))
    - Remove deny(pointer_structural_match) ([`4e843a3`](https://github.com/aya-rs/aya/commit/4e843a35237c2de49d17621dccb4a2a35bb4030c))
    - Merge pull request #938 from swananan/enhance_urpobe_symbol_lookup ([`bde4b5f`](https://github.com/aya-rs/aya/commit/bde4b5f86b12a3e4ac2f99898edb1b564fe9dd7e))
    - Fix clippy ([`c7898c5`](https://github.com/aya-rs/aya/commit/c7898c596f2f74f29570101d0f71f35b0ab4104b))
    - Adjust symbol lookup tests for object crate alignment requirements ([`462514e`](https://github.com/aya-rs/aya/commit/462514ed4c4c06e9618d029a57708c7fa14ab748))
    - Add symbol lookup in associated debug files ([`e6e1bfe`](https://github.com/aya-rs/aya/commit/e6e1bfeb58ac392637061640365b057182ee1b39))
    - Merge pull request #928 from seanyoung/io-error ([`d0e9b95`](https://github.com/aya-rs/aya/commit/d0e9b95aa5edc6c056687caeb950e1ce44b18d66))
    - S/MiriSafeFd/MockableFd/ ([`a11b61e`](https://github.com/aya-rs/aya/commit/a11b61ebfde8713c35b6f2a760e470d3586803a7))
    - Remove miri ignores ([`cb6d3bd`](https://github.com/aya-rs/aya/commit/cb6d3bd75d162e4928fdf4daa7f515e1ad85ae85))
    - Document miri skip reasons ([`35962a4`](https://github.com/aya-rs/aya/commit/35962a4794484aa3b37dadc98a70a659fd107b75))
    - Avoid crashing under Miri ([`7a7d168`](https://github.com/aya-rs/aya/commit/7a7d16885a89af8c10a52e5aba0927784d42f551))
    - Deduplicate test helpers ([`7e1666f`](https://github.com/aya-rs/aya/commit/7e1666fb83e5c2b270cb24becb84adebbe29be1a))
    - Reduce duplication ([`58e154e`](https://github.com/aya-rs/aya/commit/58e154e1bc4846a6a2afcb8397aa599cfb7ea6fd))
    - Expose io_error in SyscallError ([`a6c45f6`](https://github.com/aya-rs/aya/commit/a6c45f61c77c4bbec4409debb8447cd606f0db5d))
    - Appease clippy ([`09442c2`](https://github.com/aya-rs/aya/commit/09442c2cbe9513365dfc1df8d4f7cf6f808a67ed))
    - Generate new bindings ([`b06ff40`](https://github.com/aya-rs/aya/commit/b06ff402780b80862933791831c578e4c339fc96))
    - Appease clippy ([`0a32dac`](https://github.com/aya-rs/aya/commit/0a32dacd2fd2f225f4a3709ac4ea2838a9937378))
    - Merge pull request #528 from dave-tucker/rename-all-the-things ([`63d8d4d`](https://github.com/aya-rs/aya/commit/63d8d4d34bdbbee149047dc0a5e9c2b191f3b32d))
    - Include license in crate workspace ([`a4e68eb`](https://github.com/aya-rs/aya/commit/a4e68ebdbf0e0b591509f36316d12d9689d23f89))
    - Use `Ebpf` instead of `Bpf` ([`57a69fe`](https://github.com/aya-rs/aya/commit/57a69fe9d28e858562a429bacd9a0a7700b96726))
    - Provide a deprecated `BpfError` alias ([`110a76c`](https://github.com/aya-rs/aya/commit/110a76cb9a1b2ab5c5ad3b6c0828a4ae670e67a0))
    - Rename Bpf to Ebpf ([`8c79b71`](https://github.com/aya-rs/aya/commit/8c79b71bd5699a686f33360520aa95c1a2895fa5))
    - Rename BpfRelocationError -> EbpfRelocationError ([`fd48c55`](https://github.com/aya-rs/aya/commit/fd48c55466a23953ce7a4912306e1acf059b498b))
    - Rename BpfSectionKind to EbpfSectionKind ([`cf3e2ca`](https://github.com/aya-rs/aya/commit/cf3e2ca677c81224368fb2838ebc5b10ee98419a))
    - Rename bpf -> ebpf ([`70ac91d`](https://github.com/aya-rs/aya/commit/70ac91dc1e6f209a701cd868db215763d65efa73))
    - Fix unused_qualifications lints ([`481b73b`](https://github.com/aya-rs/aya/commit/481b73b6d8dd9a796d891bba137400c2a43a0afe))
    - Add `CgroupDevice::query` ([`542306d`](https://github.com/aya-rs/aya/commit/542306d295e51ac1ec117ce453544f201875af3d))
    - Appease new nightly clippy lints ([`e38eac6`](https://github.com/aya-rs/aya/commit/e38eac6352ccb5c2b44d621161a27898744ea397))
</details>

## 0.13.0 (2024-10-09)

<csr-id-e575712c596d03b93f75d160e3d95241eb895d39/>
<csr-id-70ac91dc1e6f209a701cd868db215763d65efa73/>
<csr-id-481b73b6d8dd9a796d891bba137400c2a43a0afe/>
<csr-id-c44f8b0f5bddd820a4a98cff293126c0146b827a/>
<csr-id-02d1db5fc043fb7af90c14d13de6419ec5b9bcb5/>
<csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/>
<csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/>
<csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/>
<csr-id-cb8e47880082ccfcd75b02209b686e15426e9b6a/>
<csr-id-cd1db86fd490b3c0f03229bd8999a2e67ccecfc4/>
<csr-id-a25f501ecebaceaacdd1212fac34f528b51ad0fd/>
<csr-id-fa6af6a20439cccd8ab961f83dce545fb5884dd4/>
<csr-id-d413e2f285643cbeb665fd3c517e2c9d93d45825/>
<csr-id-462514ed4c4c06e9618d029a57708c7fa14ab748/>
<csr-id-e6e1bfeb58ac392637061640365b057182ee1b39/>
<csr-id-b06ff402780b80862933791831c578e4c339fc96/>
<csr-id-a4e68ebdbf0e0b591509f36316d12d9689d23f89/>
<csr-id-e38eac6352ccb5c2b44d621161a27898744ea397/>
<csr-id-eef7346fb2231f8741410381198015cceeebfac9/>

### Chore

 - <csr-id-e575712c596d03b93f75d160e3d95241eb895d39/> Add comments in `*_wrong_map` tests
 - <csr-id-70ac91dc1e6f209a701cd868db215763d65efa73/> Rename bpf -> ebpf
 - <csr-id-481b73b6d8dd9a796d891bba137400c2a43a0afe/> Fix unused_qualifications lints
   This was failing the docs build.

### Documentation

 - <csr-id-f1773d5af43f5f29b100572e65a60d58f2ce7fac/> fix typo
 - <csr-id-57a69fe9d28e858562a429bacd9a0a7700b96726/> Use `Ebpf` instead of `Bpf`

### New Features

 - <csr-id-5478cac008471bdb80aa30733e4456b70ec1a5bd/> Implement TCX
   This commit adds the initial support for TCX
   bpf links. This is a new, multi-program, attachment
   type allows for the caller to specify where
   they would like to be attached relative to other
   programs at the attachment point using the LinkOrder
   type.
 - <csr-id-110a76cb9a1b2ab5c5ad3b6c0828a4ae670e67a0/> Provide a deprecated `BpfError` alias
 - <csr-id-8c79b71bd5699a686f33360520aa95c1a2895fa5/> Rename Bpf to Ebpf
   And BpfLoader to EbpfLoader.
   This also adds type aliases to preserve the use of the old names, making
   updating to a new Aya release less of a burden. These aliases are marked
   as deprecated since we'll likely remove them in a later release.

### Bug Fixes

 - <csr-id-3d57d358e40591acf23dfde740697fbfff026410/> Fix PerfEventArray resize logic
   There was a logic bug in the previously merged patch where we
   set the correctly calculated max_entries size with the original.
   
   To fix this and prevent regressions a unit test was added.
   This highlighted that the original map definition needs to be
   mutated in order for the max_entries change to be properly applied.
   
   As such, this resize logic moved out of aya::sys into aya::maps
 - <csr-id-25d986a26d9c88cd499a8b795054d583f01476b2/> Set PerfEventArray max_entries to nCPUs
   Both libbpf and cilium/ebpf have will set the max_entries of a
   BPF_MAP_TYPE_PERF_EVENT_ARRAY to the number of online CPUs if
   it was omitted at map definition time. This adds that same
   logic to Aya.
 - <csr-id-38d8e32baa5a4538de9daa6fae634aea6372573c/> fix panic when creating map on custom ubuntu kernel
 - <csr-id-5e13283f59b0c3b4cb47de1e31d8d0960e80b4cc/> fix rustdocs-args ordering in taplo to -D warnings
   This fixes the current rustdoc build error by correcting the ordering of
   `rustdoc-args` to `-D warnings`. Additionally, this also removes the
   `recorder_arrays` field (defaults to false) so that the order is not
   modified, which is what caused the error in the first place.

### Other

 - <csr-id-c44f8b0f5bddd820a4a98cff293126c0146b827a/> use FdLink in SockOps programs
 - <csr-id-02d1db5fc043fb7af90c14d13de6419ec5b9bcb5/> remove unwrap and NonZero* in info
   Addresses the feedback from #1007:
   - remove panic from `unwrap` and `expect`
   - Option<NonZero*> => Option<int> with `0` mapping to `None`
 - <csr-id-fbb09304a2de0d8baf7ea20c9727fcd2e4fb7f41/> revamp MapInfo be more friendly with older kernels
   Adds detection for whether a field is available in `MapInfo`:
   - For `map_type()`, we treturn new enum `MapType` instead of the integer
     representation.
   - For fields that can't be zero, we return `Option<NonZero*>` type.
   - For `name_as_str()`, it now uses the feature probe `bpf_name()` to
     detect if field is available.
     Although the feature probe checks for program name, it can also be
     used for map name since they were both introduced in the same commit.
 - <csr-id-88f5ac31142f1657b41b1ee0f217dcd9125b210a/> revamp ProgramInfo be more friendly with older kernels
   Purpose of this commit is to add detections for whether a field is
   available in `ProgramInfo`.
   - For `program_type()`, we return the new enum `ProgramType` instead of
     the integer representation.
   - For fields that we know cannot be zero, we return `Option<NonZero*>`
     type.
   - For `name_as_str()`, it now also uses the feature probe `bpf_name()`
     to detect if field is available or not.
   - Two additional feature probes are added for the fields:
     - `prog_info_map_ids()` probe -> `map_ids()` field
     - `prog_info_gpl_compatible()` probe -> `gpl_compatible()` field
   
   With the `prog_info_map_ids()` probe, the previous implementation that
   I had for `bpf_prog_get_info_by_fd()` is shortened to use the probe
   instead of having to make 2 potential syscalls.
   
   The `test_loaded_at()` test is also moved into info tests since it is
   better related to the info tests.
 - <csr-id-1634fa7188e40ed75da53517f1fdb7396c348c34/> add conversion u32 to enum type for prog, link, & attach type
   Add conversion from u32 to program type, link type, and attach type.
   Additionally, remove duplicate match statement for u32 conversion to
   `BPF_MAP_TYPE_BLOOM_FILTER` & `BPF_MAP_TYPE_CGRP_STORAGE`.
   
   New error `InvalidTypeBinding<T>` is created to represent when a
   parsed/received value binding to a type is invalid.
   This is used in the new conversions added here, and also replaces
   `InvalidMapTypeError` in `TryFrom` for `bpf_map_type`.
 - <csr-id-cb8e47880082ccfcd75b02209b686e15426e9b6a/> improve integration tests for info API
   Improves the existing integraiton tests for `loaded_programs()` and
   `loaded_maps()` in consideration for older kernels:
     - Opt for `SocketFilter` program in tests since XDP requires v4.8 and
       fragments requires v5.18.
     - For assertion tests, first perform the assertion, if the assertion
       fails, then it checks the host kernel version to see if it is above
       the minimum version requirement. If not, then continue with test,
       otherwise fail.
       For assertions that are skipped, they're logged in stderr which can
       be observed with `-- --nocapture`.
   
   This also fixes the `bpf_prog_get_info_by_fd()` call for kernels below
   v4.15. If calling syscall  on kernels below v4.15, it can produce an
   `E2BIG` error  because `check_uarg_tail_zero()` expects the entire
   struct to all-zero bytes (which is caused from the map info).
   
   Instead, we first attempt the syscall with the map info filled, if it
   returns `E2BIG`, then perform syscall again with empty closure.
   
   Also adds doc for which version a kernel feature was introduced for
   better  awareness.
   
   The tests have been verified kernel versions:
     - 4.13.0
     - 4.15.0
     - 6.1.0
 - <csr-id-cd1db86fd490b3c0f03229bd8999a2e67ccecfc4/> adjust bpf programs for big endian
   In aya/src/sys/bpf.rs, there are several simple bpf programs written as
   byte arrays. These need to be adjusted to account for big endian.
 - <csr-id-a25f501ecebaceaacdd1212fac34f528b51ad0fd/> expose run_time_ns and run_cnt fields in ProgramInfo
   Added functions to expose `run_time_ns` & `run_cnt` statistics from
   ProgramInfo/bpf_prog_info.
 - <csr-id-fa6af6a20439cccd8ab961f83dce545fb5884dd4/> add BPF_ENABLE_STATS syscall function
   Add bpf syscall function for BPF_ENABLE_STATS to enable stats tracking
   for benchmarking purposes.
   
   Additionally, move `#[cfg(test)]` annotation around the `Drop` trait
   instead. Having separate functions causes some complications when
   needing ownership/moving of the inner value `OwnedFd` when `Drop` is
   manually implemented.
 - <csr-id-d413e2f285643cbeb665fd3c517e2c9d93d45825/> :programs::uprobe: fix bad variable name
   The variable fn_name was very much *not* the fn_name, but rather the
   object file path.
 - <csr-id-462514ed4c4c06e9618d029a57708c7fa14ab748/> adjust symbol lookup tests for object crate alignment requirements
   The object::File::parse API requires parameter to be aligned with 8 bytes.
   Adjusted the Vec in the tests with miri to meet this requirement.
 - <csr-id-e6e1bfeb58ac392637061640365b057182ee1b39/> add symbol lookup in associated debug files
   This change enhances the logic for symbol lookup in uprobe or uretprobe.
   If the symbol is not found in the original binary, the search continues
   in the debug file associated through the debuglink section. Before
   searching the symbol table, it compares the build IDs of the two files.
   The symbol lookup will only be terminated if both build IDs exist and do
   not match. This modification does not affect the existing symbol lookup
   logic.
 - <csr-id-b06ff402780b80862933791831c578e4c339fc96/> Generate new bindings
 - <csr-id-a4e68ebdbf0e0b591509f36316d12d9689d23f89/> include license in crate workspace
   This PR includes the licenses files in the crate workspace subdirectory.
   Without this, they won't be showing on crates.io and would be giving out
   errors on tooling such as rust2rpm.
 - <csr-id-e38eac6352ccb5c2b44d621161a27898744ea397/> appease new nightly clippy lints
   ```
     error: unnecessary qualification
        --> aya/src/maps/ring_buf.rs:434:22
         |
     434 |                 ptr: ptr::NonNull::new(ptr).ok_or(
         |                      ^^^^^^^^^^^^^^^^^
         |
     note: the lint level is defined here
        --> aya/src/lib.rs:72:5
         |
     72  |     unused_qualifications,
         |     ^^^^^^^^^^^^^^^^^^^^^
     help: remove the unnecessary path segments
         |
     434 -                 ptr: ptr::NonNull::new(ptr).ok_or(
     434 +                 ptr: NonNull::new(ptr).ok_or(
         |
   
     error: unnecessary qualification
        --> aya/src/maps/mod.rs:225:21
         |
     225 |     let mut limit = std::mem::MaybeUninit::<rlimit>::uninit();
         |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         |
     help: remove the unnecessary path segments
         |
     225 -     let mut limit = std::mem::MaybeUninit::<rlimit>::uninit();
     225 +     let mut limit = mem::MaybeUninit::<rlimit>::uninit();
         |
   
     error: unnecessary qualification
        --> aya/src/programs/mod.rs:614:9
         |
     614 |         crate::obj::Program {
         |         ^^^^^^^^^^^^^^^^^^^
         |
     help: remove the unnecessary path segments
         |
     614 -         crate::obj::Program {
     614 +         obj::Program {
         |
   
     error: unnecessary qualification
        --> aya/src/util.rs:373:14
         |
     373 |     unsafe { std::slice::from_raw_parts(bpf_name.as_ptr() as
         *const _, length) }
         |              ^^^^^^^^^^^^^^^^^^^^^^^^^^
         |
     help: remove the unnecessary path segments
         |
     373 -     unsafe { std::slice::from_raw_parts(bpf_name.as_ptr() as
         *const _, length) }
     373 +     unsafe { slice::from_raw_parts(bpf_name.as_ptr() as *const _,
         length) }
         |
   
     error: unnecessary qualification
         --> aya/src/maps/mod.rs:1130:47
          |
     1130 |                     .copy_from_slice(unsafe {
          std::mem::transmute(TEST_NAME) });
          |                                               ^^^^^^^^^^^^^^^^^^^
          |
     note: the lint level is defined here
         --> aya/src/lib.rs:72:5
          |
     72   |     unused_qualifications,
          |     ^^^^^^^^^^^^^^^^^^^^^
     help: remove the unnecessary path segments
          |
     1130 -                     .copy_from_slice(unsafe {
          std::mem::transmute(TEST_NAME) });
     1130 +                     .copy_from_slice(unsafe {
          mem::transmute(TEST_NAME) });
          |
   ```

### Performance

 - <csr-id-d05110fd86f9b317d47ffb7cf5c00e588635d4cd/> cache `nr_cpus` in a thread_local

### Test

 - <csr-id-eef7346fb2231f8741410381198015cceeebfac9/> adjust test byte arrays for big endian
   Adding support for s390x (big endian architecture) and found that some
   of the unit tests have structures and files implemented as byte arrays.
   They are all coded as little endian and need a bug endian version to
   work properly.

### New Features (BREAKING)

 - <csr-id-fd48c55466a23953ce7a4912306e1acf059b498b/> Rename BpfRelocationError -> EbpfRelocationError
 - <csr-id-cf3e2ca677c81224368fb2838ebc5b10ee98419a/> Rename BpfSectionKind to EbpfSectionKind

## 0.12.0 (2024-02-28)

<csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/>
<csr-id-770a95e0779a6a943c2f5439334fa208ac2ca7e6/>
<csr-id-48fdf5a250ce74516a02c0f34b0f359f7f9a4d63/>
<csr-id-2be705bfa04a80b1c4b58a69750e485aa0f2639a/>
<csr-id-d570450a0c4622a5a8e7e62b321847d3155af1ea/>
<csr-id-0f6a7343926b23190483bed49855fdc9bb10988d/>
<csr-id-92b194788527b1318e262a3b9bb4558339aee05b/>
<csr-id-7022528f04e08ef1a79ef0fee78323f29b6cc81c/>
<csr-id-7c1bfeffe8988bb60020d6b61ee0f10aa5f1e1e7/>
<csr-id-2257cbeccb18a3f486c9d64b52b33a331c89531e/>
<csr-id-b13645b13da5b843728959e0416617ea19096613/>
<csr-id-e9e2f48d4fa8825fec9d343e76999d58b170cdd8/>
<csr-id-b1769678f48f7abf6c987a1d686bbaffd5d1e664/>
<csr-id-c06fcc3edafe8efefc90d2eff1b4b4a5489fb9eb/>
<csr-id-15faca8b2eddfad22594824cc634bfa1e540eeaa/>
<csr-id-4d24d1cfe8108365403d834e40efa3fa72983f6d/>
<csr-id-36420d929734beb7486cc5d14944fc7cf8e9b62a/>
<csr-id-68ba02002fbd3bcf157c72b8212a697551cae8e6/>
<csr-id-8780a50be194f7d7c41f6886f1c5de8eee4e59d0/>
<csr-id-c89b2d156dbddd495f885edecbf71910cc61bba8/>
<csr-id-984c08cbad73c51a501b528c53e72f6130976639/>
<csr-id-e2cf734490bc188bcedb1eac92d23d81123e42cd/>
<csr-id-4af9d1bd3ea8dd638bddeb2ae2a8ccea6d11b249/>
<csr-id-b73c0a46f572a77d6d05d96d65f638848ac9b132/>
<csr-id-8462b69716d5918a599933bb9688fa7f57b8ee1d/>
<csr-id-5cdd1baf291f7d98128257a6a73cf8df2c144908/>
<csr-id-5e637071c130fece2b26f6a7246bdef5f782fced/>
<csr-id-cc48523347c2be5520779ef8eeadc6d3a68649d0/>
<csr-id-7b71c7e1cd8d6948764d02afb0279151c6eae437/>
<csr-id-0bf97eba64b44835300d8291cd4f78c220c3ad48/>
<csr-id-bd6ba3ad8bae0537eee9eb78d20620592daa3c76/>
<csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/>
<csr-id-0a6a2674fa6cbfda986b20d76f64802f0f65c2f0/>
<csr-id-dffff1ce6b6c4500b970dec53b57b7eb9c3ec717/>
<csr-id-00dc7a5bd4468b7d86d7f167a49e78d89016e2ac/>
<csr-id-c6754c614ed3aca142bb27fae4e8d488aff72019/>
<csr-id-9ed1d3d2811db89dc7314914d92922c54032382c/>
<csr-id-f7fbbcd0e5cad297ddc5407e201580f878b4c5ee/>
<csr-id-0647927e32333de662c6a065d5f5b9761c429e68/>
<csr-id-139f3826383daba9a10dc7aacc079f31d28980fc/>
<csr-id-ede3e91014075de01af02da624cad99861da2dad/>
<csr-id-ec8293ab8644cbf8f1c4e7b1c44b286bc0ae969a/>
<csr-id-938f979fe7a82f6d31c3b7e926682864c507e381/>
<csr-id-0f4021ec89ef2dc5c28355ecfde4b2c53b4b6429/>
<csr-id-0dacb34d449f71b1998b0a23cd58c0023277c2ef/>
<csr-id-b4d5a1e8dbb82fc6fca543ad3b6e2f8175ae83b6/>
<csr-id-f41592663cda156082255b93db145cfdd19378e5/>
<csr-id-6ab7475fa66d1b8155487dfc548645e2b8ee20c6/>
<csr-id-172859c66b25fbfa0d6d2af38ba7dd3f8e99d999/>
<csr-id-2a1bf609b2b1239c9a789f1a1c814dfa888dfd1d/>
<csr-id-8b0c7f12046c2ebadcee5e7ab813d5a34ddc08c6/>
<csr-id-204d02022a94dab441029855e5d39d5143444204/>
<csr-id-cee0265b5291acb747cf3a9532cfbf61c455f398/>
<csr-id-6895b1e2ede8d571e7f7069a109932e917fd3ede/>
<csr-id-d2e74e562dfa601397b3570ece1a51f5013b9928/>
<csr-id-1ccfdbc17577a5f132ba0af2eb9b754e6e19ddca/>
<csr-id-0bba9b14b02a01ca33dbb1fa4a910b77a73a4d65/>
<csr-id-abda239d635e70c34898a425d119040d1bac39a5/>
<csr-id-9ff1bf3d3bb8f3d51ecaf625dbf3f8d2dbb51abc/>
<csr-id-a31544b6e77d6868d950820ad31fc1fe8ed3666b/>
<csr-id-89bc255f1d14d72a61064b9b40b641b58f8970e0/>
<csr-id-3d68fa32cba3dfadc6a611cf285c7f6733abd39a/>
<csr-id-ae6526e59b2875807524d466667e2d89c4cd4b8e/>
<csr-id-504fd1df0a29a02f5a19185e302c3e305a1045c7/>
<csr-id-e1a556894c412daeb44c09c6aa2f9f4489952f34/>
<csr-id-d88ca62aaaff690335c18ac725164c82fd173be2/>
<csr-id-db975e977813ed6961963f7052ae53bc6df69309/>
<csr-id-5ac186299b468e54f93b16393bae44b3d896c544/>
<csr-id-c7a19bcefba25455279d9e718f6430dee7a84b74/>
<csr-id-5138c731a92a8e5107e41829573617fc624ea9c7/>
<csr-id-8ebf0ac3279db08a6b71ae6fed42a135d627e576/>
<csr-id-cca9b8f1a7e345a39d852bd18a43974871d3ed4b/>
<csr-id-81fb4e5568b2521a61db2db839126a4b7df240df/>
<csr-id-dcc6b84a8803cfee37ab4e138c89616f1fc1b002/>
<csr-id-71737f55764f56a764a5b21de0e59b8ecc49477c/>
<csr-id-89ef97e8482d1d0c1bb243441d911f688e183315/>
<csr-id-7bb9b7f5a5f03e815a5274457a93d0b20677059f/>
<csr-id-b1404e9a73aee4cdf93e96b44d35057ae1f6f079/>
<csr-id-a0af7e0b2fddaf297887c3e4c7480ef625c88ada/>
<csr-id-de8519a38083e96f9a0c34f0577657b8050db8a8/>
<csr-id-4cb3ea6e8fa990b88c5e8a67f1c852355bc7d99a/>
<csr-id-7ee6f52a7442e97d81ef41bc75673c8560bec5b0/>
<csr-id-dbfba18dac87cbd837820316d53ad09b27d0c469/>
<csr-id-17f25a67934ad10443a4fbb62a563b5f6edcaa5f/>
<csr-id-ea96c29ccbae6c59a6a5bfc90f402ad307e22665/>
<csr-id-683a1cf2e4cdfba05ba35d708fecc4f43b0e83b3/>
<csr-id-76c78e3bf82eb77c947dd125ed6624dfa6f4cc1c/>
<csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/>
<csr-id-74b546827cdde13872e141e9e5b6cc9ac39efe1e/>
<csr-id-8c61fc9ea6d1d52b38a238541fb229bc850c82ac/>
<csr-id-27120b328aac5f992eed98b03216a9880a381749/>
<csr-id-47f764c19185a69a00f3925239797caa98cd5afe/>
<csr-id-00c480d2f95d4c47fc281173307c179220cc4452/>
<csr-id-65d10f9ffcad065bd87c15aacc85cc4a0c2a03ee/>
<csr-id-93435fc85400aa036f3890c43c78c9c9eb4baa96/>
<csr-id-987e8489d05c50b777272124a7ec6ef6f3db6145/>
<csr-id-49c6f5d12253cccf6354f818bf6d3b190428dc29/>
<csr-id-8e9f395eab70b23b84b14e17d9b1518918b35ee6/>
<csr-id-e9be3d9023478b0132779267dcd88222f69feef5/>
<csr-id-591e21267a9bc9adca9818095de5a695cee7ee9b/>
<csr-id-9e1109b3ce70a3668771bd11a7fda101eec3ab93/>
<csr-id-ae8a95b0ee513b220b0b5ff1332ca24059ed3e7e/>
<csr-id-4c78f7f1a014cf54d54c805233a0f29eb1ca5eeb/>
<csr-id-33a0a2b604e77b63b771b9d0e167c894793492b5/>
<csr-id-3aeeb8167baa2edb511f39b3d396d9112443aa73/>
<csr-id-f1d891836e73d503c1841f5e7aee199d2b223afa/>
<csr-id-1132b6e01b86856aa1fddf179fcc7e3825e79406/>
<csr-id-7c25fe90a9611545aba047cd347ca431616130b6/>
<csr-id-93ac3e94bcb47864670c124dfe00e16ed2ab6f5e/>
<csr-id-bcb2972a969f85e8c6c77e1213d89cc8198e8fe7/>
<csr-id-b614ffd603f4a276fd060659e14e5794bb26381f/>
<csr-id-2e3c1779be03898dd6a01644012ef21b2475ad63/>
<csr-id-94049ec661ed715e65fb4fb29c92d10d803699cc/>
<csr-id-de4905a24bc0f665c40af964b56471c04434a8b4/>
<csr-id-b1a70fc6e40f7ad398bce9994f3bb2642267ca8b/>
<csr-id-ce79de7ff6b965efa25840b35b0d051c3087db0a/>
<csr-id-7479c1dd6c1356bddb0401dbeea65618674524c9/>
<csr-id-d0b3d3b2fac955ed0e1e3d885fcd3ba67941dc8c/>
<csr-id-763b92a2e007a17cc2b6a17929dcb6a5c26c9f88/>
<csr-id-ce22ca668f3e7c0f9832d28370457204537d2e50/>
<csr-id-a18693b42dc986bde06b07540e261ecac59eef24/>
<csr-id-7a720ab0c1061b7a6f4e8e7bf862d86550bbdc7b/>
<csr-id-c22014c757c88c40091e44a48e14920f6e6e0334/>
<csr-id-9c451a3357317405dd8e2e4df7d006cee943adcc/>
<csr-id-e52497cb9c02123ae450ca36fb6f898d24b25c4b/>
<csr-id-ac49827e204801079be2b87160a795ef412bd6cb/>
<csr-id-81bc307dce452f0aacbfbe8c304089d11ddd8c5e/>
<csr-id-aba99ea4b1f5694e115ae49e9dbe058d3e761fd8/>
<csr-id-12e422b21134e3f4fb1949b248ecfd2afd768e53/>
<csr-id-b3ae7786d335fd0294a6ddecf3f31ef28d56af9d/>
<csr-id-51bb50ed8e9726723b395515374053e59cd4c402/>
<csr-id-1fe7bba070cc74008cc8165030b01336cb9acbe1/>
<csr-id-e0a98952601bf8244a1f046a106b6419313537b6/>
<csr-id-ec2bd690532cc21b22e07cfa1539a195bf5e149c/>
<csr-id-43aff5779390881d785a4d1c0d6c7bd681381dfe/>
<csr-id-2eccf1d57da4c9bfa1ea4c0802bc34905c9b1f72/>
<csr-id-5693fb994123b88eb856af83c5b8f79afd1d789f/>
<csr-id-de6fa98963b7c5a311aafec6afe956ff716d68c5/>
<csr-id-7c244e1f65fdb80f65c6a317773f3ff069255cd8/>
<csr-id-f961cbb3d43693e21a9c633d8b581c8a24fa7055/>
<csr-id-6af2053cf3fd36522642169710d2804feb1e20a5/>
<csr-id-3bed2c2b94a47503ba32e9879c7a29fe9f8e9227/>
<csr-id-c30ae6e0010adda3d3e3de792cf2919f3c1dcf32/>
<csr-id-4b5b9ab3d92befe967709ad6cc55264fc0541b73/>
<csr-id-18584e2259382bbb4e56007eacbe81dba25db05a/>
<csr-id-f34ebeba99e409bb369a74687e1664a50c430c1e/>
<csr-id-7b143199fb61edd168f3efc860a8e8c1d4cd9136/>
<csr-id-4c1d645aa6e8150b50007ff42eb17e270a5b80af/>
<csr-id-a6025255f56a941c2614d8bbf395e07b47588b75/>
<csr-id-edd80397dce46f6e2a4cc96bd951562987721e55/>
<csr-id-3211646aef48c7d388941a4a9e932e66bec87fd6/>
<csr-id-03a15b98643a520269197e5db98cc48715a61577/>
<csr-id-34ba2bc0482f9a16bc9c7ad138e9288c66e4bac4/>
<csr-id-64f8a434d2a337578bde86c1983f46a3282e7f53/>
<csr-id-5726b6d044011b462b04e533f881e0dd26d60d0f/>
<csr-id-c9e70a8758ef10cfe1970e5f7a1e830e0ba5ec8e/>
<csr-id-3d592d0f295b0a2c385e200bb0224c57c144f5ea/>
<csr-id-bebe98e6706ec4c149508f8aabdd44707d1c6d73/>
<csr-id-336faf553e1ef8d21298a4f6e9835a22e29904ad/>
<csr-id-661a21570f1154f4ae32c81a8a142913f7deec86/>
<csr-id-004f3dd6644b0c0a2ff1e877093a5ee0610eb830/>
<csr-id-9e85b923230bd1db18fb87a3a6bc4a5c60a6b405/>
<csr-id-b4413322e3730b183546fcfdfc4b12f0ffce4a9c/>
<csr-id-fd52bfeadc70020e4111bb4dda0ca4e361c3be43/>
<csr-id-ccb189784f87d58bc397b22c04e976cabcbd8e00/>
<csr-id-623579a47f1fd169ba9503bd71550c3fcce76b21/>
<csr-id-2b98259be73865cf6b213de1b73d0b7b0086a22f/>
<csr-id-7b21a2d17eac57696352b2519bd76a4c7e9b1a2b/>
<csr-id-0cd1e514763fd99dc287128317e9a36312ff6883/>
<csr-id-572d047e37111b732be49ef3ad6fb16f70aa4063/>
<csr-id-6f3cce75cf11af27a9267dd88a688fc24e6b17b5/>
<csr-id-c74813f8c545fca288094f47b20096e58eb5f46a/>
<csr-id-13b1fc63ef2ae083ba03ce9de24cb4f31f989d21/>

### Chore

 - <csr-id-b3e7ef741c5b8d09fc7dc8302576f8174be75ff4/> Use the cargo workspace package table
   This allows for inheritance of common fields from the workspace root.
   The following fields have been made common:
   
   - authors
   - license
   - repository
   - homepage
   - edition
 - <csr-id-770a95e0779a6a943c2f5439334fa208ac2ca7e6/> Appease clippy unused imports
 - <csr-id-48fdf5a250ce74516a02c0f34b0f359f7f9a4d63/> tracefs review fixes

### Chore

 - <csr-id-13b1fc63ef2ae083ba03ce9de24cb4f31f989d21/> Don't use path deps in workspace
   This moves the path dependencies back into the per-crate Cargo.toml.
   It is required such that the release tooling can correctly calculate
   which version constraints require changing when we perform a release.

### Documentation

 - <csr-id-281ac1ac02cf0da7be1161b25c2ef023b922bc0c/> Document breaking changes
   This provides a `BREAKING-CHANGES.md` that we can populate per-crate.
   Doing so will allow us to pull this content into our changelog and
   websites to make things easier for users.
 - <csr-id-95e8c78db8fef4fcc12a9cbf0a52753049070e4b/> Add labels for optional features
   Following the lead of crates like tokio and nix, we now annotate APIs
   that require optional features. This helps in cases where a user wants
   to have an `AsyncPerfEventArray` which is documented on crates.io, but
   it's not obvious that you have to enable the `async` feature.
 - <csr-id-713cd4e858d9474318104b2a1e4dee0a25e8c67a/> Add crabby logo
 - <csr-id-2d9d7a1a0b8fb944a9843642e85480b16c11bd11/> Document more breaking changes
 - <csr-id-12280a83f967ba9a90dcd066b3470f4bcc4ea77c/> Add CHANGELOG

### New Features

 - <csr-id-c6c4ac7eeaf7e6cfa31ab0b949aa93b136eda91b/> get_tracefs function

### Bug Fixes

 - <csr-id-c31cce4a368ac56b42196604ef110139d28a2f8e/> invalid transmute when calling fd
   Correct an invalid transmutation for sock_map.
   fd is already a ref of MapFd, so transmuting &fd to &SockMapFd is
   equivalent to transmuting &&SockMapFd into &SockMapFd which is buggy.
 - <csr-id-243986c1da440c763393a4a37d5b3922b6baa3cc/> Relax unnecessarily strict atomic ordering on probe event_alias
 - <csr-id-0e4aec475ff2e9448196bce0b4598a983419974e/> remove useless `any` `all` in cfg.

### Other

 - <csr-id-2be705bfa04a80b1c4b58a69750e485aa0f2639a/> reformat to please rustfmt
 - <csr-id-d570450a0c4622a5a8e7e62b321847d3155af1ea/> export some missing modules
   Previously we were only re-exporting the program types from these, so
   links and other pub types were not exported.
 - <csr-id-0f6a7343926b23190483bed49855fdc9bb10988d/> perf_event: add inherit argument to attach()
 - <csr-id-92b194788527b1318e262a3b9bb4558339aee05b/> add StackTraceMap::remove()
 - <csr-id-7022528f04e08ef1a79ef0fee78323f29b6cc81c/> appease new nightly clippy lints
   ```
     error: this call to `as_ref.map(...)` does nothing
        --> aya/src/bpf.rs:536:30
         |
     536 |                 let btf_fd = btf_fd.as_ref().map(Arc::clone);
         |                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: try: `btf_fd.clone()`
         |
         = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#useless_asref
     note: the lint level is defined here
        --> aya/src/lib.rs:41:5
         |
     41  |     clippy::all,
         |     ^^^^^^^^^^^
         = note: `#[deny(clippy::useless_asref)]` implied by `#[deny(clippy::all)]`
   
     error: could not compile `aya` (lib) due to 1 previous error
     warning: build failed, waiting for other jobs to finish...
     error: initializer for `thread_local` value can be made `const`
       --> aya/src/sys/fake.rs:14:61
        |
     14 |     pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = RefCell::new(ptr::null_mut());
        |                                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: replace with: `const { RefCell::new(ptr::null_mut()) }`
        |
        = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#thread_local_initializer_can_be_made_const
        = note: `#[deny(clippy::thread_local_initializer_can_be_made_const)]` implied by `#[deny(clippy::all)]`
   ```
 - <csr-id-7c1bfeffe8988bb60020d6b61ee0f10aa5f1e1e7/> appease nightly lint
   ```
   error: lint `unused_tuple_struct_fields` has been renamed to `dead_code`
     --> aya/src/lib.rs:74:5
      |
   74 |     unused_tuple_struct_fields,
      |     ^^^^^^^^^^^^^^^^^^^^^^^^^^ help: use the new name: `dead_code`
      |
      = note: `-D renamed-and-removed-lints` implied by `-D warnings`
      = help: to override `-D warnings` add `#[allow(renamed_and_removed_lints)]`
   ```
   
   See https://github.com/rust-lang/rust/commit/9fcf9c141068984ffcbb4cb00c.
 - <csr-id-2257cbeccb18a3f486c9d64b52b33a331c89531e/> add SchedClassifier::attach_to_link
   Similar to Xdp::attach_to_link, can be used to replace/upgrade the
   program attached to a link.
 - <csr-id-b13645b13da5b843728959e0416617ea19096613/> add SchedClassifierLink::attach_type() getter
   The link already exposes priority() and handle(). Expose attach_type()
   too.
 - <csr-id-e9e2f48d4fa8825fec9d343e76999d58b170cdd8/> Fix ringbuf docs
   doctests are not running in CI and therefore the didn't catch the
   ringbuf docs failures. This commit fixes the issues in the examples.
 - <csr-id-b1769678f48f7abf6c987a1d686bbaffd5d1e664/> pin for (async)perf_event_array
   Implement pinning for perf_event_array and async_perf_event_array.
   Additionally make the core MapData.pin method operate on a reference
   rather than a mutable reference.
 - <csr-id-c06fcc3edafe8efefc90d2eff1b4b4a5489fb9eb/> make RingBuf: Send + Sync
   There was no reason for them not to be -- the APIs all require mutable
   references and hold onto mutable references, so there cannot be internal
   concurrency. The !Send + !Sync came from the MMap, but not for any good
   reason.
 - <csr-id-15faca8b2eddfad22594824cc634bfa1e540eeaa/> extracting program and map names with the same function
 - <csr-id-4d24d1cfe8108365403d834e40efa3fa72983f6d/> add MapInfo struct following the same pattern as ProgramInfo
   This makes the APIs for loading maps and programs more similar.
 - <csr-id-36420d929734beb7486cc5d14944fc7cf8e9b62a/> support loading a map by fd
   This adds support to loading maps by fd similarly to the way programs
   can be loaded by fd.
 - <csr-id-68ba02002fbd3bcf157c72b8212a697551cae8e6/> make KernelVersion::code public
 - <csr-id-8780a50be194f7d7c41f6886f1c5de8eee4e59d0/> Add markdownlint
   This adds a linter to catch common markdown formatting errors.
   The linter used is markdownlint-cli2 which is available on all platforms
   and has an associated Github Action to automate these checks in CI.
   
   Configuration is checked in at .markdownlint-cli2.yaml.
   
   You may run the check locally using `markdownlint-cli2`.
   Or you may install the extension for VSCode:
   DavidAnson.vscode-markdownlint
 - <csr-id-c89b2d156dbddd495f885edecbf71910cc61bba8/> update async-io requirement from 1.3 to 2.0
   Updates the requirements on [async-io](https://github.com/smol-rs/async-io) to permit the latest version.
   - [Release notes](https://github.com/smol-rs/async-io/releases)
   - [Changelog](https://github.com/smol-rs/async-io/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/smol-rs/async-io/compare/v1.3.0...v1.13.0)
   
   ---
   updated-dependencies:
   - dependency-name: async-io
     dependency-type: direct:production
   ...
 - <csr-id-984c08cbad73c51a501b528c53e72f6130976639/> fix unused async-io dependency linter error
   Not using the `dep:` syntax created a Cargo feature flag for async-io,
   though this feature alone does nothing without the `async_std` or
   `async_tokio` features.
 - <csr-id-e2cf734490bc188bcedb1eac92d23d81123e42cd/> Implement RingBuf
   This implements the userspace binding for RingBuf.
   
   Instead of streaming the samples as heap buffers, the process_ring
   function takes a callback to which we pass the event's byte region,
   roughly following [libbpf]'s API design. This avoids a copy and allows
   marking the consumer pointer in a timely manner.
 - <csr-id-4af9d1bd3ea8dd638bddeb2ae2a8ccea6d11b249/> move mmap from perf_buffer.rs to sys/mod.rs
   mmap() is needed for the ring buffer implementation, so move it to a common module
 - <csr-id-b73c0a46f572a77d6d05d96d65f638848ac9b132/> impl From<obj::InvalidMapTypeError> for MapTypeError
 - <csr-id-8462b69716d5918a599933bb9688fa7f57b8ee1d/> sort variants
   Missed in 5e637071c130fece2b26f6a7246bdef5f782fced due to merge skew
   with 7b71c7e1cd8d6948764d02afb0279151c6eae437.
 - <csr-id-5cdd1baf291f7d98128257a6a73cf8df2c144908/> import types from std::ffi rather than libc
 - <csr-id-5e637071c130fece2b26f6a7246bdef5f782fced/> sort variants
 - <csr-id-cc48523347c2be5520779ef8eeadc6d3a68649d0/> remove redundant keys
   `default-features = false` is already in the root Cargo.toml.
 - <csr-id-7b71c7e1cd8d6948764d02afb0279151c6eae437/> add pin() api
   - Adds new `maps_mut()` API to the BpfManager to allow us to iterate though
   and pin all of maps at the same time.
   
   - Adds new pin(Path)/unpin(Path) api to Maps so they
   can be generically pinned AFTER load.
   
   - Adds macro for pinning explicit map types in aya.
   Convert all explicit map types "inner" field to be
   pub crate in order to facilitate this.
 - <csr-id-0bf97eba64b44835300d8291cd4f78c220c3ad48/> fix libbpf_pin_by_name
   Aligns with libbpf for the special LIBBPF_PIN_BY_NAME
   map flag. Specifically if the flag is provided without a pin path
   default to "/sys/fs/bpf".
 - <csr-id-bd6ba3ad8bae0537eee9eb78d20620592daa3c76/> Deprecate `syscall_prefix`
   Using the prefix only for the host architecture is often not enough,
   kernels usually provide symbols for more architectures, which are
   used by multilib applications. Handling them might or might not be
   necessary depending on the use case. Due to that complexity, we
   decided to let the callers to handle prefixes the way they prefer.
 - <csr-id-d16e607fd4b6258b516913071fdacafeb2bbbff9/> group_imports = "StdExternalCrate"
   High time we stop debating this; let the robots do the work.
 - <csr-id-0a6a2674fa6cbfda986b20d76f64802f0f65c2f0/> Fix program loading on kernels with a patch > 255
 - <csr-id-dffff1ce6b6c4500b970dec53b57b7eb9c3ec717/> fix load time and add test
   Time since boot is defined as the UNIX_EPOCH plus the duration
   since boot. which is realtime - boottime NOT boottime - realtime.
   
   Add a integration test to ensure this doesn't happen again.
 - <csr-id-00dc7a5bd4468b7d86d7f167a49e78d89016e2ac/> make maps work on kernels not supporting ProgIds
   On startup, the kernel is probed for support of chained program ids for
   CpuMap, DevMap and DevMapHash, and will patch maps at load time to have
   the proper size. Then, at runtime, the support is checked and will error
   out if a program id is passed when the kernel does not support it.
 - <csr-id-c6754c614ed3aca142bb27fae4e8d488aff72019/> use ProgramFd instead of impl AsRawFd
   Not having a generic here allows to pass `None` without specifying the
   actual type you don't care about.
 - <csr-id-9ed1d3d2811db89dc7314914d92922c54032382c/> add documentation for XDP maps
 - <csr-id-f7fbbcd0e5cad297ddc5407e201580f878b4c5ee/> fix docstring missing trailing period
 - <csr-id-0647927e32333de662c6a065d5f5b9761c429e68/> add support for chained xdp programs in {cpu,dev}map
   set/insert functions can now take an optional bpf program fd to run once
   the packet has been redirected from the main probe
 - <csr-id-139f3826383daba9a10dc7aacc079f31d28980fc/> add support for map-bound XDP programs
   Such programs are to be bound to cpumap or devmap instead of the usual
   network interfaces.
 - <csr-id-ede3e91014075de01af02da624cad99861da2dad/> Update XDP maps implementations
   Map impls changed since this was first written.
 - <csr-id-ec8293ab8644cbf8f1c4e7b1c44b286bc0ae969a/> Implement XDP Map Types
   This commit adds implementations for:
   - xskmap
   - devmap
   - devmap_hash
   - cpumap
   
   Which can all be used to redirect XDP packets to various different
   locations
 - <csr-id-938f979fe7a82f6d31c3b7e926682864c507e381/> Make MapData::pin pub
   This is to solve a use-case where a user (in this case bpfd) may want
   to:
   
   - MapData::from_pin to open a pinned map from bpffs
   - MapData::pin to pin that object into another bpffs
   
   Both operations should be easily accomplished without needing to cast
   a MapData into a concrete Map type - e.g aya::maps::HashMap.
 - <csr-id-0f4021ec89ef2dc5c28355ecfde4b2c53b4b6429/> Remove MapData::pinned
   BPF objects can be pinned multiple times, to multiple different places.
   Tracking whether or not a map is pinned in a bool is therefore not sufficient.
   We could track this in a HashSet<PathBuf>, but there is really no reason
   to track it at all.
 - <csr-id-0dacb34d449f71b1998b0a23cd58c0023277c2ef/> fix typos, avoid fallible conversions
 - <csr-id-b4d5a1e8dbb82fc6fca543ad3b6e2f8175ae83b6/> MapData::{obj, fd} are private
 - <csr-id-f41592663cda156082255b93db145cfdd19378e5/> `MapFd` and `SockMapFd` are owned
 - <csr-id-6ab7475fa66d1b8155487dfc548645e2b8ee20c6/> add program_info() api to program
   Add a new api to the outer level `Program` structure which
   allows users to get the program's kernel info before casting
   it to an explicit program variant.
 - <csr-id-172859c66b25fbfa0d6d2af38ba7dd3f8e99d999/> support TryFrom for LRU hash maps
   The macro to implement TryFrom for MapData didn't have the ability to
   specify that more than one variant of MapData can be valid for a single
   map implementation. Support for new syntax was added to the macro so that
   the implementation can succeed for both valid variants in the HashMap
   and PerCpuHashMap impl.
 - <csr-id-2a1bf609b2b1239c9a789f1a1c814dfa888dfd1d/> rework TryFrom macros
   The old macros were repetitive and inflexible. This unifies the various
   macros used to generate TryFrom implementations for map implementations
   from the relevant map enum variants.
   
   Cleanup in anticipation of fixing #636.
   
   The API changes are just about renaming the return to Self and
   Self::Error; they are not real changes.
 - <csr-id-8b0c7f12046c2ebadcee5e7ab813d5a34ddc08c6/> access inner through async
   Avoid holding onto raw file descriptors.
   
   Remove some implied bounds (BorrowMut implies Borrow).
 - <csr-id-204d02022a94dab441029855e5d39d5143444204/> ProgAttachLink and LircLink hold owned FDs
 - <csr-id-cee0265b5291acb747cf3a9532cfbf61c455f398/> use OwnedFd
 - <csr-id-6895b1e2ede8d571e7f7069a109932e917fd3ede/> Use AsFd when attaching fds to programs
   This is a breaking change but adds another level of safety to ensure
   the file descriptor we receive is valid. Additionally, this allows
   aya to internally easily duplicate this file descriptor using std
   library methods instead of manually calling `dup` which doesn't
   duplicate with the CLOSE_ON_EXEC flag that is standard practice to
   avoid leaking the file descriptor when exec'ing.
 - <csr-id-d2e74e562dfa601397b3570ece1a51f5013b9928/> Use BorrowedFd when using the program fd in sys/bpf.rs
   This commit reveals but does not address a file descriptor leak in
   LircLink2::query. This function returns a list of `LircLink`s where
   each of them have a program file descriptor that is not going to be
   closed. This commit does not add this leak; it merely makes it louder
   in the code.
 - <csr-id-1ccfdbc17577a5f132ba0af2eb9b754e6e19ddca/> support non-UTF8 probing
 - <csr-id-0bba9b14b02a01ca33dbb1fa4a910b77a73a4d65/> avoid path UTF-8 assumptions
 - <csr-id-abda239d635e70c34898a425d119040d1bac39a5/> deny various allow-by-default lints
 - <csr-id-9ff1bf3d3bb8f3d51ecaf625dbf3f8d2dbb51abc/> fix docs build
   Appease the new lint rustdoc::redundant_explicit_links that was added in
   https://github.com/rust-lang/rust/pull/113167.
 - <csr-id-a31544b6e77d6868d950820ad31fc1fe8ed3666b/> BloomFilter::insert takes &mut self
   This is consistent with all the other maps.
 - <csr-id-89bc255f1d14d72a61064b9b40b641b58f8970e0/> MapData::fd is non-optional
   The primary driver of change here is that `MapData::create` is now a
   factory function that returns `Result<Self, _>` rather than mutating
   `&mut self`. The remaining changes are consequences of that change, the
   most notable of which is the removal of several errors which are no
   longer possible.
 - <csr-id-3d68fa32cba3dfadc6a611cf285c7f6733abd39a/> use RAII to close FDs
 - <csr-id-ae6526e59b2875807524d466667e2d89c4cd4b8e/> `ProgramData::attach_prog_fd` is owned
   This prevents a file descriptor leak when extensions are used.
   
   This is an API breaking change.
 - <csr-id-504fd1df0a29a02f5a19185e302c3e305a1045c7/> `ProgramFd` is owned
 - <csr-id-e1a556894c412daeb44c09c6aa2f9f4489952f34/> add helper methods for ProgramInfo
   - Add helper methods to get useful information from the ProgramInfo
   object which is returned by the `loaded_programs()` API.  Specifically
   this code mirrors the `bpftool prog` command in terms of useful fields.
   - Add a new API macro to each aya `Program` type to allow us to fetch
   its accompanying `ProgramInfo` metadata after its been loaded.
   - Add a new ProgramInfo constructor that builds a new instance using
   a raw fd.
   - Add a smoke test for the loaded_programs() API as well as
   all the relevant methods on the ProgramInfo type.
 - <csr-id-d88ca62aaaff690335c18ac725164c82fd173be2/> Plug attach_btf_obj_fd leak
 - <csr-id-db975e977813ed6961963f7052ae53bc6df69309/> Don't store bpf_fd in MapData
   This is only used in create and therefore can be passed
   as a parameter.
 - <csr-id-5ac186299b468e54f93b16393bae44b3d896c544/> refactor btf_obj_get_info_by_fd to share code
 - <csr-id-c7a19bcefba25455279d9e718f6430dee7a84b74/> add map_ids to bpf_prog_get_info_by_fd
   Allows the caller to pass a slice which the kernel will populate with
   map ids used by the program.
 - <csr-id-5138c731a92a8e5107e41829573617fc624ea9c7/> avoid vector allocation when parsing ksyms
 - <csr-id-8ebf0ac3279db08a6b71ae6fed42a135d627e576/> Use OwnedFd in FdLink.
 - <csr-id-cca9b8f1a7e345a39d852bd18a43974871d3ed4b/> Remove name from ProgramSection
   The name here is never used as we get the program name from the symbol
   table instead.
 - <csr-id-81fb4e5568b2521a61db2db839126a4b7df240df/> refactor target resolution
   This attempts to do fewer lossy conversions and to avoid some
   allocations.
 - <csr-id-dcc6b84a8803cfee37ab4e138c89616f1fc1b002/> extract library path resolving
   The function is extracted so that a test could be written. This test is
   valid on linux-gnu targets, and it doesn't need any special privileges.
   This is in anticipation of removing the code that uses this functionality
   (seemingly incidentally) from integration tests.
 - <csr-id-71737f55764f56a764a5b21de0e59b8ecc49477c/> Set BPF_F_SLEEPABLE for sleepable programs
 - <csr-id-89ef97e8482d1d0c1bb243441d911f688e183315/> preallocate the vector
   This code badly needs tests :(
 - <csr-id-7bb9b7f5a5f03e815a5274457a93d0b20677059f/> plug file descriptor leak
   This leaked a file descriptor if bpf_prog_get_info_by_fd failed.
 - <csr-id-b1404e9a73aee4cdf93e96b44d35057ae1f6f079/> push error construction up
 - <csr-id-a0af7e0b2fddaf297887c3e4c7480ef625c88ada/> make `loaded_programs` opaque
 - <csr-id-de8519a38083e96f9a0c34f0577657b8050db8a8/> extract common SyscallError
   We currently have 4 copies of this.
 - <csr-id-4cb3ea6e8fa990b88c5e8a67f1c852355bc7d99a/> `sys_bpf` takes mut ref
   Some syscalls mutate the argument, we can't be passing an immutable
   reference here.
 - <csr-id-7ee6f52a7442e97d81ef41bc75673c8560bec5b0/> avoid repeating BPF_BTF_LOAD dance
 - <csr-id-dbfba18dac87cbd837820316d53ad09b27d0c469/> Return `OwnedFd` for `perf_event_open`.
   This fixes a file descriptor leak when creating a link of
   BPF_PERF_EVENT attach type.
 - <csr-id-17f25a67934ad10443a4fbb62a563b5f6edcaa5f/> better panic messages
   Always include operands in failing assertions. Use assert_matches over
   manual match + panic.
 - <csr-id-ea96c29ccbae6c59a6a5bfc90f402ad307e22665/> Use Arc<OwnedFd> when loading BTF fd
   This fixes an existing file descriptor leak when there is BTF data in
   the loaded object.
   
   To avoid lifetime issues while having minimal impact to UX the
   `OwnedFd` returned from the BPF_BTF_LOAD syscall will be wrapped in an
   `Arc` and shared across the programs and maps of the loaded BPF
   file.
 - <csr-id-683a1cf2e4cdfba05ba35d708fecc4f43b0e83b3/> Make SysResult generic on Ok variant
 - <csr-id-76c78e3bf82eb77c947dd125ed6624dfa6f4cc1c/> bpf_prog_get_fd_by_id returns OwnedFd
 - <csr-id-96fa08bd82233268154edf30b106876f5a4f0e30/> Define dependencies on the workspace level
   This way we will avoid version mismatches and make differences in
   features across our crates clearer.
 - <csr-id-74b546827cdde13872e141e9e5b6cc9ac39efe1e/> Ignore embedded BTF error if not truly required
   This allows fallback to BTF manual relocation when BTF loading fail when not truly required.
 - <csr-id-8c61fc9ea6d1d52b38a238541fb229bc850c82ac/> compile C probes using build.rs
   - Add libbpf as a submodule. This prevents having to plumb its location
     around (which can't be passed to Cargo build scripts) and also
     controls the version against which codegen has run.
   - Move bpf written in C to the integration-test crate and define
     constants for each probe.
   - Remove magic; each C source file must be directly enumerated in the
     build script and in lib.rs.
 - <csr-id-27120b328aac5f992eed98b03216a9880a381749/> don't allocate static strings
 - <csr-id-47f764c19185a69a00f3925239797caa98cd5afe/> Make Features part of the public API
   This commit adds a new probe for bpf_attach_cookie, which would be used
   to implement USDT probes. Since USDT probes aren't currently supported,
   we this triggers a dead_code warning in clippy.
   
   There are cases where exposing FEATURES - our lazy static - is actually
   helpful to users of the library. For example, they may wish to choose to
   load a different version of their bytecode based on current features.
   Or, in the case of an orchestrator like bpfd, we might want to allow
   users to describe which features their program needs and return nice
   error message is one or more nodes in their cluster doesn't support the
   necessary feature set.
   
   To do this without breaking the API, we make all the internal members of
   the `Features` and `BtfFeatures` structs private, and add accessors for
   them. We then add a `features()` API to avoid leaking the
   lazy_static.
 - <csr-id-00c480d2f95d4c47fc281173307c179220cc4452/> Remove iter_key from LPM Trie API
   Based on the discussion in Discord we've decided to drop the
   iter_key() API for LPM Trie. According to the kernel self-tests and
   experimentation done in Aya, providing a key into bpf_map_get_next_id
   will either:
   
   - If key is an EXACT match, proceed iterating through all keys in the
   trie from this point
   - If key is NOT an EXACT match, proceed iterating through all keys in
   the trie starting at the leftmost entry.
   
   An API in Aya could be crafted that gets the LPM match + less specific
   matches for a prefix using these semantics BUT it would only apply to
   userspace. Therefore we've opted out of fixing this.
 - <csr-id-65d10f9ffcad065bd87c15aacc85cc4a0c2a03ee/> replace os::unix::prelude with os::fd
 - <csr-id-93435fc85400aa036f3890c43c78c9c9eb4baa96/> allow global value to be optional
   This allow to not error out when a global symbol is missing from the object.
 - <csr-id-987e8489d05c50b777272124a7ec6ef6f3db6145/> add syscall_prefix and syscall_fnname_add_prefix
   These two functions are needed because kernel symbols representing
   syscalls have architecture-specific prefixes.
   
   These are the equivalent of bcc's get_syscall_fnname and
   get_syscall_prefix.
 - <csr-id-49c6f5d12253cccf6354f818bf6d3b190428dc29/> Fix uprobe support on 4.16 and lower
   Fix uprobe support on Ubuntu 18.04.
 - <csr-id-8e9f395eab70b23b84b14e17d9b1518918b35ee6/> Add support for old ld.so.cache format
   This fix uprobe support on Debian 10. (and possibly others)
   This implement support to parse the original libc5 format.
 - <csr-id-e9be3d9023478b0132779267dcd88222f69feef5/> Make probe event_alias unique
   This fixes issues when trying to attach the same kernel function multiple times on 4.17 and lower (possibly upper too?)
 - <csr-id-591e21267a9bc9adca9818095de5a695cee7ee9b/> Do not create data maps on kernel without global data support
   Fix map creation failure when a BPF have a data section on older
   kernel. (< 5.2)
   
   If the BPF uses that section, relocation will fail accordingly and
   report an error.
 - <csr-id-9e1109b3ce70a3668771bd11a7fda101eec3ab93/> Move program's functions to the same map
 - <csr-id-ae8a95b0ee513b220b0b5ff1332ca24059ed3e7e/> update bitflags requirement from 1.2.1 to 2.2.1
   Updates the requirements on [bitflags](https://github.com/bitflags/bitflags) to permit the latest version.
   - [Release notes](https://github.com/bitflags/bitflags/releases)
   - [Changelog](https://github.com/bitflags/bitflags/blob/main/CHANGELOG.md)
   - [Commits](https://github.com/bitflags/bitflags/compare/1.2.1...2.2.1)
 - <csr-id-4c78f7f1a014cf54d54c805233a0f29eb1ca5eeb/> update object requirement from 0.30 to 0.31
   Updates the requirements on [object](https://github.com/gimli-rs/object) to permit the latest version.
   - [Release notes](https://github.com/gimli-rs/object/releases)
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.30.0...0.31.0)
   
   ---
   updated-dependencies:
   - dependency-name: object
     dependency-type: direct:production
   ...
 - <csr-id-33a0a2b604e77b63b771b9d0e167c894793492b5/> flip feature "no_std" to feature "std"
   This fixes `cargo build --all-features` by sidestepping the feature
   unification problem described in The Cargo Book[0].
   
   Add `cargo hack --feature-powerset` to CI to enforce that this doesn't
   regress (and that all combinations of features work).
   
   Since error_in_core is nightly-only, use core-error and a fake std
   module to allow aya-obj to build without std on stable.
   
   [0] https://doc.rust-lang.org/cargo/reference/features.html#feature-unification
 - <csr-id-3aeeb8167baa2edb511f39b3d396d9112443aa73/> Correctly set the kernel code version for Debian kernel
   Fix BPF syscall failure related to the kernel code version.
 - <csr-id-f1d891836e73d503c1841f5e7aee199d2b223afa/> Correctly set the kernel code version for Ubuntu kernel
   Fix BPF syscall failure related to the kernel code version.
 - <csr-id-1132b6e01b86856aa1fddf179fcc7e3825e79406/> Add sanitize code for kernels without bpf_probe_read_kernel
   Required for kernel before 5.5.
   
   Also move Features to aya-obj.
 - <csr-id-7c25fe90a9611545aba047cd347ca431616130b6/> Do not use unwrap with btf_fd in bpf_create_map
   Fixes a crash when trying to create a map of type BPF_MAP_TYPE_PERCPU_ARRAY when btf_fd is None.
   
   Tested on Ubuntu 18.04 (4.15.0-202-generic)
 - <csr-id-93ac3e94bcb47864670c124dfe00e16ed2ab6f5e/> support relocations across multiple text sections + fixes
   Fix R_BPF_64_64 text relocations in sections other than .text (for
   instance .text.unlikely). Also fix misc bugs triggered by integration
   tests.
 - <csr-id-bcb2972a969f85e8c6c77e1213d89cc8198e8fe7/> make it possible to use set_global() with slices of Pod(s)
 - <csr-id-b614ffd603f4a276fd060659e14e5794bb26381f/> make it possible to use set_global() with slices of Pod(s)
 - <csr-id-2e3c1779be03898dd6a01644012ef21b2475ad63/> Allow to attach XDP probe by interface index
 - <csr-id-94049ec661ed715e65fb4fb29c92d10d803699cc/> Fix MapData Clone implementation
   The Clone implementation of MapData was previously not storing the
   result of the dup operation.
 - <csr-id-de4905a24bc0f665c40af964b56471c04434a8b4/> Add loaded_programs() API to list all loaded programs
   This uses a Programs iterator to yield all loaded bpf programs using
   bpf_prog_get_next_id.
 - <csr-id-b1a70fc6e40f7ad398bce9994f3bb2642267ca8b/> MapData should be Borrow, not AsRef
   We don't ever do ref-to-ref conversion for MapData so Borrow should
   suffice.
 - <csr-id-ce79de7ff6b965efa25840b35b0d051c3087db0a/> Fix is_perf_link_supported
   This was mistakenly comparing the exit code of the syscall, which is
   always -1 and not the corresponding error-code. Added unit tests to
   ensure we don't regress.
 - <csr-id-7479c1dd6c1356bddb0401dbeea65618674524c9/> More discrete feature logging
   Just use the Debug formatter vs. printing a message for each probe.
 - <csr-id-d0b3d3b2fac955ed0e1e3d885fcd3ba67941dc8c/> Enable bpf_link for perf_attach programs
   This adds support for bpf_link to PerfEvent, Tracepoint, Kprobe and
   Uprobe programs.
 - <csr-id-763b92a2e007a17cc2b6a17929dcb6a5c26c9f88/> Add probe for bpf_link_create for perf programs
 - <csr-id-ce22ca668f3e7c0f9832d28370457204537d2e50/> Make features a lazy_static
 - <csr-id-a18693b42dc986bde06b07540e261ecac59eef24/> Add support for multibuffer programs
   This adds support for loading XDP programs that are multi-buffer
   capable, which is signalled using the xdp.frags section name. When this
   is set, we should set the BPF_F_XDP_HAS_FRAGS flag when loading the
   program into the kernel.
 - <csr-id-7a720ab0c1061b7a6f4e8e7bf862d86550bbdc7b/> Add from_pin for Programs
   This commit adds from_pin() which allows the creation of a Program
   from a path on bpffs. This is useful to be able to call `attach` or
   other APIs for programs that are already loaded to the kernel.
   
   This differs from #444 since it implements this on the concrete program
   type, not the Program enum, allowing the user to pass in any additional
   context that isn't available from bpf_prog_info.
 - <csr-id-c22014c757c88c40091e44a48e14920f6e6e0334/> fix Lru and LruPerCpu hash maps
   They were broken by https://github.com/aya-rs/aya/pull/397
 - <csr-id-9c451a3357317405dd8e2e4df7d006cee943adcc/> update documentation and versioning info
   - Set the version number of `aya-obj` to `0.1.0`.
   - Update the description of the `aya-obj` crate.
   - Add a section in README and rustdoc warning about the unstable API.
 - <csr-id-e52497cb9c02123ae450ca36fb6f898d24b25c4b/> add basic documentation to public members
   Types relevant to maps are moved into aya_obj::maps.
   Some members are marked `pub(crate)` again.
 - <csr-id-ac49827e204801079be2b87160a795ef412bd6cb/> migrate aya::obj into a separate crate
   To split the crate into two, several changes were made:
   1. Most `pub(crate)` are now `pub` to allow access from Aya;
   2. Parts of BpfError are merged into, for example, RelocationError;
   3. BTF part of Features is moved into the new crate;
   4. `#![deny(missing_docs)]` is removed temporarily;
   5. Some other code gets moved into the new crate, mainly:
      - aya::{bpf_map_def, BtfMapDef, PinningType},
      - aya::programs::{CgroupSock*AttachType},
   
   The new crate is currently allowing missing_docs. Member visibility
   will be adjusted later to minimize exposure of implementation details.
 - <csr-id-81bc307dce452f0aacbfbe8c304089d11ddd8c5e/> migrate bindgen destination
 - <csr-id-aba99ea4b1f5694e115ae49e9dbe058d3e761fd8/> make btf::RelocationError private
 - <csr-id-12e422b21134e3f4fb1949b248ecfd2afd768e53/> fix regression computing pointer sizes
   Computing pointer sizes was broken in #285
 - <csr-id-b3ae7786d335fd0294a6ddecf3f31ef28d56af9d/> fix detaching links on drop
 - <csr-id-51bb50ed8e9726723b395515374053e59cd4c402/> add missing TryFrom<Map> for HashMap, PerCpuHashMap and LpmTrie
 - <csr-id-1fe7bba070cc74008cc8165030b01336cb9acbe1/> update object requirement from 0.29 to 0.30
   Updates the requirements on [object](https://github.com/gimli-rs/object) to permit the latest version.
   - [Release notes](https://github.com/gimli-rs/object/releases)
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.29.0...0.30.0)
   
   ---
   updated-dependencies:
   - dependency-name: object
     dependency-type: direct:production
   ...
 - <csr-id-e0a98952601bf8244a1f046a106b6419313537b6/> Fix the error message in `MapData::pin()`
   The syscall name is `BPF_OBJ_PIN`, not `BPF_OBJ_GET`.
 - <csr-id-ec2bd690532cc21b22e07cfa1539a195bf5e149c/> Remove unused dependencies
 - <csr-id-43aff5779390881d785a4d1c0d6c7bd681381dfe/> Disable miri warnings about integer-to-pointer conversions
   `override_syscall` performs integer-to-pointer conversion. This is
   considered harmful on the newest Rust nightly which provides
   `ptr::from_exposed_addr`, but there is no other way on Rust stable than
   doing `as *const T`, which is what miri is unhappy about.
 - <csr-id-2eccf1d57da4c9bfa1ea4c0802bc34905c9b1f72/> add BpfLoader::set_max_entries
   Add BpfLoader::set_max_entries, which sets the max_entries for the
   specified map, as the load-time option.
   The max_entries set at map initialization in the ebpf component can be
   overwritten by this method called on the userspace component.
   If you want to set max_entries for multiple maps in an ebpf component,
   you can do so by calling set_max_entries in the form of a method chain.
 - <csr-id-5693fb994123b88eb856af83c5b8f79afd1d789f/> Rename from_pinned and from_path to from_pin
 - <csr-id-de6fa98963b7c5a311aafec6afe956ff716d68c5/> Fix review comments from #387
 - <csr-id-7c244e1f65fdb80f65c6a317773f3ff069255cd8/> Add integration test for pinning lifecycle
 - <csr-id-f961cbb3d43693e21a9c633d8b581c8a24fa7055/> Replace From<FdLink> for XdpLink with TryFrom
 - <csr-id-6af2053cf3fd36522642169710d2804feb1e20a5/> Rename bpf_obj_get_info_by_id
 - <csr-id-3bed2c2b94a47503ba32e9879c7a29fe9f8e9227/> fix miss doc period
 - <csr-id-c30ae6e0010adda3d3e3de792cf2919f3c1dcf32/> change  variant names
 - <csr-id-4b5b9ab3d92befe967709ad6cc55264fc0541b73/> More pinning fixes
   This commit fixes a bug and adds some missing lifecycle APIs.
   
   1. Adds PinnedLink::from_path to create a pinned link from bpffs
   2. Adds From<PinnedLink> for FdLink to allow for ^ to be converted
   3. Adds From<FdLink> for XdpLink
 - <csr-id-18584e2259382bbb4e56007eacbe81dba25db05a/> Fix segfault in define_link_wrapper
   The From<$wrapper> for $base implementation is refers to itself,
   eventually causing a segfault.
 - <csr-id-f34ebeba99e409bb369a74687e1664a50c430c1e/> Improved BTF Type API
   This commit removes reliance on generated BtfType structs, as
   well as adding a dedicated struct for each BTF type. As such,
   we can now add nice accessors like `bits()` and `encoding()`
   for Int vs. inlined shift/mask operations.
 - <csr-id-7b143199fb61edd168f3efc860a8e8c1d4cd9136/> update `VerifierLogLevel` to use bitflags
 - <csr-id-4c1d645aa6e8150b50007ff42eb17e270a5b80af/> Fix Link Pinning
   1. Removes OwnedLink
   2. Allows Links to be converted into FdLink
   3. Introduces a PinnedLink type to handle wrap FdLink when pinned and
      support un-pinning
 - <csr-id-a6025255f56a941c2614d8bbf395e07b47588b75/> update `VerifierLogLevel` level variants
 - <csr-id-edd80397dce46f6e2a4cc96bd951562987721e55/> use enum to set verifier log level
 - <csr-id-3211646aef48c7d388941a4a9e932e66bec87fd6/> expose BPF verifier log level configuration
 - <csr-id-03a15b98643a520269197e5db98cc48715a61577/> Remove MapError::InvalidPinPath
 - <csr-id-34ba2bc0482f9a16bc9c7ad138e9288c66e4bac4/> Use PinError for all pinning errors
 - <csr-id-64f8a434d2a337578bde86c1983f46a3282e7f53/> Implement FdLink::pin()
   This allows for FdLinks to also be pinned to BpfFs.
   In order for it to be called, the user would first call
   `take_link` to get the underlying link. This can then
   be destructured to an FdLink where FdLink::pin() may be called.
 - <csr-id-5726b6d044011b462b04e533f881e0dd26d60d0f/> Allow pin to be used on all programs
   This allows for `pin` to be called as `Xdp::pin()` or
   Program::pin() - the same way that unload() can be used.
   This simplifies the use of this API.
 - <csr-id-c9e70a8758ef10cfe1970e5f7a1e830e0ba5ec8e/> Fix rlimit warning on for 32bit systems
 - <csr-id-3d592d0f295b0a2c385e200bb0224c57c144f5ea/> Raise the RLIMIT_MEMLOCK warning only if failed to create a map
   Also, mention that setting the RLIMIT_MEMLOCK to a higher value is an
   option.
 - <csr-id-bebe98e6706ec4c149508f8aabdd44707d1c6d73/> Raise the warning when RMILIT_MEMLOCK is not RLIM_INFINITY
   Kernels before 5.11 don't use cgroup accounting, so they might reach the
   RLIMIT_MEMLOCK when creating maps. After this change, we raise a warning
   recommending to raise the RLIMIT_MEMLOCK.
 - <csr-id-336faf553e1ef8d21298a4f6e9835a22e29904ad/> Fix latest nightly lints
 - <csr-id-661a21570f1154f4ae32c81a8a142913f7deec86/> update object requirement from 0.28 to 0.29
   Updates the requirements on [object](https://github.com/gimli-rs/object) to permit the latest version.
   - [Release notes](https://github.com/gimli-rs/object/releases)
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.28.0...0.29.0)
   
   ---
   updated-dependencies:
   - dependency-name: object
     dependency-type: direct:production
   ...
 - <csr-id-004f3dd6644b0c0a2ff1e877093a5ee0610eb830/> Improve Extension Docs
 - <csr-id-9e85b923230bd1db18fb87a3a6bc4a5c60a6b405/> Add Extension::attach_to_program()
   This allows for Extension programs already loaded to the kernel to be
   attached to another program that is BTF-compatible with the one provided
   at `load()` time
 - <csr-id-b4413322e3730b183546fcfdfc4b12f0ffce4a9c/> Replace ProgramFd trait with struct
   This removes the ProgramFd trait with a struct that wraps a RawFd.
   Program::fd() has been implemented as well as fd() for each Program
   Type. This allows for a better API than requiring the use of the
   ProgramFd trait.
 - <csr-id-fd52bfeadc70020e4111bb4dda0ca4e361c3be43/> Implement attach_to_link for XDP
 - <csr-id-ccb189784f87d58bc397b22c04e976cabcbd8e00/> Add support for bpf_link_update
 - <csr-id-623579a47f1fd169ba9503bd71550c3fcce76b21/> Add Map::fd() function to return a MapFd
 - <csr-id-2b98259be73865cf6b213de1b73d0b7b0086a22f/> Add crabby, sync with aya/README.md
 - <csr-id-7b21a2d17eac57696352b2519bd76a4c7e9b1a2b/> Implement BPF_PROG_TYPE_CGROUP_SOCK
 - <csr-id-0cd1e514763fd99dc287128317e9a36312ff6883/> Unload programs on drop

### Test

 - <csr-id-572d047e37111b732be49ef3ad6fb16f70aa4063/> avoid lossy string conversions
   We can be strict in tests.
 - <csr-id-6f3cce75cf11af27a9267dd88a688fc24e6b17b5/> s/assert!(.*) ==/assert_eq!\1,/
   One case manually adjusted to `assert_matches!`.
 - <csr-id-c74813f8c545fca288094f47b20096e58eb5f46a/> add the possibility to run a test inside a network namespace
   For tests that do networking operations, this allows to have a
   clean-state network namespace and interfaces for each test. Mainly, this
   avoids "device or resource busy" errors when reusing the loopback
   interface across tests.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 434 commits contributed to the release.
 - 631 days passed between releases.
 - 182 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Release aya-obj v0.1.0, aya v0.12.0, safety bump aya-log v0.2.0 ([`0e99fa0`](https://github.com/aya-rs/aya/commit/0e99fa0f340b2fb2e0da3b330aa6555322a77eec))
    - Don't use path deps in workspace ([`13b1fc6`](https://github.com/aya-rs/aya/commit/13b1fc63ef2ae083ba03ce9de24cb4f31f989d21))
    - Merge pull request #892 from dave-tucker/breaking-changes-v2 ([`daa5a47`](https://github.com/aya-rs/aya/commit/daa5a473105e0c99f5f171ba519d076a7157af6e))
    - Merge pull request #891 from dave-tucker/changelog ([`431ce23`](https://github.com/aya-rs/aya/commit/431ce23f27ef5c36a6b38c73b38f23b1cf007900))
    - Document more breaking changes ([`2d9d7a1`](https://github.com/aya-rs/aya/commit/2d9d7a1a0b8fb944a9843642e85480b16c11bd11))
    - Add CHANGELOG ([`12280a8`](https://github.com/aya-rs/aya/commit/12280a83f967ba9a90dcd066b3470f4bcc4ea77c))
    - Merge pull request #889 from dave-tucker/breaking-changes ([`5c9c044`](https://github.com/aya-rs/aya/commit/5c9c044719f84dcb76edfa496e3999194253b5c4))
    - Document breaking changes ([`281ac1a`](https://github.com/aya-rs/aya/commit/281ac1ac02cf0da7be1161b25c2ef023b922bc0c))
    - Merge pull request #882 from dave-tucker/metadata ([`0fadd69`](https://github.com/aya-rs/aya/commit/0fadd695377b8a3f0d9a3af3bc8140f0f1bed8d2))
    - Use the cargo workspace package table ([`b3e7ef7`](https://github.com/aya-rs/aya/commit/b3e7ef741c5b8d09fc7dc8302576f8174be75ff4))
    - Merge pull request #885 from dave-tucker/nightly-up ([`2d72197`](https://github.com/aya-rs/aya/commit/2d721971cfae39e168f0dc4dac1f219490c16fbf))
    - Appease clippy unused imports ([`770a95e`](https://github.com/aya-rs/aya/commit/770a95e0779a6a943c2f5439334fa208ac2ca7e6))
    - Appease rustc dead_code lint ([`963dd13`](https://github.com/aya-rs/aya/commit/963dd1321925c95f80c8a2bf656b88a39497ca01))
    - Invalid transmute when calling fd ([`c31cce4`](https://github.com/aya-rs/aya/commit/c31cce4a368ac56b42196604ef110139d28a2f8e))
    - Merge pull request #878 from alessandrod/missing-exports ([`46b4805`](https://github.com/aya-rs/aya/commit/46b48053df07d813ee519598382f74cead5fd602))
    - Reformat to please rustfmt ([`2be705b`](https://github.com/aya-rs/aya/commit/2be705bfa04a80b1c4b58a69750e485aa0f2639a))
    - Reorder imports a bit ([`9b4f876`](https://github.com/aya-rs/aya/commit/9b4f87646d2e0973be6ff30cb1acf26e1f416b3f))
    - Export some missing modules ([`d570450`](https://github.com/aya-rs/aya/commit/d570450a0c4622a5a8e7e62b321847d3155af1ea))
    - Perf_event: add inherit argument to attach() ([`0f6a734`](https://github.com/aya-rs/aya/commit/0f6a7343926b23190483bed49855fdc9bb10988d))
    - Add StackTraceMap::remove() ([`92b1947`](https://github.com/aya-rs/aya/commit/92b194788527b1318e262a3b9bb4558339aee05b))
    - Merge pull request #865 from tamird/appease-lint ([`09851a2`](https://github.com/aya-rs/aya/commit/09851a2090287b531652e8547a14c70532633d6c))
    - Appease new nightly clippy lints ([`7022528`](https://github.com/aya-rs/aya/commit/7022528f04e08ef1a79ef0fee78323f29b6cc81c))
    - Merge pull request #861 from tamird/appease-lint ([`604742a`](https://github.com/aya-rs/aya/commit/604742a2f218012ea967d220ecf7be9b74cda8b8))
    - Appease nightly lint ([`7c1bfef`](https://github.com/aya-rs/aya/commit/7c1bfeffe8988bb60020d6b61ee0f10aa5f1e1e7))
    - Add SchedClassifier::attach_to_link ([`2257cbe`](https://github.com/aya-rs/aya/commit/2257cbeccb18a3f486c9d64b52b33a331c89531e))
    - Add SchedClassifierLink::attach_type() getter ([`b13645b`](https://github.com/aya-rs/aya/commit/b13645b13da5b843728959e0416617ea19096613))
    - Merge pull request #858 from dave-tucker/ringbuf-doctests ([`13f21dc`](https://github.com/aya-rs/aya/commit/13f21dce1b875b225e6561b2b734411cde2a225a))
    - Fix ringbuf docs ([`e9e2f48`](https://github.com/aya-rs/aya/commit/e9e2f48d4fa8825fec9d343e76999d58b170cdd8))
    - Pin for (async)perf_event_array ([`b176967`](https://github.com/aya-rs/aya/commit/b1769678f48f7abf6c987a1d686bbaffd5d1e664))
    - Merge pull request #843 from ajwerner/ringbuf-send-sync ([`931cd55`](https://github.com/aya-rs/aya/commit/931cd55905d74192a80dbbf22a758a53135f8716))
    - Make RingBuf: Send + Sync ([`c06fcc3`](https://github.com/aya-rs/aya/commit/c06fcc3edafe8efefc90d2eff1b4b4a5489fb9eb))
    - Extracting program and map names with the same function ([`15faca8`](https://github.com/aya-rs/aya/commit/15faca8b2eddfad22594824cc634bfa1e540eeaa))
    - Add MapInfo struct following the same pattern as ProgramInfo ([`4d24d1c`](https://github.com/aya-rs/aya/commit/4d24d1cfe8108365403d834e40efa3fa72983f6d))
    - Support loading a map by fd ([`36420d9`](https://github.com/aya-rs/aya/commit/36420d929734beb7486cc5d14944fc7cf8e9b62a))
    - Make KernelVersion::code public ([`68ba020`](https://github.com/aya-rs/aya/commit/68ba02002fbd3bcf157c72b8212a697551cae8e6))
    - Merge pull request #746 from dave-tucker/markdownlint ([`958931e`](https://github.com/aya-rs/aya/commit/958931efcbfd86cab2220b36b7ebb2b34c18a842))
    - Add markdownlint ([`8780a50`](https://github.com/aya-rs/aya/commit/8780a50be194f7d7c41f6886f1c5de8eee4e59d0))
    - Merge pull request #825 from aya-rs/dependabot/cargo/async-io-2.0 ([`67fe16e`](https://github.com/aya-rs/aya/commit/67fe16e723c13b30fa4a2a73d58eda812d7ef517))
    - Update async-io requirement from 1.3 to 2.0 ([`c89b2d1`](https://github.com/aya-rs/aya/commit/c89b2d156dbddd495f885edecbf71910cc61bba8))
    - Merge pull request #821 from Tuetuopay/fix-udeps ([`f037a94`](https://github.com/aya-rs/aya/commit/f037a94c9f0f3ea4ccdfec631446384e188b64c5))
    - Fix unused async-io dependency linter error ([`984c08c`](https://github.com/aya-rs/aya/commit/984c08cbad73c51a501b528c53e72f6130976639))
    - Merge pull request #629 from ajwerner/ringbuf ([`6284994`](https://github.com/aya-rs/aya/commit/62849944f2d807e2214984f40ca0ee8193585f18))
    - Implement RingBuf ([`e2cf734`](https://github.com/aya-rs/aya/commit/e2cf734490bc188bcedb1eac92d23d81123e42cd))
    - Move mmap from perf_buffer.rs to sys/mod.rs ([`4af9d1b`](https://github.com/aya-rs/aya/commit/4af9d1bd3ea8dd638bddeb2ae2a8ccea6d11b249))
    - Impl From<obj::InvalidMapTypeError> for MapTypeError ([`b73c0a4`](https://github.com/aya-rs/aya/commit/b73c0a46f572a77d6d05d96d65f638848ac9b132))
    - Merge pull request #814 from tamird/sort-variants-again ([`cb455fe`](https://github.com/aya-rs/aya/commit/cb455febbbb350ae1ad15eeb465b5684077b5168))
    - Sort variants ([`8462b69`](https://github.com/aya-rs/aya/commit/8462b69716d5918a599933bb9688fa7f57b8ee1d))
    - Merge pull request #812 from tamird/redundant-cargo ([`715d490`](https://github.com/aya-rs/aya/commit/715d49022eefb152ef8817c730d9eac2b3e6d66f))
    - Merge pull request #813 from tamird/sort-variants ([`ae612a0`](https://github.com/aya-rs/aya/commit/ae612a0a1061ea65237b62a7d9fa1f2f583dff36))
    - Merge pull request #811 from tamird/libc ([`b7ceee4`](https://github.com/aya-rs/aya/commit/b7ceee4f51da23b124f4f500c7685b65d89d20d0))
    - Import types from std::ffi rather than libc ([`5cdd1ba`](https://github.com/aya-rs/aya/commit/5cdd1baf291f7d98128257a6a73cf8df2c144908))
    - Sort variants ([`5e63707`](https://github.com/aya-rs/aya/commit/5e637071c130fece2b26f6a7246bdef5f782fced))
    - Remove redundant keys ([`cc48523`](https://github.com/aya-rs/aya/commit/cc48523347c2be5520779ef8eeadc6d3a68649d0))
    - Merge pull request #783 from astoycos/map_pin2 ([`ef27bce`](https://github.com/aya-rs/aya/commit/ef27bce619981ef8be8b368ac39054f4ce0c5505))
    - Add pin() api ([`7b71c7e`](https://github.com/aya-rs/aya/commit/7b71c7e1cd8d6948764d02afb0279151c6eae437))
    - Fix libbpf_pin_by_name ([`0bf97eb`](https://github.com/aya-rs/aya/commit/0bf97eba64b44835300d8291cd4f78c220c3ad48))
    - Merge pull request #806 from vadorovsky/deprecate-syscall-prefix ([`66bd85a`](https://github.com/aya-rs/aya/commit/66bd85a8de011acd207dd806ccafb6ec56a73500))
    - Deprecate `syscall_prefix` ([`bd6ba3a`](https://github.com/aya-rs/aya/commit/bd6ba3ad8bae0537eee9eb78d20620592daa3c76))
    - Merge pull request #797 from aya-rs/rustfmt-group-imports ([`373fb7b`](https://github.com/aya-rs/aya/commit/373fb7bf06ba80ee4c120d8c112f5e810204c472))
    - Group_imports = "StdExternalCrate" ([`d16e607`](https://github.com/aya-rs/aya/commit/d16e607fd4b6258b516913071fdacafeb2bbbff9))
    - Merge pull request #791 from nrxus/fix-kernel-code-on-submode-gt-255 ([`6786383`](https://github.com/aya-rs/aya/commit/67863833ca87ddeb51e3dd7fd5ec87a22f7be63a))
    - Fix program loading on kernels with a patch > 255 ([`0a6a267`](https://github.com/aya-rs/aya/commit/0a6a2674fa6cbfda986b20d76f64802f0f65c2f0))
    - Merge pull request #527 from Tuetuopay/xdpmaps ([`7f9ce06`](https://github.com/aya-rs/aya/commit/7f9ce062f4b8b5cefbe07d8ea47363266f7eacd1))
    - Aya, bpf: misc fixes following review comments ([`579e3ce`](https://github.com/aya-rs/aya/commit/579e3cee22ae8e932efb0894ca7fd9ceb91ca7fa))
    - Merge pull request #769 from astoycos/fix-loaded-at ([`c130500`](https://github.com/aya-rs/aya/commit/c130500f18943b380e66ab6286c051f9548c47d0))
    - Fix load time and add test ([`dffff1c`](https://github.com/aya-rs/aya/commit/dffff1ce6b6c4500b970dec53b57b7eb9c3ec717))
    - Make maps work on kernels not supporting ProgIds ([`00dc7a5`](https://github.com/aya-rs/aya/commit/00dc7a5bd4468b7d86d7f167a49e78d89016e2ac))
    - Use ProgramFd instead of impl AsRawFd ([`c6754c6`](https://github.com/aya-rs/aya/commit/c6754c614ed3aca142bb27fae4e8d488aff72019))
    - Add documentation for XDP maps ([`9ed1d3d`](https://github.com/aya-rs/aya/commit/9ed1d3d2811db89dc7314914d92922c54032382c))
    - Fix docstring missing trailing period ([`f7fbbcd`](https://github.com/aya-rs/aya/commit/f7fbbcd0e5cad297ddc5407e201580f878b4c5ee))
    - Add support for chained xdp programs in {cpu,dev}map ([`0647927`](https://github.com/aya-rs/aya/commit/0647927e32333de662c6a065d5f5b9761c429e68))
    - Add support for map-bound XDP programs ([`139f382`](https://github.com/aya-rs/aya/commit/139f3826383daba9a10dc7aacc079f31d28980fc))
    - Update XDP maps implementations ([`ede3e91`](https://github.com/aya-rs/aya/commit/ede3e91014075de01af02da624cad99861da2dad))
    - Implement XDP Map Types ([`ec8293a`](https://github.com/aya-rs/aya/commit/ec8293ab8644cbf8f1c4e7b1c44b286bc0ae969a))
    - Merge pull request #790 from dave-tucker/no-map-pinned ([`42fd82e`](https://github.com/aya-rs/aya/commit/42fd82e32b85715df78508ef77f79eb8c2edd890))
    - Make MapData::pin pub ([`938f979`](https://github.com/aya-rs/aya/commit/938f979fe7a82f6d31c3b7e926682864c507e381))
    - Remove MapData::pinned ([`0f4021e`](https://github.com/aya-rs/aya/commit/0f4021ec89ef2dc5c28355ecfde4b2c53b4b6429))
    - Merge pull request #782 from astoycos/prog-info ([`0b6ea31`](https://github.com/aya-rs/aya/commit/0b6ea313ded3240715d1b30d3b247e2bc983659e))
    - Merge pull request #770 from aya-rs/mapfd-is-owned ([`41d01f6`](https://github.com/aya-rs/aya/commit/41d01f638bc81306749dd0f6aa7d2a677f4de27b))
    - Fix typos, avoid fallible conversions ([`0dacb34`](https://github.com/aya-rs/aya/commit/0dacb34d449f71b1998b0a23cd58c0023277c2ef))
    - MapData::{obj, fd} are private ([`b4d5a1e`](https://github.com/aya-rs/aya/commit/b4d5a1e8dbb82fc6fca543ad3b6e2f8175ae83b6))
    - `MapFd` and `SockMapFd` are owned ([`f415926`](https://github.com/aya-rs/aya/commit/f41592663cda156082255b93db145cfdd19378e5))
    - Add program_info() api to program ([`6ab7475`](https://github.com/aya-rs/aya/commit/6ab7475fa66d1b8155487dfc548645e2b8ee20c6))
    - Merge pull request #775 from aya-rs/perf-as-raw-fd ([`92d3056`](https://github.com/aya-rs/aya/commit/92d3056db35df729efdbdf757ec389485ce7d8fd))
    - Merge pull request #774 from ajwerner/try_from_LruHash ([`8d3fc49`](https://github.com/aya-rs/aya/commit/8d3fc49d68b5f75010451d8820a0239e538e41a7))
    - Support TryFrom for LRU hash maps ([`172859c`](https://github.com/aya-rs/aya/commit/172859c66b25fbfa0d6d2af38ba7dd3f8e99d999))
    - Merge pull request #777 from ajwerner/ajwerner/TryFrom-macros ([`792f467`](https://github.com/aya-rs/aya/commit/792f467d40dc4c6c543c62dda7a608863fc364dc))
    - Rework TryFrom macros ([`2a1bf60`](https://github.com/aya-rs/aya/commit/2a1bf609b2b1239c9a789f1a1c814dfa888dfd1d))
    - Access inner through async ([`8b0c7f1`](https://github.com/aya-rs/aya/commit/8b0c7f12046c2ebadcee5e7ab813d5a34ddc08c6))
    - Merge pull request #772 from aya-rs/link-owned ([`8668436`](https://github.com/aya-rs/aya/commit/8668436787d3c6b0079a8841e69da3d1f654a650))
    - Merge pull request #771 from aya-rs/xdp-raw ([`c4d1d10`](https://github.com/aya-rs/aya/commit/c4d1d1086a9fbcf907c260e5a6893bc71f712cfd))
    - ProgAttachLink and LircLink hold owned FDs ([`204d020`](https://github.com/aya-rs/aya/commit/204d02022a94dab441029855e5d39d5143444204))
    - Use OwnedFd ([`cee0265`](https://github.com/aya-rs/aya/commit/cee0265b5291acb747cf3a9532cfbf61c455f398))
    - Merge pull request #723 from nrxus/map-program-owned-fd ([`c4643b3`](https://github.com/aya-rs/aya/commit/c4643b395f06d65876462e95f2988f773b725742))
    - Use AsFd when attaching fds to programs ([`6895b1e`](https://github.com/aya-rs/aya/commit/6895b1e2ede8d571e7f7069a109932e917fd3ede))
    - Use BorrowedFd when using the program fd in sys/bpf.rs ([`d2e74e5`](https://github.com/aya-rs/aya/commit/d2e74e562dfa601397b3570ece1a51f5013b9928))
    - Merge pull request #765 from aya-rs/more-utf8-fixes ([`461c275`](https://github.com/aya-rs/aya/commit/461c2759c58f31af7a2ea396a477f8a8c0f8875f))
    - Support non-UTF8 probing ([`1ccfdbc`](https://github.com/aya-rs/aya/commit/1ccfdbc17577a5f132ba0af2eb9b754e6e19ddca))
    - Merge pull request #742 from aya-rs/avoid-utf-assumption ([`8ffd9bb`](https://github.com/aya-rs/aya/commit/8ffd9bb236a4dfc7694bbdac2b6ea1236b238582))
    - Avoid path UTF-8 assumptions ([`0bba9b1`](https://github.com/aya-rs/aya/commit/0bba9b14b02a01ca33dbb1fa4a910b77a73a4d65))
    - Avoid lossy string conversions ([`572d047`](https://github.com/aya-rs/aya/commit/572d047e37111b732be49ef3ad6fb16f70aa4063))
    - Merge pull request #763 from aya-rs/lints ([`ff8c124`](https://github.com/aya-rs/aya/commit/ff8c124770104d04de78057ea33a35442f86671d))
    - Deny various allow-by-default lints ([`abda239`](https://github.com/aya-rs/aya/commit/abda239d635e70c34898a425d119040d1bac39a5))
    - Merge pull request #764 from aya-rs/fix-docs ([`1fa1241`](https://github.com/aya-rs/aya/commit/1fa1241ccb218c0809595bad3e6c65643d89aa43))
    - Fix docs build ([`9ff1bf3`](https://github.com/aya-rs/aya/commit/9ff1bf3d3bb8f3d51ecaf625dbf3f8d2dbb51abc))
    - Merge pull request #758 from aya-rs/map-fd-not-option ([`1d5f764`](https://github.com/aya-rs/aya/commit/1d5f764d07c06fa25167d1d4cf341913d4f0cd01))
    - BloomFilter::insert takes &mut self ([`a31544b`](https://github.com/aya-rs/aya/commit/a31544b6e77d6868d950820ad31fc1fe8ed3666b))
    - MapData::fd is non-optional ([`89bc255`](https://github.com/aya-rs/aya/commit/89bc255f1d14d72a61064b9b40b641b58f8970e0))
    - Merge pull request #757 from aya-rs/attach-fd-owned ([`c7b5cd5`](https://github.com/aya-rs/aya/commit/c7b5cd5eb5ca238781c30794fbe72e1794b89a23))
    - Use RAII to close FDs ([`3d68fa3`](https://github.com/aya-rs/aya/commit/3d68fa32cba3dfadc6a611cf285c7f6733abd39a))
    - `ProgramData::attach_prog_fd` is owned ([`ae6526e`](https://github.com/aya-rs/aya/commit/ae6526e59b2875807524d466667e2d89c4cd4b8e))
    - Merge pull request #744 from aya-rs/programfd-borrowed ([`e813a05`](https://github.com/aya-rs/aya/commit/e813a054adfe8e62c13da6dc1ab95a53576d18f2))
    - `ProgramFd` is owned ([`504fd1d`](https://github.com/aya-rs/aya/commit/504fd1df0a29a02f5a19185e302c3e305a1045c7))
    - Merge pull request #637 from astoycos/helpers ([`bcc9743`](https://github.com/aya-rs/aya/commit/bcc97432548b19d14ea974b1a83969dc159c6af4))
    - Add helper methods for ProgramInfo ([`e1a5568`](https://github.com/aya-rs/aya/commit/e1a556894c412daeb44c09c6aa2f9f4489952f34))
    - Merge pull request #702 from dave-tucker/mapdata-btffd ([`03c5012`](https://github.com/aya-rs/aya/commit/03c5012db20fb0f9445c4464370ca339dc743c33))
    - Merge pull request #748 from aya-rs/btf_obj_fd-owned ([`7f98e41`](https://github.com/aya-rs/aya/commit/7f98e419e623440b350d6e888b6794d1fb35ce01))
    - Plug attach_btf_obj_fd leak ([`d88ca62`](https://github.com/aya-rs/aya/commit/d88ca62aaaff690335c18ac725164c82fd173be2))
    - Don't store bpf_fd in MapData ([`db975e9`](https://github.com/aya-rs/aya/commit/db975e977813ed6961963f7052ae53bc6df69309))
    - Merge pull request #747 from aya-rs/helpers ([`5bc922a`](https://github.com/aya-rs/aya/commit/5bc922af23f9b4fb08910f287622c0c486f162d9))
    - Refactor btf_obj_get_info_by_fd to share code ([`5ac1862`](https://github.com/aya-rs/aya/commit/5ac186299b468e54f93b16393bae44b3d896c544))
    - Add map_ids to bpf_prog_get_info_by_fd ([`c7a19bc`](https://github.com/aya-rs/aya/commit/c7a19bcefba25455279d9e718f6430dee7a84b74))
    - Merge pull request #743 from aya-rs/avoid-vec-ksyms ([`90cf131`](https://github.com/aya-rs/aya/commit/90cf13163b73aa87f99be285f7a9e4bc98557c7b))
    - Avoid vector allocation when parsing ksyms ([`5138c73`](https://github.com/aya-rs/aya/commit/5138c731a92a8e5107e41829573617fc624ea9c7))
    - Merge pull request #740 from addisoncrump/main ([`0c0cf70`](https://github.com/aya-rs/aya/commit/0c0cf70deba630c7fedb12f4820a47e3fa76a135))
    - Nuclear option: no symbol resolution in the crate ([`ed77727`](https://github.com/aya-rs/aya/commit/ed777273b187cc30afa573101a1fade14a4fb465))
    - Merge pull request #725 from dave-tucker/enum64 ([`2a55fc7`](https://github.com/aya-rs/aya/commit/2a55fc7bd3a15340b5b644d668f3a387bbdb09d3))
    - Aya, aya-obj: Implement ENUM64 fixups ([`e38e256`](https://github.com/aya-rs/aya/commit/e38e2566e3393034b37c299e50c6a4b70d51ad1d))
    - Merge pull request #709 from nrxus/fd-link-owned-fd ([`bd5442a`](https://github.com/aya-rs/aya/commit/bd5442a1de94f8d1359829d6f172cdd9f3452a09))
    - Use OwnedFd in FdLink. ([`8ebf0ac`](https://github.com/aya-rs/aya/commit/8ebf0ac3279db08a6b71ae6fed42a135d627e576))
    - Merge pull request #720 from dave-tucker/programsection-noname ([`e915379`](https://github.com/aya-rs/aya/commit/e9153792f1c18caa5899edc7c05487eb291415a4))
    - Extract trait SymbolResolver ([`d8709de`](https://github.com/aya-rs/aya/commit/d8709de9f232483943132e6ffdf54ae8fdb0839d))
    - Merge pull request #718 from ajwerner/better-code ([`ef6308b`](https://github.com/aya-rs/aya/commit/ef6308b640609743d7eb51453b605fe90a6aaf38))
    - Remove name from ProgramSection ([`cca9b8f`](https://github.com/aya-rs/aya/commit/cca9b8f1a7e345a39d852bd18a43974871d3ed4b))
    - Refactor target resolution ([`81fb4e5`](https://github.com/aya-rs/aya/commit/81fb4e5568b2521a61db2db839126a4b7df240df))
    - Merge pull request #717 from ajwerner/no-libc-in-integration-tests ([`de8604d`](https://github.com/aya-rs/aya/commit/de8604d0119930491d602cb18d700191ac3e2e95))
    - Merge pull request #711 from dave-tucker/sleepable ([`77e9603`](https://github.com/aya-rs/aya/commit/77e9603976b58491427df049a163e1945bc0bf27))
    - Extract library path resolving ([`dcc6b84`](https://github.com/aya-rs/aya/commit/dcc6b84a8803cfee37ab4e138c89616f1fc1b002))
    - Merge pull request #712 from aya-rs/loaded-links ([`368ddf1`](https://github.com/aya-rs/aya/commit/368ddf10c470a8a3c0420eb0f09cd254801c333b))
    - Add links iterator ([`30faa5f`](https://github.com/aya-rs/aya/commit/30faa5f68f362b385b9ca96ff300dffcfd774033))
    - Merge pull request #716 from aya-rs/prealloc-vec ([`b1bf61c`](https://github.com/aya-rs/aya/commit/b1bf61ca61285bc2390b3b3d10ee6a91eabfef34))
    - Set BPF_F_SLEEPABLE for sleepable programs ([`71737f5`](https://github.com/aya-rs/aya/commit/71737f55764f56a764a5b21de0e59b8ecc49477c))
    - Preallocate the vector ([`89ef97e`](https://github.com/aya-rs/aya/commit/89ef97e8482d1d0c1bb243441d911f688e183315))
    - Plug file descriptor leak ([`7bb9b7f`](https://github.com/aya-rs/aya/commit/7bb9b7f5a5f03e815a5274457a93d0b20677059f))
    - Push error construction up ([`b1404e9`](https://github.com/aya-rs/aya/commit/b1404e9a73aee4cdf93e96b44d35057ae1f6f079))
    - Make `loaded_programs` opaque ([`a0af7e0`](https://github.com/aya-rs/aya/commit/a0af7e0b2fddaf297887c3e4c7480ef625c88ada))
    - Extract common SyscallError ([`de8519a`](https://github.com/aya-rs/aya/commit/de8519a38083e96f9a0c34f0577657b8050db8a8))
    - `sys_bpf` takes mut ref ([`4cb3ea6`](https://github.com/aya-rs/aya/commit/4cb3ea6e8fa990b88c5e8a67f1c852355bc7d99a))
    - Merge pull request #714 from aya-rs/dry-btf-load ([`f095c59`](https://github.com/aya-rs/aya/commit/f095c591af9010dcbf9e7e8e4c6f9e2741c8592b))
    - Avoid repeating BPF_BTF_LOAD dance ([`7ee6f52`](https://github.com/aya-rs/aya/commit/7ee6f52a7442e97d81ef41bc75673c8560bec5b0))
    - Merge pull request #706 from aya-rs/reloc-tests ([`3692e53`](https://github.com/aya-rs/aya/commit/3692e53ff0e5cb87983a9b2dd54624baad22d582))
    - S/assert!(.*) ==/assert_eq!\1,/ ([`6f3cce7`](https://github.com/aya-rs/aya/commit/6f3cce75cf11af27a9267dd88a688fc24e6b17b5))
    - Merge pull request #707 from aya-rs/one-option-not-two ([`4c3219f`](https://github.com/aya-rs/aya/commit/4c3219f754c79e00ae4e56e13b646123cde31c61))
    - Reduce state cardinality from 4 to 2 ([`0ec9afd`](https://github.com/aya-rs/aya/commit/0ec9afdb07f42bc40e60c9a6af1908b23f5bf263))
    - Merge pull request #701 from nrxus/perf-event-owned-fd ([`445cb8b`](https://github.com/aya-rs/aya/commit/445cb8b46318a13a94e10e11000232d4bd5b23af))
    - Return `OwnedFd` for `perf_event_open`. ([`dbfba18`](https://github.com/aya-rs/aya/commit/dbfba18dac87cbd837820316d53ad09b27d0c469))
    - Merge pull request #704 from aya-rs/better-panic ([`868a9b0`](https://github.com/aya-rs/aya/commit/868a9b00b3701a4e035dc1d70cac934ef836655b))
    - Better panic messages ([`17f25a6`](https://github.com/aya-rs/aya/commit/17f25a67934ad10443a4fbb62a563b5f6edcaa5f))
    - Merge pull request #696 from Tuetuopay/tests-netns ([`f705eab`](https://github.com/aya-rs/aya/commit/f705eabe667d4abdfd0b895de586cc4145319cf0))
    - Add the possibility to run a test inside a network namespace ([`c74813f`](https://github.com/aya-rs/aya/commit/c74813f8c545fca288094f47b20096e58eb5f46a))
    - Merge pull request #699 from aya-rs/cache-again-god-damn-it ([`e95f76a`](https://github.com/aya-rs/aya/commit/e95f76a5b348070dd6833d37ea16db04f6afa612))
    - Do not escape newlines on Err(LoadError).unwrap() ([`8961be9`](https://github.com/aya-rs/aya/commit/8961be95268d2a4464ef75b0898cf07f9ba44470))
    - Merge pull request #662 from nrxus/use-owned-fd-for-btf ([`13e83b2`](https://github.com/aya-rs/aya/commit/13e83b24ee572009176b82840fb5cf1845fcf3dd))
    - Use Arc<OwnedFd> when loading BTF fd ([`ea96c29`](https://github.com/aya-rs/aya/commit/ea96c29ccbae6c59a6a5bfc90f402ad307e22665))
    - Make SysResult generic on Ok variant ([`683a1cf`](https://github.com/aya-rs/aya/commit/683a1cf2e4cdfba05ba35d708fecc4f43b0e83b3))
    - Replace std::os::unix::io for std::os::fd ([`c63d990`](https://github.com/aya-rs/aya/commit/c63d9904f7e64349bd23c029a3bf31aaf1d97291))
    - Merge pull request #688 from aya-rs/get-fd-owned ([`53d36a3`](https://github.com/aya-rs/aya/commit/53d36a3fe04b6828568603bfcfd9a588418abb1b))
    - Bpf_prog_get_fd_by_id returns OwnedFd ([`76c78e3`](https://github.com/aya-rs/aya/commit/76c78e3bf82eb77c947dd125ed6624dfa6f4cc1c))
    - Merge pull request #667 from vadorovsky/workspace-dependencies ([`f554d42`](https://github.com/aya-rs/aya/commit/f554d421053bc34266afbf8e00b28705ab4b41d2))
    - Define dependencies on the workspace level ([`96fa08b`](https://github.com/aya-rs/aya/commit/96fa08bd82233268154edf30b106876f5a4f0e30))
    - Merge pull request #671 from dave-tucker/misc-fixes ([`7ac808c`](https://github.com/aya-rs/aya/commit/7ac808cf551154b73f0e471af8a1a2ab88258409))
    - Clippy fixes for latest nightly ([`764eb30`](https://github.com/aya-rs/aya/commit/764eb309b082a2e54b0d98782bb9cecd1243ff42))
    - Merge pull request #656 from aya-rs/kernel-version-fml ([`232cd45`](https://github.com/aya-rs/aya/commit/232cd45e41031060238d37fc7f08eb3d63fa2eeb))
    - Handle WSL kernel version strings ([`35ed85a`](https://github.com/aya-rs/aya/commit/35ed85a87ff467c7091c8749e48b8475cd1af592))
    - Replace matches with assert_matches ([`961f45d`](https://github.com/aya-rs/aya/commit/961f45da37616b912d2d4ed594036369f3f8285b))
    - Merge pull request #650 from aya-rs/test-cleanup ([`61608e6`](https://github.com/aya-rs/aya/commit/61608e64583f9dc599eef9b8db098f38a765b285))
    - Merge pull request #584 from marysaka/fix/btf-kern-optional ([`0766e70`](https://github.com/aya-rs/aya/commit/0766e705486df167b0d5cf736c1edc14880bce17))
    - Don't use env::tempdir ([`5407d4a`](https://github.com/aya-rs/aya/commit/5407d4a9a1885806a0f74abfc8cfe17baf13e124))
    - Remove "async" feature ([`fa91fb4`](https://github.com/aya-rs/aya/commit/fa91fb4f59be3505664f8088b6e3e8da2c372253))
    - Ignore embedded BTF error if not truely required ([`74b5468`](https://github.com/aya-rs/aya/commit/74b546827cdde13872e141e9e5b6cc9ac39efe1e))
    - Fix build ([`242d8c3`](https://github.com/aya-rs/aya/commit/242d8c33c4ff71f766f32f184f826d3216929faa))
    - Merge pull request #520 from astoycos/unsupported-map ([`eb60d65`](https://github.com/aya-rs/aya/commit/eb60d6561362e57955b2963b9a6b0a818281aabf))
    - Merge pull request #560 from astoycos/fix-perf-link-pin ([`edb7baf`](https://github.com/aya-rs/aya/commit/edb7baf9a37187027e4459a7c716b22c2204ca1f))
    - Add FdLink documentation and example ([`80b371f`](https://github.com/aya-rs/aya/commit/80b371f6d134aeba0f31716bf091d03cc9ca13fe))
    - Merge pull request #644 from aya-rs/build-script ([`7def6d7`](https://github.com/aya-rs/aya/commit/7def6d72183d786427b8232945e139bb8c84d2d2))
    - Implement FdLink conversions ([`58895db`](https://github.com/aya-rs/aya/commit/58895db9b46f810d8dd1550951d490ff56dcb9b4))
    - Compile C probes using build.rs ([`8c61fc9`](https://github.com/aya-rs/aya/commit/8c61fc9ea6d1d52b38a238541fb229bc850c82ac))
    - Merge pull request #648 from aya-rs/clippy-more ([`a840a17`](https://github.com/aya-rs/aya/commit/a840a17308c1c27867e67baa62942738c5bd2caf))
    - Clippy over tests and integration-ebpf ([`e621a09`](https://github.com/aya-rs/aya/commit/e621a09181d0a5ddb6289d8b13d4b89a71de63f1))
    - Merge pull request #643 from aya-rs/procfs ([`6e9aba5`](https://github.com/aya-rs/aya/commit/6e9aba55fe8d23aa337b29a1cab890bb54816068))
    - Type-erase KernelVersion::current error ([`a1e0130`](https://github.com/aya-rs/aya/commit/a1e0130387390c148fc035ed1ae6b5665be4a96f))
    - Invert comparison ([`6bceb1c`](https://github.com/aya-rs/aya/commit/6bceb1c3da2d0d71842073a2503810a666ef3caf))
    - Rewrite kernel version logic ([`6e570f0`](https://github.com/aya-rs/aya/commit/6e570f0f14e615ccd0eeb80dfb68f3674f6ee74a))
    - Remove procfs dependency ([`cc2bc0a`](https://github.com/aya-rs/aya/commit/cc2bc0acc183f178292d630789031aed0634f878))
    - Remove verifier log special case ([`b5ebcb7`](https://github.com/aya-rs/aya/commit/b5ebcb7cc5fd0f719567b97f682a0ea0f8e0dc13))
    - Merge pull request #641 from aya-rs/logger-messages-plz ([`4c0983b`](https://github.com/aya-rs/aya/commit/4c0983bca962e0e9b2711805ae7fbc6b53457c34))
    - Get verifier logs when loading programs ([`b45a5bb`](https://github.com/aya-rs/aya/commit/b45a5bb71b485dbf05e21ddc4392bfda78f2e6f5))
    - Hide details of VerifierLog ([`6b94b20`](https://github.com/aya-rs/aya/commit/6b94b2080dc4c122954beea814b2a1a4569e9aa3))
    - Use procfs crate for kernel version parsing ([`b611038`](https://github.com/aya-rs/aya/commit/b611038d5b41a45ca70553550dbdef9aa1fd117c))
    - Merge pull request #642 from aya-rs/less-strings ([`32be47a`](https://github.com/aya-rs/aya/commit/32be47a23b94902caadcc7bb1612adbd18318eca))
    - Don't allocate static strings ([`27120b3`](https://github.com/aya-rs/aya/commit/27120b328aac5f992eed98b03216a9880a381749))
    - Merge pull request #639 from aya-rs/test-no-bpftool ([`e93e3c4`](https://github.com/aya-rs/aya/commit/e93e3c4a55c5c740f4b1d4ce52be709f218dae1b))
    - Remove dependency on bpftool in integration tests ([`ff86f13`](https://github.com/aya-rs/aya/commit/ff86f1385c1c45ed8dadcf160f2d4ae67b39ec13))
    - Merge pull request #531 from dave-tucker/probe-cookie ([`bc0d021`](https://github.com/aya-rs/aya/commit/bc0d02143f5bc6103cca27d5f0c7a40beacd0668))
    - Make Features part of the public API ([`47f764c`](https://github.com/aya-rs/aya/commit/47f764c19185a69a00f3925239797caa98cd5afe))
    - Merge pull request #526 from dave-tucker/trie ([`76d35d1`](https://github.com/aya-rs/aya/commit/76d35d10ce2ca86daee8646e701d42ceedfd9d06))
    - Remove iter_key from LPM Trie API ([`00c480d`](https://github.com/aya-rs/aya/commit/00c480d2f95d4c47fc281173307c179220cc4452))
    - Merge pull request #633 from ajwerner/change-fd-import ([`5c6bd55`](https://github.com/aya-rs/aya/commit/5c6bd5526096a5a4c10e95643365d16d0090cf8f))
    - Replace os::unix::prelude with os::fd ([`65d10f9`](https://github.com/aya-rs/aya/commit/65d10f9ffcad065bd87c15aacc85cc4a0c2a03ee))
    - Merge pull request #632 from marysaka/feat/global-data-optional ([`b2737d5`](https://github.com/aya-rs/aya/commit/b2737d5b0d18ce09202ca9eb2ce772b1144ea6b8))
    - Update aya/src/bpf.rs ([`77cce84`](https://github.com/aya-rs/aya/commit/77cce840f7957f12e29f29e1f05762173bb2b92b))
    - Allow global value to be optional ([`93435fc`](https://github.com/aya-rs/aya/commit/93435fc85400aa036f3890c43c78c9c9eb4baa96))
    - Fixups in response to alessandrod review ([`17930a8`](https://github.com/aya-rs/aya/commit/17930a88c5ea08d0ae68ac8fecee59f425fd06a3))
    - Add Unsupported Map type ([`b5719c5`](https://github.com/aya-rs/aya/commit/b5719c5b3fcb7e48896212bdc7ee82d40f838bc2))
    - Merge pull request #625 from FedericoPonzi/issue-534 ([`9cdae81`](https://github.com/aya-rs/aya/commit/9cdae8126573e598284f7dc3f6fff2f97a48cc02))
    - Add syscall_prefix and syscall_fnname_add_prefix ([`987e848`](https://github.com/aya-rs/aya/commit/987e8489d05c50b777272124a7ec6ef6f3db6145))
    - Merge pull request #622 from marysaka/fix/uprobe-416-lower ([`e5bac02`](https://github.com/aya-rs/aya/commit/e5bac0295306a6627658e818939927c387442295))
    - Fix uprobe support on 4.16 and lower ([`49c6f5d`](https://github.com/aya-rs/aya/commit/49c6f5d12253cccf6354f818bf6d3b190428dc29))
    - Merge pull request #621 from marysaka/fix/uprobe-debian-10 ([`41fe944`](https://github.com/aya-rs/aya/commit/41fe944a1a60279705f5ed156b25675ea302e861))
    - Add support for old ld.so.cache format ([`8e9f395`](https://github.com/aya-rs/aya/commit/8e9f395eab70b23b84b14e17d9b1518918b35ee6))
    - Merge pull request #619 from poliorcetics/relax-ordering-probe-alias ([`37b7c1e`](https://github.com/aya-rs/aya/commit/37b7c1e6141c53fce195b01deafedb18a955e9e1))
    - Relax unnecessarily strict atomic ordering on probe event_alias ([`243986c`](https://github.com/aya-rs/aya/commit/243986c1da440c763393a4a37d5b3922b6baa3cc))
    - Merge pull request #618 from marysaka/fix/aya-probe-event-alias-uniq ([`d56ed8f`](https://github.com/aya-rs/aya/commit/d56ed8fd687453f248fa79b6459598d53e11f40a))
    - Make probe event_alias unique ([`e9be3d9`](https://github.com/aya-rs/aya/commit/e9be3d9023478b0132779267dcd88222f69feef5))
    - Merge pull request #602 from marysaka/fix/btf-reloc-all-functions ([`3a9a54f`](https://github.com/aya-rs/aya/commit/3a9a54fd9b2f69e2427accbe0451761ecc537197))
    - Merge pull request #616 from nak3/fix-bump ([`3211d2c`](https://github.com/aya-rs/aya/commit/3211d2c92801d8208c76856cb271f2b7772a0313))
    - Add a few tweak a code to fix libbpf's API change. ([`afb4aa1`](https://github.com/aya-rs/aya/commit/afb4aa1c66b17d9e2b9a445f345c206764a9d391))
    - Fixed a typo in the per_cpu_hashmap documentation ([`3d1013d`](https://github.com/aya-rs/aya/commit/3d1013d72981e673cbc3d24401d5855ab12f6a02))
    - Merge pull request #607 from Hanaasagi/fix-warning ([`d4bfd72`](https://github.com/aya-rs/aya/commit/d4bfd72f578d24fb3a9bc5fb8177f08f98ef56d0))
    - Remove useless `any` `all` in cfg. ([`0e4aec4`](https://github.com/aya-rs/aya/commit/0e4aec475ff2e9448196bce0b4598a983419974e))
    - Merge pull request #605 from marysaka/fix/global-data-reloc-ancient-kernels ([`9c437aa`](https://github.com/aya-rs/aya/commit/9c437aafd96bebc5c90fdc7f370b5415174b1019))
    - Do not create data maps on kernel without global data support ([`591e212`](https://github.com/aya-rs/aya/commit/591e21267a9bc9adca9818095de5a695cee7ee9b))
    - Move program's functions to the same map ([`9e1109b`](https://github.com/aya-rs/aya/commit/9e1109b3ce70a3668771bd11a7fda101eec3ab93))
    - Merge pull request #592 from probulate/update-bitflags ([`67f480e`](https://github.com/aya-rs/aya/commit/67f480eb8e1798ddb6c025560bd77bb21f46650b))
    - Update bitflags requirement from 1.2.1 to 2.2.1 ([`ae8a95b`](https://github.com/aya-rs/aya/commit/ae8a95b0ee513b220b0b5ff1332ca24059ed3e7e))
    - Merge pull request #577 from aya-rs/dependabot/cargo/object-0.31 ([`deb054a`](https://github.com/aya-rs/aya/commit/deb054afa45cfb9ffb7b213f34fc549c9503c0dd))
    - Merge pull request #545 from epompeii/lsm_sleepable ([`120b59d`](https://github.com/aya-rs/aya/commit/120b59dd2e42805cf5880ada8f1bd0ba5faf4a44))
    - Update object requirement from 0.30 to 0.31 ([`4c78f7f`](https://github.com/aya-rs/aya/commit/4c78f7f1a014cf54d54c805233a0f29eb1ca5eeb))
    - Merge pull request #586 from probulate/no-std-inversion ([`45efa63`](https://github.com/aya-rs/aya/commit/45efa6384ffbcff82ca55e151c446d930147abf0))
    - Flip feature "no_std" to feature "std" ([`33a0a2b`](https://github.com/aya-rs/aya/commit/33a0a2b604e77b63b771b9d0e167c894793492b5))
    - Merge branch 'aya-rs:main' into lsm_sleepable ([`1f2006b`](https://github.com/aya-rs/aya/commit/1f2006bfde865cc4308643b21d51cf4a8e69d6d4))
    - Merge pull request #525 from dave-tucker/borrow ([`ed14751`](https://github.com/aya-rs/aya/commit/ed14751c791a0db4d01ec759a6dc21e2f6cc3312))
    - Merge pull request #579 from marysaka/fix/ubuntu-debian-kernel-version-code ([`1066c6c`](https://github.com/aya-rs/aya/commit/1066c6c2e5607d4484591cbfb77efd9464d802b2))
    - Correctly set the kernel code version for Debian kernel ([`3aeeb81`](https://github.com/aya-rs/aya/commit/3aeeb8167baa2edb511f39b3d396d9112443aa73))
    - Correctly set the kernel code version for Ubuntu kernel ([`f1d8918`](https://github.com/aya-rs/aya/commit/f1d891836e73d503c1841f5e7aee199d2b223afa))
    - Merge pull request #582 from marysaka/feature/no-kern-read-sanitizer ([`b5c2928`](https://github.com/aya-rs/aya/commit/b5c2928b0e0d20c48157a5862f0d2c3dd5dbb784))
    - Add sanitize code for kernels without bpf_probe_read_kernel ([`1132b6e`](https://github.com/aya-rs/aya/commit/1132b6e01b86856aa1fddf179fcc7e3825e79406))
    - Merge pull request #580 from marysaka/fix/bpf_create_map_panic ([`edd9928`](https://github.com/aya-rs/aya/commit/edd9928314baf6e53f091f06b166aad797fa7337))
    - Do not use unwrap with btf_fd in bpf_create_map ([`7c25fe9`](https://github.com/aya-rs/aya/commit/7c25fe90a9611545aba047cd347ca431616130b6))
    - Merge pull request #572 from alessandrod/reloc-fixes ([`542ada3`](https://github.com/aya-rs/aya/commit/542ada3fe7f9d4d06542253361acc5fadce3f24b))
    - Support relocations across multiple text sections + fixes ([`93ac3e9`](https://github.com/aya-rs/aya/commit/93ac3e94bcb47864670c124dfe00e16ed2ab6f5e))
    - Aya, aya-obj: refactor map relocations ([`401ea5e`](https://github.com/aya-rs/aya/commit/401ea5e8482ece34b6c88de85ec474bdfc577fd4))
    - Review ([`85714d5`](https://github.com/aya-rs/aya/commit/85714d5cf3622da49d1442c34caa63451d9efe48))
    - Program_section ([`17f497c`](https://github.com/aya-rs/aya/commit/17f497ce4207c5c26023914d956c7c69411b25c1))
    - Merge pull request #557 from drewvis/main ([`b13070a`](https://github.com/aya-rs/aya/commit/b13070a3429033700f8d13b4f01f81d4ede07fe1))
    - Make it possible to use set_global() with slices of Pod(s) ([`bcb2972`](https://github.com/aya-rs/aya/commit/bcb2972a969f85e8c6c77e1213d89cc8198e8fe7))
    - Added code check comment ([`8f64cf8`](https://github.com/aya-rs/aya/commit/8f64cf8cd5bf5d03445a6a79216775fda83179be))
    - Add check for empty tracefs mounts ([`3a2c0cd`](https://github.com/aya-rs/aya/commit/3a2c0cd1dd7472feb77019dec3a4a8bc466167b7))
    - Revert "aya: make it possible to use set_global() with slices of Pod(s)" ([`8ef00c4`](https://github.com/aya-rs/aya/commit/8ef00c4c637bb3f86f6cabb86f44d5e9a40d6506))
    - Make it possible to use set_global() with slices of Pod(s) ([`b614ffd`](https://github.com/aya-rs/aya/commit/b614ffd603f4a276fd060659e14e5794bb26381f))
    - Merge pull request #548 from kriomant/feature-xdp-attach-by-index ([`d6319f9`](https://github.com/aya-rs/aya/commit/d6319f95c91212218f4282aa025e3295166c9b7f))
    - Don't leak libc types ([`ce60854`](https://github.com/aya-rs/aya/commit/ce60854934312c9ebb75178f44faf9369febf6ad))
    - Fix formatting ([`896e3ab`](https://github.com/aya-rs/aya/commit/896e3ab3130c4de44e8c0f4f974163c13aa50ff0))
    - Rename method and fix comment ([`676b5cd`](https://github.com/aya-rs/aya/commit/676b5cdc0df380471090153ab4ff2e641e4e1d03))
    - Allow to attach XDP probe by interface index ([`2e3c177`](https://github.com/aya-rs/aya/commit/2e3c1779be03898dd6a01644012ef21b2475ad63))
    - Merge pull request #539 from marysaka/fix/map_data_clone ([`113e3ef`](https://github.com/aya-rs/aya/commit/113e3ef0183acc69202fa6587643449f793cfff8))
    - Fix MapData Clone implementation ([`94049ec`](https://github.com/aya-rs/aya/commit/94049ec661ed715e65fb4fb29c92d10d803699cc))
    - Merge pull request #524 from dave-tucker/prog_list ([`d9878a6`](https://github.com/aya-rs/aya/commit/d9878a67917069e89e4ea974d116c8fdab3da4e5))
    - Add loaded_programs() API to list all loaded programs ([`de4905a`](https://github.com/aya-rs/aya/commit/de4905a24bc0f665c40af964b56471c04434a8b4))
    - MapData should be Borrow, not AsRef ([`b1a70fc`](https://github.com/aya-rs/aya/commit/b1a70fc6e40f7ad398bce9994f3bb2642267ca8b))
    - Merge pull request #523 from dave-tucker/fix_perf_link ([`56c1438`](https://github.com/aya-rs/aya/commit/56c143831e8f056ac77bb5282a340c1a545eb0f2))
    - Fix is_perf_link_supported ([`ce79de7`](https://github.com/aya-rs/aya/commit/ce79de7ff6b965efa25840b35b0d051c3087db0a))
    - Merge pull request #522 from dave-tucker/perf_link ([`d7d6442`](https://github.com/aya-rs/aya/commit/d7d6442671a38098613b1a0accea0c08272d9fc0))
    - More discrete feature logging ([`7479c1d`](https://github.com/aya-rs/aya/commit/7479c1dd6c1356bddb0401dbeea65618674524c9))
    - Enable bpf_link for perf_attach programs ([`d0b3d3b`](https://github.com/aya-rs/aya/commit/d0b3d3b2fac955ed0e1e3d885fcd3ba67941dc8c))
    - Add probe for bpf_link_create for perf programs ([`763b92a`](https://github.com/aya-rs/aya/commit/763b92a2e007a17cc2b6a17929dcb6a5c26c9f88))
    - Make features a lazy_static ([`ce22ca6`](https://github.com/aya-rs/aya/commit/ce22ca668f3e7c0f9832d28370457204537d2e50))
    - Merge pull request #519 from dave-tucker/frags ([`bc83f20`](https://github.com/aya-rs/aya/commit/bc83f208b11542607e02751126a68b1ca568873b))
    - Add support for multibuffer programs ([`a18693b`](https://github.com/aya-rs/aya/commit/a18693b42dc986bde06b07540e261ecac59eef24))
    - Merge pull request #496 from dave-tucker/program-from-pinned3 ([`811ab29`](https://github.com/aya-rs/aya/commit/811ab299deee19017fa8158b7b9e8eea88107c6a))
    - Add from_pin for Programs ([`7a720ab`](https://github.com/aya-rs/aya/commit/7a720ab0c1061b7a6f4e8e7bf862d86550bbdc7b))
    - Merge pull request #515 from alessandrod/fix-lru-hash ([`cfa693b`](https://github.com/aya-rs/aya/commit/cfa693bc3b4442a8c97cfcd24551ea6439f25e50))
    - Fix Lru and LruPerCpu hash maps ([`c22014c`](https://github.com/aya-rs/aya/commit/c22014c757c88c40091e44a48e14920f6e6e0334))
    - Merge pull request #512 from astoycos/crucial-btf-fixes ([`27017ca`](https://github.com/aya-rs/aya/commit/27017ca8a32e692d6226e11857d68e5c0acc249e))
    - Support BTF key/value specification for all maps ([`52e6250`](https://github.com/aya-rs/aya/commit/52e625060e463c5b7b0ec0fe9f683b82d7227ad0))
    - Merge pull request #445 from anfredette/tc-link-recon ([`22d7931`](https://github.com/aya-rs/aya/commit/22d79312f7f5d8afd97dfaa42d3cd063206772e3))
    - Address review comments from @alessandrod ([`7c24296`](https://github.com/aya-rs/aya/commit/7c24296b5df73a5d9d07872a3832cf4e9aa9c76f))
    - Merge pull request #471 from banditopazzo/tracefs_mount_select ([`7e5637b`](https://github.com/aya-rs/aya/commit/7e5637bb9c9a0c35424e17139eaf58c825aad08c))
    - Tracefs review fixes ([`48fdf5a`](https://github.com/aya-rs/aya/commit/48fdf5a250ce74516a02c0f34b0f359f7f9a4d63))
    - Get_tracefs function ([`c6c4ac7`](https://github.com/aya-rs/aya/commit/c6c4ac7eeaf7e6cfa31ab0b949aa93b136eda91b))
    - Updates after rebase due to changes in define_link_wrapper ([`d43879d`](https://github.com/aya-rs/aya/commit/d43879d99177c33c5d33827d8a3c7572841dd9df))
    - Remove SchedClassifierLink description ([`6766532`](https://github.com/aya-rs/aya/commit/6766532341803ab70501e0c522afc0656385e002))
    - Address review comments ([`2972d46`](https://github.com/aya-rs/aya/commit/2972d462a505aaba8d9e40ddf2c6110e497283db))
    - Address review comments ([`65f5b76`](https://github.com/aya-rs/aya/commit/65f5b76593f35b8ca09f5d868a4195086ddca831))
    - Rename SchedClassifierLink:new() to new_tc_link() ([`849796c`](https://github.com/aya-rs/aya/commit/849796c4208b520cd12a7ac5de28857dc885c026))
    - Additional edits to SchedClassifierLink documentation. ([`67efc33`](https://github.com/aya-rs/aya/commit/67efc33414df049853247e344dfaa37eeeafe602))
    - Combine updates to SchedClassifierLink example made by Dave Tucker ([`6563e6c`](https://github.com/aya-rs/aya/commit/6563e6cc065d01270aad50d9c3449f9deb9f04d6))
    - Add example for SchedClassifierLink::new() ([`c3a8400`](https://github.com/aya-rs/aya/commit/c3a8400e4d219eb72167ccaeb500d36ad924873d))
    - Support reconstruction of `SchedClassifierLink` ([`f46fd17`](https://github.com/aya-rs/aya/commit/f46fd17cc31f7f900f01d8e97baebe6445c468d4))
    - Expose inner errors ([`1899d5f`](https://github.com/aya-rs/aya/commit/1899d5f4fd3ec5d91e40a94d671a7756125a4487))
    - Merge pull request #484 from vadorovsky/update-tokio ([`bea0e83`](https://github.com/aya-rs/aya/commit/bea0e83512cc6d45b3e4fb5c3f62432c434139b7))
    - Update Tokio and inventory ([`dad75f4`](https://github.com/aya-rs/aya/commit/dad75f45ac357e86eebc92c4f95f6dd4e43d8496))
    - Merge pull request #475 from yesh0/aya-obj ([`897957a`](https://github.com/aya-rs/aya/commit/897957ac84370cd1ee463bdf2ff4859333b41012))
    - Update documentation and versioning info ([`9c451a3`](https://github.com/aya-rs/aya/commit/9c451a3357317405dd8e2e4df7d006cee943adcc))
    - Add basic documentation to public members ([`e52497c`](https://github.com/aya-rs/aya/commit/e52497cb9c02123ae450ca36fb6f898d24b25c4b))
    - Migrate aya::obj into a separate crate ([`ac49827`](https://github.com/aya-rs/aya/commit/ac49827e204801079be2b87160a795ef412bd6cb))
    - Migrate bindgen destination ([`81bc307`](https://github.com/aya-rs/aya/commit/81bc307dce452f0aacbfbe8c304089d11ddd8c5e))
    - Btf relocs: don't panic on failed relocation ([`c6f93b1`](https://github.com/aya-rs/aya/commit/c6f93b177511d3dfb0ab6cce4fa298d13707dedc))
    - Make btf::RelocationError private ([`aba99ea`](https://github.com/aya-rs/aya/commit/aba99ea4b1f5694e115ae49e9dbe058d3e761fd8))
    - Fix regression computing pointer sizes ([`12e422b`](https://github.com/aya-rs/aya/commit/12e422b21134e3f4fb1949b248ecfd2afd768e53))
    - Resolve symbol address for PIE executables ([`1a22792`](https://github.com/aya-rs/aya/commit/1a22792ee75642a3998634cc16abda7d813b45bb))
    - Fix detaching links on drop ([`b3ae778`](https://github.com/aya-rs/aya/commit/b3ae7786d335fd0294a6ddecf3f31ef28d56af9d))
    - Merge pull request #461 from FallingSnow/main ([`9f5d157`](https://github.com/aya-rs/aya/commit/9f5d157628e1636390cc73fd5d21db62b1894a13))
    - Fix LpnTrieKeys -> LpmTrieKeys typo ([`10ac595`](https://github.com/aya-rs/aya/commit/10ac5957c1a01dd5a41307c45e2824cf20021dff))
    - Merge pull request #466 from bpfdeploy-io/ml/cgroup-device ([`d1919a8`](https://github.com/aya-rs/aya/commit/d1919a83ed21ec8156732b9bb34194c9c8a50bc1))
    - Fix doctest issue ([`925504f`](https://github.com/aya-rs/aya/commit/925504f230db683f2728f72577c3c7f2504b6f16))
    - Fix CI, clippy and feedback ([`4b6d97e`](https://github.com/aya-rs/aya/commit/4b6d97e4db4261921a43958366b66fa3e0da237b))
    - Add support for BPF_PROG_TYPE_CGROUP_DEVICE ([`8f1163a`](https://github.com/aya-rs/aya/commit/8f1163a400b13010acf5353ddc43e9b81ca61d7a))
    - Fix formatting ([`a44f054`](https://github.com/aya-rs/aya/commit/a44f054bec60c64c5254a9799ae0c92683dd8889))
    - Merge pull request #460 from Tuetuopay/owned-per-cpu-hash-map ([`66d435f`](https://github.com/aya-rs/aya/commit/66d435fc7c6cf55a64263de3263f9864762f4f92))
    - Remove old test ([`1368eb9`](https://github.com/aya-rs/aya/commit/1368eb94e7609e477a503da5b9fe94ed0f3cea93))
    - Add ability to iterate over lpmtrie key matches ([`9a3682e`](https://github.com/aya-rs/aya/commit/9a3682e793e02ce16c83e5ba8dcfa89f44d6b434))
    - Fix lpmtrie iter returning nothing ([`8fe64ae`](https://github.com/aya-rs/aya/commit/8fe64aef1fa13cc2796ab62889526745203cd579))
    - Add missing TryFrom<Map> for HashMap, PerCpuHashMap and LpmTrie ([`51bb50e`](https://github.com/aya-rs/aya/commit/51bb50ed8e9726723b395515374053e59cd4c402))
    - Iterate lpmtrie ([`e4182a9`](https://github.com/aya-rs/aya/commit/e4182a9eabe157e7b506111b0dda2d0dc15f0d8d))
    - Merge pull request #456 from dmitris/uninlined_format_args ([`16b029e`](https://github.com/aya-rs/aya/commit/16b029ed3708470afd2a6d67615b30c8d30b5059))
    - Fix uninlined_format_args clippy issues ([`055d94f`](https://github.com/aya-rs/aya/commit/055d94f58be4f80ada416b99278a22f600c71285))
    - Merge pull request #450 from aya-rs/dependabot/cargo/object-0.30 ([`1ded0e6`](https://github.com/aya-rs/aya/commit/1ded0e61cd9d49007408584210c51521be2aad5f))
    - Update object requirement from 0.29 to 0.30 ([`1fe7bba`](https://github.com/aya-rs/aya/commit/1fe7bba070cc74008cc8165030b01336cb9acbe1))
    - Merge pull request #452 from vadorovsky/fix-lint ([`9382de7`](https://github.com/aya-rs/aya/commit/9382de75cc4cbf6e115a96fb33a40137fd70476a))
    - Fix clippy error ([`176d61a`](https://github.com/aya-rs/aya/commit/176d61ae23c3977a8f2b6c9a41286604ebe9280e))
    - Merge pull request #418 from anfredette/tc-handle ([`7fef833`](https://github.com/aya-rs/aya/commit/7fef833e3a94aef9eba7c9fa0f83e3fc9ba0e1ea))
    - Make doc fixes ([`abb75ba`](https://github.com/aya-rs/aya/commit/abb75ba0293ca7b68abeff3d670dadc5997eb959))
    - Merge pull request #431 from 0b01/refs ([`88d7777`](https://github.com/aya-rs/aya/commit/88d77775530341ec32ff4f764b729e53a48c0de0))
    - Fix formatting ([`76e417a`](https://github.com/aya-rs/aya/commit/76e417a474ca6f89956dd3834e387928c328b44c))
    - Support both attach() and attach_with_options() for SchedClassifier ([`a3e3e80`](https://github.com/aya-rs/aya/commit/a3e3e806986b6c3761b1072626825d7f58376c50))
    - Merge pull request #435 from vadorovsky/pin-fix-error-msg ([`3e089a6`](https://github.com/aya-rs/aya/commit/3e089a61d19955440bdbd77d2ab62a2f68ccf99f))
    - Fix the error message in `MapData::pin()` ([`e0a9895`](https://github.com/aya-rs/aya/commit/e0a98952601bf8244a1f046a106b6419313537b6))
    - Make sure everything is marked correctly ([`6ce60ad`](https://github.com/aya-rs/aya/commit/6ce60ad21da48d98a47442d234b94e60b1449008))
    - Fix array ([`9525b1a`](https://github.com/aya-rs/aya/commit/9525b1a370a0f3123bf97b31040ca6d07d315ef3))
    - Fix wrong bounds ([`575fea4`](https://github.com/aya-rs/aya/commit/575fea4cb9a19540de82283855fb84fad8113dfd))
    - Cargo fmt ([`fbfbedb`](https://github.com/aya-rs/aya/commit/fbfbedb6a89825bec107b2f0b8fc6fed8042321d))
    - Use & ([`9991ffb`](https://github.com/aya-rs/aya/commit/9991ffb093bff3a10678c48f8c4c7610558ab809))
    - Add test case ([`e9ec257`](https://github.com/aya-rs/aya/commit/e9ec257328299551a750883075095f8a60f1cce3))
    - Use Borrow<T> instead ([`1247ffc`](https://github.com/aya-rs/aya/commit/1247ffc19b8d68d37c032a7b916e3f2b3531972f))
    - Use a struct for setting priority and handle in SchedClassfier attach ([`af3de84`](https://github.com/aya-rs/aya/commit/af3de84b081941bd3139c7089618a53dfa37ac83))
    - Support using handle in tc programs ([`ac07608`](https://github.com/aya-rs/aya/commit/ac07608b7922a545cd1de1996b66dcbdeb7fbbe1))
    - Merge pull request #397 from astoycos/refactor-map-api2 ([`d6cb1a1`](https://github.com/aya-rs/aya/commit/d6cb1a16ad0f8df483e2234fb01ab55bdbeaa8b8))
    - Fix doc links, update rustdoc args ([`82edd68`](https://github.com/aya-rs/aya/commit/82edd681c398f73de026a695837dd37643ed124a))
    - Make map APIs return an option ([`f3262e8`](https://github.com/aya-rs/aya/commit/f3262e87bd6ff895537df47fcf5d17c598e564cc))
    - Fixups4 ([`4ddf260`](https://github.com/aya-rs/aya/commit/4ddf2600b4084d224d66810f8372f42354dc40e0))
    - Fixups 3 ([`440097d`](https://github.com/aya-rs/aya/commit/440097d7bc671c78fa33d13f890c3aa456530306))
    - Fixups 2 ([`939d16c`](https://github.com/aya-rs/aya/commit/939d16cce5dcfeaebc5d571d21127105fc886186))
    - Fixups ([`8009361`](https://github.com/aya-rs/aya/commit/8009361694a7f8967a31734d109f79a6b26516dc))
    - Implement Copy for MapData ([`893f9f4`](https://github.com/aya-rs/aya/commit/893f9f44a22d4c78d86107cdac1204c4da65938a))
    - Use SockMapFd ([`898a14d`](https://github.com/aya-rs/aya/commit/898a14d42559c7567f45e43fccdaa741a3ac9f27))
    - Core refactor of Map API ([`1aefa2e`](https://github.com/aya-rs/aya/commit/1aefa2e5e6d22a600cc7339d289d64ab06f842e3))
    - Merge branch 'aya-rs:main' into integration-tests-cli-options ([`4183c7a`](https://github.com/aya-rs/aya/commit/4183c7a7d21c655b71c6a62998d71d7ffe653f53))
    - Merge pull request #411 from abhijeetbhagat/fix-warnings ([`94bc93e`](https://github.com/aya-rs/aya/commit/94bc93ea07664c682198389d42a14bfe58367967))
    - Fix all clippy warnings ([`6c813b8`](https://github.com/aya-rs/aya/commit/6c813b8c38a172e8372d7009b50029d1cb8513e4))
    - Merge pull request #406 from dave-tucker/unused-deps ([`57ab0d7`](https://github.com/aya-rs/aya/commit/57ab0d7978e211b16fece64be25edef28ab9441a))
    - Remove unused dependencies ([`ec2bd69`](https://github.com/aya-rs/aya/commit/ec2bd690532cc21b22e07cfa1539a195bf5e149c))
    - Merge pull request #404 from dave-tucker/async-docs ([`14ba644`](https://github.com/aya-rs/aya/commit/14ba644aa5ac4263062d6249420fb07b36ca5080))
    - Add labels for optional features ([`95e8c78`](https://github.com/aya-rs/aya/commit/95e8c78db8fef4fcc12a9cbf0a52753049070e4b))
    - Merge pull request #398 from vadorovsky/fix-miri ([`3f2f3a8`](https://github.com/aya-rs/aya/commit/3f2f3a8be038edd8944823b11ff772e924d3d962))
    - Disable miri warnings about integer-to-pointer conversions ([`43aff57`](https://github.com/aya-rs/aya/commit/43aff5779390881d785a4d1c0d6c7bd681381dfe))
    - Avoid integer to pointer casts ([`2432677`](https://github.com/aya-rs/aya/commit/2432677b2bafcfa4028f9315f6754b14c070b4dd))
    - Merge pull request #393 from aztecher/impl-set_max_entries ([`a93a975`](https://github.com/aya-rs/aya/commit/a93a975cc63e4e47542289b8c9d8fb83fa135ef9))
    - Add BpfLoader::set_max_entries ([`2eccf1d`](https://github.com/aya-rs/aya/commit/2eccf1d57da4c9bfa1ea4c0802bc34905c9b1f72))
    - Merge pull request #394 from vadorovsky/clippy ([`6eca4f5`](https://github.com/aya-rs/aya/commit/6eca4f570990e0334281560be969505380445688))
    - Fix clippy warnings ([`5a4b5ff`](https://github.com/aya-rs/aya/commit/5a4b5ff8d8bf8d3f36cb784d9e3af5284e388433))
    - Merge pull request #391 from dave-tucker/fix-387 ([`e696389`](https://github.com/aya-rs/aya/commit/e696389837c1625de9f58ad9f77c56ecfb268b0c))
    - Rename from_pinned and from_path to from_pin ([`5693fb9`](https://github.com/aya-rs/aya/commit/5693fb994123b88eb856af83c5b8f79afd1d789f))
    - Fix review comments from #387 ([`de6fa98`](https://github.com/aya-rs/aya/commit/de6fa98963b7c5a311aafec6afe956ff716d68c5))
    - Merge pull request #387 from astoycos/map-from-prog ([`eb26a6b`](https://github.com/aya-rs/aya/commit/eb26a6b116885fa19294c944080b42408f49bd30))
    - Add `from_pinned` and `from_fd` methods ([`8a9cbf1`](https://github.com/aya-rs/aya/commit/8a9cbf179f62b68def7d30612cdffb576d062baa))
    - Merge pull request #378 from dave-tucker/pin-fixes-again ([`98e25ca`](https://github.com/aya-rs/aya/commit/98e25ca5e6550526d35f783d74e6276f7aaf8a71))
    - Add integration test for pinning lifecycle ([`7c244e1`](https://github.com/aya-rs/aya/commit/7c244e1f65fdb80f65c6a317773f3ff069255cd8))
    - Replace From<FdLink> for XdpLink with TryFrom ([`f961cbb`](https://github.com/aya-rs/aya/commit/f961cbb3d43693e21a9c633d8b581c8a24fa7055))
    - Rename bpf_obj_get_info_by_id ([`6af2053`](https://github.com/aya-rs/aya/commit/6af2053cf3fd36522642169710d2804feb1e20a5))
    - Merge pull request #376 from conectado/verifier-log-level ([`fe22b02`](https://github.com/aya-rs/aya/commit/fe22b0210894e7f383566110f094acf6a738125e))
    - Fix miss doc period ([`3bed2c2`](https://github.com/aya-rs/aya/commit/3bed2c2b94a47503ba32e9879c7a29fe9f8e9227))
    - Change  variant names ([`c30ae6e`](https://github.com/aya-rs/aya/commit/c30ae6e0010adda3d3e3de792cf2919f3c1dcf32))
    - More pinning fixes ([`4b5b9ab`](https://github.com/aya-rs/aya/commit/4b5b9ab3d92befe967709ad6cc55264fc0541b73))
    - Merge pull request #384 from aya-rs/codegen ([`7b99a57`](https://github.com/aya-rs/aya/commit/7b99a5733084d4638e74327901bb442ce8b4333b))
    - [codegen] Update libbpf to efd33720cdf4a0049323403df5daad0e9e894b3dUpdate libbpf to efd33720cdf4a0049323403df5daad0e9e894b3d ([`ed849ff`](https://github.com/aya-rs/aya/commit/ed849ffd18fd360fef9b5bfa636054a5f18f0170))
    - Merge pull request #381 from aya-rs/codegen ([`49c5a94`](https://github.com/aya-rs/aya/commit/49c5a94aa0198897a9aef9a1cad4523bb63c56ee))
    - [codegen] Update libbpf to efd33720cdf4a0049323403df5daad0e9e894b3dUpdate libbpf to efd33720cdf4a0049323403df5daad0e9e894b3d ([`8e96011`](https://github.com/aya-rs/aya/commit/8e96011c2da245090f8b8603bf6d57cf7c5902a4))
    - Merge pull request #379 from dave-tucker/fix-link-segfault ([`9451699`](https://github.com/aya-rs/aya/commit/945169996c435815f0b9ef1a591c17a6fbec5a0d))
    - Fix segfault in define_link_wrapper ([`18584e2`](https://github.com/aya-rs/aya/commit/18584e2259382bbb4e56007eacbe81dba25db05a))
    - Merge pull request #285 from dave-tucker/btf-redux ([`66b4f79`](https://github.com/aya-rs/aya/commit/66b4f79ecafe9832fcc1e44373598774b9954514))
    - Improved BTF Type API ([`f34ebeb`](https://github.com/aya-rs/aya/commit/f34ebeba99e409bb369a74687e1664a50c430c1e))
    - Update `VerifierLogLevel` to use bitflags ([`7b14319`](https://github.com/aya-rs/aya/commit/7b143199fb61edd168f3efc860a8e8c1d4cd9136))
    - Merge pull request #366 from dave-tucker/pin-redux-2 ([`4826bf7`](https://github.com/aya-rs/aya/commit/4826bf7f748722724536c7f9bbc3234262e35128))
    - Fix Link Pinning ([`4c1d645`](https://github.com/aya-rs/aya/commit/4c1d645aa6e8150b50007ff42eb17e270a5b80af))
    - Merge pull request #371 from conectado/verifier-log-level ([`b95adc3`](https://github.com/aya-rs/aya/commit/b95adc3135f9b9cc74d16052250b5d8611caf9dc))
    - Update `VerifierLogLevel` level variants ([`a602525`](https://github.com/aya-rs/aya/commit/a6025255f56a941c2614d8bbf395e07b47588b75))
    - Use enum to set verifier log level ([`edd8039`](https://github.com/aya-rs/aya/commit/edd80397dce46f6e2a4cc96bd951562987721e55))
    - Expose BPF verifier log level configuration ([`3211646`](https://github.com/aya-rs/aya/commit/3211646aef48c7d388941a4a9e932e66bec87fd6))
    - Change from Rust edition 2018 to 2021 ([`944d6b8`](https://github.com/aya-rs/aya/commit/944d6b8a1647df36c17cd060b15c37ac9615f4a7))
    - Add support for setting priority for classifier programs ([`207c689`](https://github.com/aya-rs/aya/commit/207c689f560de2963210d245ae718b1f09d9eaae))
    - Merge pull request #355 from dave-tucker/rm-map-pin-path ([`55a7e3c`](https://github.com/aya-rs/aya/commit/55a7e3c4d0b92bc19ccb9705358b95a1f4bf448c))
    - Remove MapError::InvalidPinPath ([`03a15b9`](https://github.com/aya-rs/aya/commit/03a15b98643a520269197e5db98cc48715a61577))
    - Merge pull request #343 from dave-tucker/pinning-redux ([`8e6c9ad`](https://github.com/aya-rs/aya/commit/8e6c9ad0d279fd127f2453b948b6306600eb566d))
    - Use PinError for all pinning errors ([`34ba2bc`](https://github.com/aya-rs/aya/commit/34ba2bc0482f9a16bc9c7ad138e9288c66e4bac4))
    - Implement FdLink::pin() ([`64f8a43`](https://github.com/aya-rs/aya/commit/64f8a434d2a337578bde86c1983f46a3282e7f53))
    - Allow pin to be used on all programs ([`5726b6d`](https://github.com/aya-rs/aya/commit/5726b6d044011b462b04e533f881e0dd26d60d0f))
    - Merge pull request #350 from dave-tucker/monorepo ([`f37a514`](https://github.com/aya-rs/aya/commit/f37a51433ff5283205ba5d1e74cdc75fbdeea160))
    - Fix rlimit warning on for 32bit systems ([`c9e70a8`](https://github.com/aya-rs/aya/commit/c9e70a8758ef10cfe1970e5f7a1e830e0ba5ec8e))
    - Merge pull request #140 from dave-tucker/btf-maps ([`73ee3cf`](https://github.com/aya-rs/aya/commit/73ee3cff70db51d5bb2d4934c2767a1ab2f13eda))
    - Support BTF Maps ([`f976229`](https://github.com/aya-rs/aya/commit/f97622947706a8efd06546c45860cc60cfe41a13))
    - Merge pull request #344 from vadorovsky/rlimit-v2 ([`fa4347a`](https://github.com/aya-rs/aya/commit/fa4347aae4251f30f583cfa198584392b3853087))
    - Raise the RLIMIT_MEMLOCK warning only if failed to create a map ([`3d592d0`](https://github.com/aya-rs/aya/commit/3d592d0f295b0a2c385e200bb0224c57c144f5ea))
    - Merge pull request #342 from vadorovsky/rlimit ([`a7fa938`](https://github.com/aya-rs/aya/commit/a7fa938f1e96c81e941eaf543e8acef03bbcfc52))
    - Raise the warning when RMILIT_MEMLOCK is not RLIM_INFINITY ([`bebe98e`](https://github.com/aya-rs/aya/commit/bebe98e6706ec4c149508f8aabdd44707d1c6d73))
    - Merge pull request #336 from dave-tucker/clippy ([`6188c9d`](https://github.com/aya-rs/aya/commit/6188c9dee34ef603ca04cc7cf5b113a9e96c37d2))
    - Fix latest nightly lints ([`336faf5`](https://github.com/aya-rs/aya/commit/336faf553e1ef8d21298a4f6e9835a22e29904ad))
    - Merge pull request #330 from aya-rs/dependabot/cargo/object-0.29 ([`f2fb211`](https://github.com/aya-rs/aya/commit/f2fb2116344e3fed10cff1dd1a1474971204e799))
    - Update object requirement from 0.28 to 0.29 ([`661a215`](https://github.com/aya-rs/aya/commit/661a21570f1154f4ae32c81a8a142913f7deec86))
    - Merge pull request #328 from drewkett/map-update-no-key ([`a301a56`](https://github.com/aya-rs/aya/commit/a301a563167d27498c2eda1a9a87d07ba6475024))
    - Merge pull request #282 from dave-tucker/bpfd ([`e5f455f`](https://github.com/aya-rs/aya/commit/e5f455f238e930dff476087085ba847bb82eca87))
    - Improve Extension Docs ([`004f3dd`](https://github.com/aya-rs/aya/commit/004f3dd6644b0c0a2ff1e877093a5ee0610eb830))
    - Add Extension::attach_to_program() ([`9e85b92`](https://github.com/aya-rs/aya/commit/9e85b923230bd1db18fb87a3a6bc4a5c60a6b405))
    - Replace ProgramFd trait with struct ([`b441332`](https://github.com/aya-rs/aya/commit/b4413322e3730b183546fcfdfc4b12f0ffce4a9c))
    - Implement attach_to_link for XDP ([`fd52bfe`](https://github.com/aya-rs/aya/commit/fd52bfeadc70020e4111bb4dda0ca4e361c3be43))
    - Add support for bpf_link_update ([`ccb1897`](https://github.com/aya-rs/aya/commit/ccb189784f87d58bc397b22c04e976cabcbd8e00))
    - Have bpf_map_update_elem take Option<&K> for key ([`36edf09`](https://github.com/aya-rs/aya/commit/36edf092541574633ff03f7deb8b95003b2bcdd2))
    - Add Map::fd() function to return a MapFd ([`623579a`](https://github.com/aya-rs/aya/commit/623579a47f1fd169ba9503bd71550c3fcce76b21))
    - Merge pull request #320 from dave-tucker/moar-crabby-docs ([`ed3b690`](https://github.com/aya-rs/aya/commit/ed3b690a6d0638eaa563704c9be45559205cffeb))
    - Add crabby, sync with aya/README.md ([`2b98259`](https://github.com/aya-rs/aya/commit/2b98259be73865cf6b213de1b73d0b7b0086a22f))
    - Add crabby logo ([`713cd4e`](https://github.com/aya-rs/aya/commit/713cd4e858d9474318104b2a1e4dee0a25e8c67a))
    - Merge pull request #315 from dave-tucker/sock ([`7549eb9`](https://github.com/aya-rs/aya/commit/7549eb979c39555215edfc58fbf94cdf735dc949))
    - Implement BPF_PROG_TYPE_CGROUP_SOCK ([`7b21a2d`](https://github.com/aya-rs/aya/commit/7b21a2d17eac57696352b2519bd76a4c7e9b1a2b))
    - Unload programs on drop ([`0cd1e51`](https://github.com/aya-rs/aya/commit/0cd1e514763fd99dc287128317e9a36312ff6883))
</details>

## v0.11.0 (2022-06-06)

<csr-id-b2a6f00212997a997799c88ba9022a69d9a0b582/>
<csr-id-2226b89ceb94ea29beb71376c43f371d2830ef61/>
<csr-id-824baf9d642424b891ae8380cc3741fffe795123/>
<csr-id-4a32e7d985de5b55f263cf9244791debb34cc00f/>
<csr-id-ba312c48d561b5a414cdd1301c322266e38118a4/>
<csr-id-af54b6c818c4f08d599df82beeb3661b8e26ca48/>
<csr-id-8069ad14d0baad310f52b9f1f5a651b77566310f/>
<csr-id-cdaa3af5ae12161e12db438282912f7b027ea277/>
<csr-id-d1f22151935edebed13e0baaa04f25a96ddb30f0/>
<csr-id-4e57d1fe32763f3016a454941b8295ece4b36f9e/>
<csr-id-cb57d10d25611a35b2cc34523d95b9f331470958/>
<csr-id-f357be7db45b7201be6864e83fb7eb7e78cd984a/>
<csr-id-ad1636d2e795212ed6e326bd7df0fc60794be115/>

### Other

 - <csr-id-b2a6f00212997a997799c88ba9022a69d9a0b582/> Rename forget_link to take_link
 - <csr-id-2226b89ceb94ea29beb71376c43f371d2830ef61/> Add support for BPF_PROG_TYPE_SK_LOOKUP
 - <csr-id-824baf9d642424b891ae8380cc3741fffe795123/> Export program modules
   This allows access to XdpLink, XdpLinkId etc... which is currently
   unavailable since these modules are private
 - <csr-id-4a32e7d985de5b55f263cf9244791debb34cc00f/> fix new lints on nightly
 - <csr-id-ba312c48d561b5a414cdd1301c322266e38118a4/> Add all crates to sidebar
 - <csr-id-af54b6c818c4f08d599df82beeb3661b8e26ca48/> Add BPF_PROG_TYPE_CGROUP_SOCK_ADDR
 - <csr-id-8069ad14d0baad310f52b9f1f5a651b77566310f/> Implement forget_link
 - <csr-id-cdaa3af5ae12161e12db438282912f7b027ea277/> Fix lint against latest nightly
 - <csr-id-d1f22151935edebed13e0baaa04f25a96ddb30f0/> Relocate maps using symbol_index
   Since we support multiple maps in the same section, the section_index is
   no longer a unique way to identify maps. This commit uses the symbol
   index as the identifier, but falls back to section_index for rodata
   and bss maps since we don't retrieve the symbol_index during parsing.
 - <csr-id-4e57d1fe32763f3016a454941b8295ece4b36f9e/> revert version to 0.10.7
   The world isn't ready to have pre-releases in git
 - <csr-id-cb57d10d25611a35b2cc34523d95b9f331470958/> rework links
   Remove LinkRef and remove the Rc<RefCell<_>> that was used to store
   type-erased link values in ProgramData. Among other things, this allows
   `Bpf` to be `Send`, which makes it easier to use it with async runtimes.
   
   Change the link API to:
   
       let link_id = prog.attach(...)?;
       ...
       prog.detach(link_id)?;
   
   Link ids are strongly typed, so it's impossible to eg:
   
       let link_id = uprobe.attach(...)?;
       xdp.detach(link_id);
   
   As it would result in a compile time error.
   
   Links are still stored inside ProgramData, and unless detached
   explicitly, they are automatically detached when the parent program gets
   dropped.
 - <csr-id-f357be7db45b7201be6864e83fb7eb7e78cd984a/> Support multiple maps in map sections
   This commit uses the symbol table to discover all maps inside an ELF
   section. Instead of doing what libbpf does - divide the section data
   in to equal sized chunks - we read in to section data using the
   symbol address and offset, thus allowing us to support definitions
   of varying lengths.
 - <csr-id-ad1636d2e795212ed6e326bd7df0fc60794be115/> perf_buffer: call BytesMut::reserve() internally
   This changes PerfBuffer::read_events() to call BytesMut::reserve()
   internally, and deprecates PerfBufferError::MoreSpaceNeeded.
   
   This makes for a more ergonomic API, and allows for a more idiomatic
   usage of BytesMut. For example consider:
   
       let mut buffers = vec![BytesMut::with_capacity(N), ...];
       loop {
           let events = oob_cpu_buf.read_events(&mut buffers).unwrap();
           for buf in &mut buffers[..events.read] {
               let sub: Bytes = buf.split_off(n).into();
               process_sub_buf(sub);
           }
           ...
       }
   
   This is a common way to process perf bufs, where a sub buffer is split
   off from the original buffer and then processed. In the next iteration
   of the loop when it's time to read again, two things can happen:
   
   - if processing of the sub buffer is complete and `sub` has been
   dropped, read_events() will call buf.reserve(sample_size) and hit a fast
   path in BytesMut that will just restore the original capacity of the
   buffer (assuming sample_size <= N).
   
   - if processing of the sub buffer hasn't ended (eg the buffer has been
   stored or is being processed in another thread),
   buf.reserve(sample_size) will actually allocate the new memory required
   to read the sample.
   
   In other words, calling buf.reserve(sample_size) inside read_events()
   simplifies doing zero-copy processing of buffers in many cases.

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 45 commits contributed to the release over the course of 57 calendar days.
 - 79 days passed between releases.
 - 13 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 3 unique issues were worked on: [#256](https://github.com/aya-rs/aya/issues/256), [#264](https://github.com/aya-rs/aya/issues/264), [#268](https://github.com/aya-rs/aya/issues/268)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#256](https://github.com/aya-rs/aya/issues/256)**
    - Add support for BPF_PROG_TYPE_CGROUP_SYSCTL ([`f721021`](https://github.com/aya-rs/aya/commit/f721021a0af2a31d9f7c8d63100fbaa6b23a4b1e))
 * **[#264](https://github.com/aya-rs/aya/issues/264)**
    - Program unload API ([`e2685c9`](https://github.com/aya-rs/aya/commit/e2685c98d8ff976610efea019d23d2f584f577c2))
 * **[#268](https://github.com/aya-rs/aya/issues/268)**
    - Add support for BPF_PROG_TYPE_CGROUP_SOCKOPT ([`e68d734`](https://github.com/aya-rs/aya/commit/e68d734c68c9adb5269c0174cd06d416d5e0f5fe))
 * **Uncategorized**
    - (cargo-release) version 0.11.0 ([`d85b36f`](https://github.com/aya-rs/aya/commit/d85b36f6d80236f142395f1ab173acbed74af99b))
    - Merge pull request #306 from dave-tucker/take_link ([`4ae5bc4`](https://github.com/aya-rs/aya/commit/4ae5bc4b9b4b41c04b15b74b3293df217f55c6f1))
    - Rename forget_link to take_link ([`b2a6f00`](https://github.com/aya-rs/aya/commit/b2a6f00212997a997799c88ba9022a69d9a0b582))
    - Merge pull request #296 from aya-rs/codegen ([`de8ab7f`](https://github.com/aya-rs/aya/commit/de8ab7f4153041a34f3c5d876b1d9b6fdf062110))
    - [codegen] Update libbpf to 4eb6485c08867edaa5a0a81c64ddb23580420340Update libbpf to 4eb6485c08867edaa5a0a81c64ddb23580420340 ([`bbb34b3`](https://github.com/aya-rs/aya/commit/bbb34b328587faf41a0aba42ff7eb9a785149028))
    - Merge pull request #286 from nak3/add-BPF_MAP_TYPE_BLOOM_FILTER ([`1633700`](https://github.com/aya-rs/aya/commit/16337001e4f7140ab33d84368027cf5cdea658a0))
    - Fix typo, take & to query the value ([`c192817`](https://github.com/aya-rs/aya/commit/c192817a59fe33f52819ec235cefbf6cda353086))
    - Merge pull request #265 from dave-tucker/sklookup ([`a047354`](https://github.com/aya-rs/aya/commit/a0473548ca045be8b0f00b9b430b00a7350c6128))
    - Add support for BPF_PROG_TYPE_SK_LOOKUP ([`2226b89`](https://github.com/aya-rs/aya/commit/2226b89ceb94ea29beb71376c43f371d2830ef61))
    - Add support for BPF_MAP_TYPE_BLOOM_FILTER ([`c4262f7`](https://github.com/aya-rs/aya/commit/c4262f793dbce8558c5823a94db257ac227a5a0b))
    - Merge pull request #281 from dave-tucker/export ([`7d8365c`](https://github.com/aya-rs/aya/commit/7d8365c3513532300b21fb80987835cb24e3402c))
    - Export program modules ([`824baf9`](https://github.com/aya-rs/aya/commit/824baf9d642424b891ae8380cc3741fffe795123))
    - Merge pull request #279 from aya-rs/codegen ([`de1559a`](https://github.com/aya-rs/aya/commit/de1559ab7759bd941d7f4a3a3ba373d99a3ac77a))
    - [codegen] Update libbpf to 47595c2f08aece55baaf21ed0b72f5c5abf2cb5eUpdate libbpf to 47595c2f08aece55baaf21ed0b72f5c5abf2cb5e ([`4767664`](https://github.com/aya-rs/aya/commit/4767664d5d78c854b143669d489e3a90d2cbaf74))
    - Merge pull request #278 from dave-tucker/riscv ([`b71fe64`](https://github.com/aya-rs/aya/commit/b71fe64a105589c806609e1f755171e77e673085))
    - Riscv scaffolding for codegen ([`edaa70b`](https://github.com/aya-rs/aya/commit/edaa70b5ba2427ef9496732ff46f5526eab02a4d))
    - Merge pull request #276 from dave-tucker/clippy ([`0d7fb44`](https://github.com/aya-rs/aya/commit/0d7fb4472d72f468b4c438c0e6967b99d3ac81f2))
    - Fix new lints on nightly ([`4a32e7d`](https://github.com/aya-rs/aya/commit/4a32e7d985de5b55f263cf9244791debb34cc00f))
    - Merge pull request #273 from dave-tucker/fix_sidebar ([`9904237`](https://github.com/aya-rs/aya/commit/9904237ac1f7dba7ef5d39d6127cdf8c591235cd))
    - Add all crates to sidebar ([`ba312c4`](https://github.com/aya-rs/aya/commit/ba312c48d561b5a414cdd1301c322266e38118a4))
    - Merge pull request #263 from nak3/cgroup-skb-attach-type ([`63b6286`](https://github.com/aya-rs/aya/commit/63b6286bd92382da90b28fd23f6fe35ed932ea28))
    - Merge pull request #267 from aya-rs/codegen ([`aacf6ec`](https://github.com/aya-rs/aya/commit/aacf6ec110b1b9a59a5d3e00f022a040088e32fb))
    - [codegen] Update libbpf to 86eb09863c1c0177e99c2c703092042d3cdba910Update libbpf to 86eb09863c1c0177e99c2c703092042d3cdba910 ([`7f7c78a`](https://github.com/aya-rs/aya/commit/7f7c78ad6b4bb619c209e9e724aeed8d9ea9a00c))
    - Use map() ([`5d22869`](https://github.com/aya-rs/aya/commit/5d228695a46ebcde0e2e351f7b8f691daa3634ea))
    - Merge pull request #261 from dave-tucker/cgroup_sock ([`8fd8816`](https://github.com/aya-rs/aya/commit/8fd8816dfdf2951017e6ee79aa6d0f2dc39c6edb))
    - Add BPF_PROG_TYPE_CGROUP_SOCK_ADDR ([`af54b6c`](https://github.com/aya-rs/aya/commit/af54b6c818c4f08d599df82beeb3661b8e26ca48))
    - Set attach type during load for BPF_PROG_TYPE_CGROUP_SKB ([`29c10fa`](https://github.com/aya-rs/aya/commit/29c10fafb70148c32b978185622214318ac5ea66))
    - Merge pull request #253 from dave-tucker/forget ([`2fca4ae`](https://github.com/aya-rs/aya/commit/2fca4aee4e98b78c928be0c7aeb4c2166d93548a))
    - Implement forget_link ([`8069ad1`](https://github.com/aya-rs/aya/commit/8069ad14d0baad310f52b9f1f5a651b77566310f))
    - Merge pull request #254 from dave-tucker/clippy ([`e71e07f`](https://github.com/aya-rs/aya/commit/e71e07f88e634157dbb9b8f863d52603447a557d))
    - Fix lint against latest nightly ([`cdaa3af`](https://github.com/aya-rs/aya/commit/cdaa3af5ae12161e12db438282912f7b027ea277))
    - Merge pull request #252 from dave-tucker/multimap-relo ([`4afc5ea`](https://github.com/aya-rs/aya/commit/4afc5ea7117c99d5fc16f5646344c984537f15d6))
    - Relocate maps using symbol_index ([`d1f2215`](https://github.com/aya-rs/aya/commit/d1f22151935edebed13e0baaa04f25a96ddb30f0))
    - Revert version to 0.10.7 ([`4e57d1f`](https://github.com/aya-rs/aya/commit/4e57d1fe32763f3016a454941b8295ece4b36f9e))
    - Merge pull request #251 from aya-rs/codegen ([`e1f448e`](https://github.com/aya-rs/aya/commit/e1f448e6b715505fbf83baea257addf49a23e413))
    - [codegen] Update libbpf to 3a4e26307d0f9b227e3ebd28b443a1a715e4e17dUpdate libbpf to 3a4e26307d0f9b227e3ebd28b443a1a715e4e17d ([`d6ca3e1`](https://github.com/aya-rs/aya/commit/d6ca3e1ae71c4081a98c3e6d4564cc68cfaa5817))
    - Merge pull request #249 from alessandrod/new-links ([`b039ac5`](https://github.com/aya-rs/aya/commit/b039ac524e2ba732f48f1117f14eb9c69299e6a5))
    - Rework links ([`cb57d10`](https://github.com/aya-rs/aya/commit/cb57d10d25611a35b2cc34523d95b9f331470958))
    - Merge pull request #181 from dave-tucker/multimap ([`5472ac0`](https://github.com/aya-rs/aya/commit/5472ac035463e2d60e11f05a21f606f5242d2357))
    - Support multiple maps in map sections ([`f357be7`](https://github.com/aya-rs/aya/commit/f357be7db45b7201be6864e83fb7eb7e78cd984a))
    - Merge pull request #243 from alessandrod/perf-reserve ([`a1d4499`](https://github.com/aya-rs/aya/commit/a1d4499967d8949aad9cd4b4e07f7478d0c3ee9b))
    - Perf_buffer: call BytesMut::reserve() internally ([`ad1636d`](https://github.com/aya-rs/aya/commit/ad1636d2e795212ed6e326bd7df0fc60794be115))
</details>

## v0.10.7 (2022-03-19)

<csr-id-07e3824aa4972fee73bbb0c9e3b96a417615aafb/>
<csr-id-9a642d373f3bd3b96b1e0a031388a8161cae5143/>
<csr-id-7dd2e3d1f87559636ba33a7bbb76e57f20d43e8e/>
<csr-id-5ee13217652216a3a01c82dd7d8a79ea8502ca12/>
<csr-id-08211f6132fd93493267e853139f5f5724e093b0/>
<csr-id-ab7eed2759d062fbe267e7e96f84c7a3f477ef11/>
<csr-id-f169a3fc6bb203d2a41de449472c1115b49ffe15/>
<csr-id-8202105b7dd415fc028050daada44a75d2ed7202/>
<csr-id-825bb3ad2044e186f873acbbb0a53de8d2b6e6cc/>
<csr-id-99fa85eab899c807c76274663240a19b4df41371/>
<csr-id-326825aab0b54898d9eb2e5338d70c8c663ed0e3/>
<csr-id-4efc2061a8aa0c25cb648a86cdc39ca44784de94/>
<csr-id-a1b46ece05e73896250f86815c4ad6df6095797d/>
<csr-id-5d8b279265bd2715b83cbed871697bbc763a00a9/>
<csr-id-7ad0524283006fce221910df4c1817af503b5b61/>
<csr-id-9ba2e147a1a82e97849cc8b7ca524550803ec3a9/>
<csr-id-89b5dd32ede08d3aeb5a07cf980f8af8ff326445/>
<csr-id-8f9a32ff10a13d414ff95edc2f5645a7a5162732/>
<csr-id-437432cdd60bbe11e7021f52297e459fd14ff069/>
<csr-id-5d9ff70498785ea1becbc347c6798f76be11036f/>
<csr-id-686ce45f930cef68f6fdfb73dc5ebc2d259d5954/>
<csr-id-4e9bc32a3dee903f8bfe71430c03b1c664607c5d/>
<csr-id-abc8d27440de76cf5ed2ca4aa56883bc07d3afc4/>
<csr-id-83cfe56fe7690e752ebb646509bd282db227af2b/>
<csr-id-bca01580e722a20e5c6026a744c92c5423f6437b/>
<csr-id-877c76043a6d313391159523dc40046426800c43/>
<csr-id-379bb313b13dd259a26fe3513ae6784bb85291ef/>
<csr-id-2b7dda766f3b002fc96915366d560c0a279106e3/>
<csr-id-54b0c677958b07fb2a8ece28fd55251b74dcebc8/>
<csr-id-18970369e27228c45117b125724a22d8999ec1fc/>
<csr-id-f56dd0a70b36a97036eb9447efa20f0e1c93c8d7/>
<csr-id-bb8a813eefd86fbdb218174ccb7bfd2578ab9692/>
<csr-id-e4d9774bf780eee5c3740d153df0682265089307/>
<csr-id-daa7ea6d0dad1895768d3a1cdc62911b15c72a94/>
<csr-id-c7f8db9a0b4e632233561fdd075cf201ae7cccb5/>
<csr-id-1584bc47bd027455b07e456683c0fb97920a5314/>
<csr-id-f8f17a09fbf1b87d14735e015c55d387a6ed048b/>
<csr-id-761cb79fe3b9006a4091dcc7d68604b671387194/>

### Chore

 - <csr-id-07e3824aa4972fee73bbb0c9e3b96a417615aafb/> formatting

### Bug Fixes

 - <csr-id-fc0861105a632deb15b17855160e0b375d7c5305/> make maps compatible with kernel <= 4.14
   In kernel 4.15 and additional parameter was added to allow maps to have
   names but using this breaks on older kernels.
   
   This change makes it so the name is only added on kernels 4.15 and
   newer.

### Other

 - <csr-id-9a642d373f3bd3b96b1e0a031388a8161cae5143/> fix lint errors
 - <csr-id-7dd2e3d1f87559636ba33a7bbb76e57f20d43e8e/> Improve documentation of set_global method
   Use `static` instead of `const` and mention the necessity of using
   `core::ptr::read_volatile`.
 - <csr-id-5ee13217652216a3a01c82dd7d8a79ea8502ca12/> Fix Loading from cgroup/skb sections
   fa037a88e2f0820d2a64bbaae12464bf5dce083d allowed for cgroup skb programs
   that did not specify an attach direction to use the cgroup/skb section
   name per the convention established in libbpf. It did not add the
   necessary code to load programs from those sections which is added in
   this commit
 - <csr-id-08211f6132fd93493267e853139f5f5724e093b0/> implement Pod for arrays of Pod types
   If a type is POD (meaning it can be converted to a byte array), then an
   array of such type is POD.
 - <csr-id-ab7eed2759d062fbe267e7e96f84c7a3f477ef11/> update parking_lot requirement from 0.11.1 to 0.12.0
   Updates the requirements on [parking_lot](https://github.com/Amanieu/parking_lot) to permit the latest version.
   - [Release notes](https://github.com/Amanieu/parking_lot/releases)
   - [Changelog](https://github.com/Amanieu/parking_lot/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/Amanieu/parking_lot/compare/0.11.1...0.12.0)
   
   ---
   updated-dependencies:
   - dependency-name: parking_lot
     dependency-type: direct:production
   ...
 - <csr-id-f169a3fc6bb203d2a41de449472c1115b49ffe15/> fix func_info/line_info offsets
   Given the new start instruction offset, rebase func_infos and
   line_infos.
 - <csr-id-8202105b7dd415fc028050daada44a75d2ed7202/> relocate .text references
   Handle relocations against .text symbols in all instructions not just
   calls. Makes it so that let x = &some_function triggers linking of
   some_function in the current program and handles the resulting
   relocation accordingly.
   
   Among other things, enables the use of bpf_for_each_map_elem.
 - <csr-id-825bb3ad2044e186f873acbbb0a53de8d2b6e6cc/> Replace / in DATASEC before load to kernel
   This replaces the / character with a . which is allowed in the kernel
   names. Not allowing a forward slash is perhaps a kernel bug, but lets
   fix it up here as it's commonly used for Aya
 - <csr-id-99fa85eab899c807c76274663240a19b4df41371/> fix match arms
   Don't match on kind and use if let...
   Match on the BtfType
 - <csr-id-326825aab0b54898d9eb2e5338d70c8c663ed0e3/> add a test for each BTF fix
 - <csr-id-4efc2061a8aa0c25cb648a86cdc39ca44784de94/> fix borrow check errors
 - <csr-id-a1b46ece05e73896250f86815c4ad6df6095797d/> Merge Fixup and Sanitzation to single step
   Aya will now perform sanitzation and fixups in a single phase, requiring
   only one pass over the BTF. This modifies the parsed BTF in place.
 - <csr-id-5d8b279265bd2715b83cbed871697bbc763a00a9/> Fix BTF verifier output
   Currently errors can occur if the verifier output is > buffer as we get
   ENOMEM. We should only provide a log_buf if initial load failed, then
   retry up to 10 times to get full verifier output.
   
   To DRY this logic it has been moved to a function so its shared with
   program loading
 - <csr-id-7ad0524283006fce221910df4c1817af503b5b61/> fix sanitization if BTF_FUNC_GLOBAL is not supported
   The lower 16 bits were not actually being cleared.
 - <csr-id-9ba2e147a1a82e97849cc8b7ca524550803ec3a9/> fixup func protos
   If an argument has a type, it must also have a name, see btf_func_check
   in the kernel.
 - <csr-id-89b5dd32ede08d3aeb5a07cf980f8af8ff326445/> run fixup in place
 - <csr-id-8f9a32ff10a13d414ff95edc2f5645a7a5162732/> Fix name truncation
 - <csr-id-437432cdd60bbe11e7021f52297e459fd14ff069/> Truncate long program names
 - <csr-id-5d9ff70498785ea1becbc347c6798f76be11036f/> Add support for BTF_TYPE_KIND_{TAG,DECL_TAG}
   Adds support for two new BTF kinds including feature probes and BTF
   sanitization
 - <csr-id-686ce45f930cef68f6fdfb73dc5ebc2d259d5954/> Fix BTF type resolution for Arrays and Ints
   The union of `size` and `type` is unused in BTF_KIND_ARRAY.
   Type information of elements is in the btf_array struct that follows in
   the type_ field while the index type is in the index_type field.
   
   For BTF_KIND_INT, only the offset should be compared and size and
   signedness should be ignored.
 - <csr-id-4e9bc32a3dee903f8bfe71430c03b1c664607c5d/> maps: rename from_pinned() to open_pinned()
 - <csr-id-abc8d27440de76cf5ed2ca4aa56883bc07d3afc4/> Retrieve program from pinned path
 - <csr-id-83cfe56fe7690e752ebb646509bd282db227af2b/> allocate func/line_info buffers outside if
   the pointer isn't valid in the current code!
 - <csr-id-bca01580e722a20e5c6026a744c92c5423f6437b/> document the public api
 - <csr-id-877c76043a6d313391159523dc40046426800c43/> Add fixup for PTR types from Rust
 - <csr-id-379bb313b13dd259a26fe3513ae6784bb85291ef/> Add Btf::to_bytes
   This allows for parsed BTF to be re-encoded such that it could be loaded
   in to the kernel. It moves bytes_of to the utils package. We could use
   Object::bytes_of, but this requires the impl of the Pod trait on
   generated code.
 - <csr-id-2b7dda766f3b002fc96915366d560c0a279106e3/> Fix for rename of BPF_ -> BPF_CORE_
 - <csr-id-54b0c677958b07fb2a8ece28fd55251b74dcebc8/> update object requirement from 0.27 to 0.28
   Updates the requirements on [object](https://github.com/gimli-rs/object) to permit the latest version.
   - [Release notes](https://github.com/gimli-rs/object/releases)
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.27.0...0.28.1)
   
   ---
   updated-dependencies:
   - dependency-name: object
     dependency-type: direct:production
   ...
 - <csr-id-18970369e27228c45117b125724a22d8999ec1fc/> Remove unnecessary unsafe markers on map iteration.
   Map iteration can yield stale keys and values by virtue of sharing a
   data structure with BPF programs which can modify it. However, all
   accesses remain perfectly safe and will not cause memory corruption or
   data races.
 - <csr-id-f56dd0a70b36a97036eb9447efa20f0e1c93c8d7/> eliminate name duplication in maps and programs.
   Map and ProgramData objects had unnecessarily cloned strings for their
   names, despite them being just as easily available to external users via
   bpf.maps() and bpf.programs().
 - <csr-id-bb8a813eefd86fbdb218174ccb7bfd2578ab9692/> use correct program name when relocating
 - <csr-id-e4d9774bf780eee5c3740d153df0682265089307/> Improve section detection
   This commit improves section detection.
   Previously, a section named "xdp_metadata" would be interpreted as a
   program section, which is incorrect. This commit first attempts to
   identify a BPF section by name, then by section.kind() ==
   SectionKind::Text (executable code). The computed section kind is
   stored in the Section so variants can be easily matched on later.
 - <csr-id-daa7ea6d0dad1895768d3a1cdc62911b15c72a94/> remove unnecessary usage of &dyn trait in favor of impl trait.
   This should improve performance in most situations by eliminating
   unnecessary fat pointer indirection.
 - <csr-id-c7f8db9a0b4e632233561fdd075cf201ae7cccb5/> programs_mut iterator to complement programs.
 - <csr-id-1584bc47bd027455b07e456683c0fb97920a5314/> close file descriptors on Map drop.
 - <csr-id-f8f17a09fbf1b87d14735e015c55d387a6ed048b/> expand include_bytes_aligned to accept expressions.
   This allows one to this macro with literal expressions involving macros
   such as concat! and env!.
 - <csr-id-761cb79fe3b9006a4091dcc7d68604b671387194/> fix test warnings

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 105 commits contributed to the release.
 - 125 days passed between releases.
 - 39 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 1 unique issue was worked on: [#111](https://github.com/aya-rs/aya/issues/111)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#111](https://github.com/aya-rs/aya/issues/111)**
    - Fix test warnings ([`761cb79`](https://github.com/aya-rs/aya/commit/761cb79fe3b9006a4091dcc7d68604b671387194))
 * **Uncategorized**
    - (cargo-release) version 0.10.7 ([`f01497e`](https://github.com/aya-rs/aya/commit/f01497e021aa6d2ab98141c53713a4457e6b2d68))
    - Fix lint errors ([`9a642d3`](https://github.com/aya-rs/aya/commit/9a642d373f3bd3b96b1e0a031388a8161cae5143))
    - Merge pull request #228 from nak3/fix-socket_filter ([`d690710`](https://github.com/aya-rs/aya/commit/d6907103376512249e28457e924d2ccdb5415237))
    - Merge pull request #229 from dave-tucker/fix_cgroup_skb_attach_v2 ([`3dc9308`](https://github.com/aya-rs/aya/commit/3dc9308c8e7c4a263ab7d1a064655516b5016071))
    - Merge pull request #224 from Tuetuopay/pod-arrays ([`02c376c`](https://github.com/aya-rs/aya/commit/02c376ceb7ff2a1704b3804fd7ef76d107bb0a6f))
    - Merge pull request #238 from vadorovsky/fix-doc-set-global ([`5269ab5`](https://github.com/aya-rs/aya/commit/5269ab5b1cb2fc023b8cc38dddda778787fb858f))
    - Improve documentation of set_global method ([`7dd2e3d`](https://github.com/aya-rs/aya/commit/7dd2e3d1f87559636ba33a7bbb76e57f20d43e8e))
    - Merge pull request #237 from hi120ki/fix-typo-fentry ([`7fdf37a`](https://github.com/aya-rs/aya/commit/7fdf37ad51e993acf8b4ca4f936a0cedbadfa84a))
    - Fix typo in aya/src/programs/fentry.rs ([`ab46253`](https://github.com/aya-rs/aya/commit/ab462533c7da6509bdc67d396517bc8113e37e6c))
    - Fix unit test ([`5725a97`](https://github.com/aya-rs/aya/commit/5725a97648ada61813d4aec7b16e111ea628f730))
    - Fix socket_filter section match ([`9e41317`](https://github.com/aya-rs/aya/commit/9e41317ca6f2834d9050632552f913eda9725848))
    - Merge pull request #234 from xonatius/patch-1 ([`e0d818f`](https://github.com/aya-rs/aya/commit/e0d818ff2da62b7311dd99269cd47131b564093f))
    - Fix typo in aya/README.md ([`49e998d`](https://github.com/aya-rs/aya/commit/49e998dc7eb248b5fe31a03bc1ca4db7e736bac7))
    - Fix Loading from cgroup/skb sections ([`5ee1321`](https://github.com/aya-rs/aya/commit/5ee13217652216a3a01c82dd7d8a79ea8502ca12))
    - Merge pull request #222 from aya-rs/dependabot/cargo/parking_lot-0.12.0 ([`00e34ec`](https://github.com/aya-rs/aya/commit/00e34ec29c120e44ea0bf6879f5630c664116b5c))
    - Implement Pod for arrays of Pod types ([`08211f6`](https://github.com/aya-rs/aya/commit/08211f6132fd93493267e853139f5f5724e093b0))
    - Update parking_lot requirement from 0.11.1 to 0.12.0 ([`ab7eed2`](https://github.com/aya-rs/aya/commit/ab7eed2759d062fbe267e7e96f84c7a3f477ef11))
    - Merge pull request #161 from nimrodshn/add_lpm_trie ([`2a18239`](https://github.com/aya-rs/aya/commit/2a1823934671ced3c910a2e6f287ba569bea9c60))
    - Fix #128: Add support for BPF_MAP_TYPE_LPM_TRIE map ([`c6e66d8`](https://github.com/aya-rs/aya/commit/c6e66d8080c8ca50917ced2d3d86ba1fb2af6758))
    - Merge pull request #179 from dave-tucker/btf_datasec_name ([`6316748`](https://github.com/aya-rs/aya/commit/6316748ec1a6c0f5673d12f2d7e48ff607ad6af8))
    - Merge pull request #177 from alessandrod/ptr-relocs ([`b2182c6`](https://github.com/aya-rs/aya/commit/b2182c6c4ed343d9d1e8d3180adf93199806846a))
    - Fix func_info/line_info offsets ([`f169a3f`](https://github.com/aya-rs/aya/commit/f169a3fc6bb203d2a41de449472c1115b49ffe15))
    - Relocate .text references ([`8202105`](https://github.com/aya-rs/aya/commit/8202105b7dd415fc028050daada44a75d2ed7202))
    - Replace / in DATASEC before load to kernel ([`825bb3a`](https://github.com/aya-rs/aya/commit/825bb3ad2044e186f873acbbb0a53de8d2b6e6cc))
    - Merge pull request #175 from dave-tucker/merge_fixup_sanitize ([`1904aea`](https://github.com/aya-rs/aya/commit/1904aeaef9aa1a450b7d319fc9df7f5e52f06793))
    - Fix match arms ([`99fa85e`](https://github.com/aya-rs/aya/commit/99fa85eab899c807c76274663240a19b4df41371))
    - Add a test for each BTF fix ([`326825a`](https://github.com/aya-rs/aya/commit/326825aab0b54898d9eb2e5338d70c8c663ed0e3))
    - Fix borrow check errors ([`4efc206`](https://github.com/aya-rs/aya/commit/4efc2061a8aa0c25cb648a86cdc39ca44784de94))
    - Merge Fixup and Sanitzation to single step ([`a1b46ec`](https://github.com/aya-rs/aya/commit/a1b46ece05e73896250f86815c4ad6df6095797d))
    - Merge pull request #164 from dave-tucker/btf_verifier ([`06f8938`](https://github.com/aya-rs/aya/commit/06f89388082274155519e620cc046feeba7aab00))
    - Fix BTF verifier output ([`5d8b279`](https://github.com/aya-rs/aya/commit/5d8b279265bd2715b83cbed871697bbc763a00a9))
    - Merge pull request #173 from alessandrod/func-proto-fixup ([`d9496df`](https://github.com/aya-rs/aya/commit/d9496df3a7d6762732a5dad943e9c8cdf82de25a))
    - Merge pull request #174 from alessandrod/func-global-fix ([`f70ab2c`](https://github.com/aya-rs/aya/commit/f70ab2caa746fd1f07213d9d02eb649d3fb8f948))
    - Fix sanitization if BTF_FUNC_GLOBAL is not supported ([`7ad0524`](https://github.com/aya-rs/aya/commit/7ad0524283006fce221910df4c1817af503b5b61))
    - Fixup func protos ([`9ba2e14`](https://github.com/aya-rs/aya/commit/9ba2e147a1a82e97849cc8b7ca524550803ec3a9))
    - Run fixup in place ([`89b5dd3`](https://github.com/aya-rs/aya/commit/89b5dd32ede08d3aeb5a07cf980f8af8ff326445))
    - Merge pull request #168 from dave-tucker/decl_tag ([`b45a160`](https://github.com/aya-rs/aya/commit/b45a160bb0018529a006cfe6f58a73d671116a4c))
    - Merge pull request #172 from dave-tucker/name_trunc ([`b93188f`](https://github.com/aya-rs/aya/commit/b93188fefebcdae19b7856d6009918386bf55e10))
    - Fix name truncation ([`8f9a32f`](https://github.com/aya-rs/aya/commit/8f9a32ff10a13d414ff95edc2f5645a7a5162732))
    - Merge pull request #171 from dave-tucker/nametoolong ([`dccdc45`](https://github.com/aya-rs/aya/commit/dccdc45ccd91452f511f18147cb84da8b9e6dd2b))
    - Truncate long program names ([`437432c`](https://github.com/aya-rs/aya/commit/437432cdd60bbe11e7021f52297e459fd14ff069))
    - Add support for BTF_TYPE_KIND_{TAG,DECL_TAG} ([`5d9ff70`](https://github.com/aya-rs/aya/commit/5d9ff70498785ea1becbc347c6798f76be11036f))
    - Merge pull request #169 from dave-tucker/fix_array_relo ([`1492d85`](https://github.com/aya-rs/aya/commit/1492d85a7bad7749fc06fea32ceafdcd12d34107))
    - Merge pull request #157 from dave-tucker/doc-aya ([`6a91fdf`](https://github.com/aya-rs/aya/commit/6a91fdf5a7f0bbce94e679a41d2f9b7f5fbaa41c))
    - Fix BTF type resolution for Arrays and Ints ([`686ce45`](https://github.com/aya-rs/aya/commit/686ce45f930cef68f6fdfb73dc5ebc2d259d5954))
    - Merge pull request #167 from aya-rs/codegen ([`0118773`](https://github.com/aya-rs/aya/commit/01187735f0c5ecdb3c632a5ed3b8508309ca0ee4))
    - Update libbpf to be89b28f96be426e30a2b0c5312d13b30ee518c7 ([`324c679`](https://github.com/aya-rs/aya/commit/324c679a41ba7e5448092a0e5b1ca7e06adb78e2))
    - Maps: rename from_pinned() to open_pinned() ([`4e9bc32`](https://github.com/aya-rs/aya/commit/4e9bc32a3dee903f8bfe71430c03b1c664607c5d))
    - Merge pull request #165 from dave-tucker/prog_pinned ([`f12054a`](https://github.com/aya-rs/aya/commit/f12054a00dbd48e0aa66d818a818690769c4a10b))
    - Retrieve program from pinned path ([`abc8d27`](https://github.com/aya-rs/aya/commit/abc8d27440de76cf5ed2ca4aa56883bc07d3afc4))
    - Merge pull request #163 from aya-rs/codegen ([`353b5f9`](https://github.com/aya-rs/aya/commit/353b5f9cb170394b8a8742a3e6c65d4c086648e2))
    - Update libbpf to 22411acc4b2c846868fd570b2d9f3b016d2af2cb ([`0619f80`](https://github.com/aya-rs/aya/commit/0619f8009085090c2afd0614701e74dd6fc669f5))
    - Merge pull request #158 from dave-tucker/btf-fix ([`001348a`](https://github.com/aya-rs/aya/commit/001348a301372a08e62d274fb2ead5d110d1d79e))
    - Allocate func/line_info buffers outside if ([`83cfe56`](https://github.com/aya-rs/aya/commit/83cfe56fe7690e752ebb646509bd282db227af2b))
    - Document the public api ([`bca0158`](https://github.com/aya-rs/aya/commit/bca01580e722a20e5c6026a744c92c5423f6437b))
    - Merge pull request #127 from dave-tucker/ext ([`c5a10f8`](https://github.com/aya-rs/aya/commit/c5a10f8fbe1c2b27651f9b11d077399612b8318f))
    - Add fixup for PTR types from Rust ([`877c760`](https://github.com/aya-rs/aya/commit/877c76043a6d313391159523dc40046426800c43))
    - Add BPF_PROG_TYPE_EXT ([`5c6131a`](https://github.com/aya-rs/aya/commit/5c6131afba02e22531fa82d8f40444311aeec5c9))
    - Add Btf::to_bytes ([`379bb31`](https://github.com/aya-rs/aya/commit/379bb313b13dd259a26fe3513ae6784bb85291ef))
    - Merge pull request #146 from dave-tucker/ro-maps ([`faa3676`](https://github.com/aya-rs/aya/commit/faa36763f78d3190492508ce9ed40d98eca81750))
    - Mark .rodata maps as readonly and freeze on load ([`65a0b83`](https://github.com/aya-rs/aya/commit/65a0b832057a007f8a64eb5c2e3de712e502d634))
    - Merge pull request #145 from aya-rs/codegen ([`3a4c84f`](https://github.com/aya-rs/aya/commit/3a4c84fe17f0f308c618788da9a88269ab10560f))
    - Fix for rename of BPF_ -> BPF_CORE_ ([`2b7dda7`](https://github.com/aya-rs/aya/commit/2b7dda766f3b002fc96915366d560c0a279106e3))
    - Update libbpf to 19656636a9b9a2de1f71fa3135709295c16701cc ([`05d4bc3`](https://github.com/aya-rs/aya/commit/05d4bc39ea4dd6897aa6685cec37e57e0f039577))
    - Support for fentry and fexit programs ([`7e2fcd1`](https://github.com/aya-rs/aya/commit/7e2fcd1d6d86af4c818f2140e23061154430f33f))
    - Update object requirement from 0.27 to 0.28 ([`54b0c67`](https://github.com/aya-rs/aya/commit/54b0c677958b07fb2a8ece28fd55251b74dcebc8))
    - Merge pull request #136 from nimrodshn/add_impl_pod_for_u128 ([`6313ddf`](https://github.com/aya-rs/aya/commit/6313ddfe0cae7d7581a473a3f942856e3e2e4fc9))
    - Implement Pod for u128 ([`24a292f`](https://github.com/aya-rs/aya/commit/24a292f605220c4df11e54c93c76819b3dd42909))
    - Merge pull request #134 from aya-rs/codegen ([`f34b76c`](https://github.com/aya-rs/aya/commit/f34b76c8d3bc55c3671252bb54e3d4d64ba21ddd))
    - Update libbpf to 93e89b34740c509406e948c78a404dd2fba67b8b ([`17d43cd`](https://github.com/aya-rs/aya/commit/17d43cd6f8b7894ef3741bbb2b51f726a879e2b2))
    - Merge pull request #125 from dave-tucker/btf ([`26d188c`](https://github.com/aya-rs/aya/commit/26d188c659e905d4121bc97a574f961172593889))
    - Merge pull request #131 from eero-thia/thia/safe_iter ([`441a660`](https://github.com/aya-rs/aya/commit/441a660b3e6b540de82377c46f4d6f2709b7462c))
    - Remove unnecessary unsafe markers on map iteration. ([`1897036`](https://github.com/aya-rs/aya/commit/18970369e27228c45117b125724a22d8999ec1fc))
    - Merge pull request #120 from eero-thia/thia/dedup ([`07a6016`](https://github.com/aya-rs/aya/commit/07a6016ebb370bc3d37c2865ed65bd0028f1eeb2))
    - Eliminate name duplication in maps and programs. ([`f56dd0a`](https://github.com/aya-rs/aya/commit/f56dd0a70b36a97036eb9447efa20f0e1c93c8d7))
    - Merge pull request #130 from wg/main ([`a340c2a`](https://github.com/aya-rs/aya/commit/a340c2a9fa1a01a237d1c0bb2f53c463c8719470))
    - Use correct program name when relocating ([`bb8a813`](https://github.com/aya-rs/aya/commit/bb8a813eefd86fbdb218174ccb7bfd2578ab9692))
    - Improve section detection ([`e4d9774`](https://github.com/aya-rs/aya/commit/e4d9774bf780eee5c3740d153df0682265089307))
    - Merge pull request #115 from eero-thia/thia/impl_trait ([`a03426f`](https://github.com/aya-rs/aya/commit/a03426f1947ce82227431392d20a905a1347bcd8))
    - Remove unnecessary usage of &dyn trait in favor of impl trait. ([`daa7ea6`](https://github.com/aya-rs/aya/commit/daa7ea6d0dad1895768d3a1cdc62911b15c72a94))
    - Merge pull request #116 from eero-thia/thia/close ([`98b36b2`](https://github.com/aya-rs/aya/commit/98b36b23bc7b52fae4dce98b905be52adf12167f))
    - Merge pull request #121 from eero-thia/thia/programs_mut ([`2955ca1`](https://github.com/aya-rs/aya/commit/2955ca1d1f350a0fc266410c464dbefcb6a42e2f))
    - Programs_mut iterator to complement programs. ([`c7f8db9`](https://github.com/aya-rs/aya/commit/c7f8db9a0b4e632233561fdd075cf201ae7cccb5))
    - Merge pull request #122 from eero-thia/thia/include_bytes_aligned ([`a6bf554`](https://github.com/aya-rs/aya/commit/a6bf554a74bf7a82bae9d97050505a03b241ef61))
    - Close file descriptors on Map drop. ([`1584bc4`](https://github.com/aya-rs/aya/commit/1584bc47bd027455b07e456683c0fb97920a5314))
    - Expand include_bytes_aligned to accept expressions. ([`f8f17a0`](https://github.com/aya-rs/aya/commit/f8f17a09fbf1b87d14735e015c55d387a6ed048b))
    - Merge pull request #108 from deverton/kprobe-debugfs ([`6db30fa`](https://github.com/aya-rs/aya/commit/6db30fad9ca8151abe51d1ccfafc3e90f9fd4adc))
    - Refactoring after feedback. ([`0e84610`](https://github.com/aya-rs/aya/commit/0e84610976c3148e1912f337e1589104373f0a96))
    - Support pid filtering in debugfs ([`606c326`](https://github.com/aya-rs/aya/commit/606c3267c42a1a3b7e20dba193bb6fbcbc114105))
    - Handle probe entry offsets ([`1dc7554`](https://github.com/aya-rs/aya/commit/1dc75542b4f500d43c158f1bc4dc4db142c612f2))
    - Merge branch 'main' into kprobe-debugfs ([`4e6aeb2`](https://github.com/aya-rs/aya/commit/4e6aeb2e6959a4872f55283e1968053dfa5e02e8))
    - Merge pull request #109 from deverton/dynamic-kver ([`b82d7f0`](https://github.com/aya-rs/aya/commit/b82d7f0515a8d7ffab1f61edd5d843b7f6b2dccc))
    - Updates based on feedback ([`3dff6e8`](https://github.com/aya-rs/aya/commit/3dff6e855521a3bdbf11f6d4da98d1ea5d7536a3))
    - Use current kernel version as default if not specified ([`4277205`](https://github.com/aya-rs/aya/commit/4277205e9d4f6a28a1f38aa8a990bdd97e683af1))
    - Functional detach of debugfs probes. ([`42c9737`](https://github.com/aya-rs/aya/commit/42c9737d47f35f4b6f9d7e65be590d53a7c69e35))
    - Fix event_alias comparison when looking in event list ([`a4faabc`](https://github.com/aya-rs/aya/commit/a4faabcf93400ae0ee85c49b92ed6343dae3aee8))
    - Don't duplicate perf_attach code and formatting ([`84fa219`](https://github.com/aya-rs/aya/commit/84fa2197ec42305fb5366995b28fb720bc819041))
    - Attempt auto detach of probe for debugfs ([`d0321bd`](https://github.com/aya-rs/aya/commit/d0321bd1ee92ce7157ce948eebe54845b447c378))
    - Support k/uprobes on older kernels. ([`34aa790`](https://github.com/aya-rs/aya/commit/34aa790a917512783fa50c60527b2e694fb93ce3))
    - Merge pull request #107 from deverton/skip-map-name ([`5b0e518`](https://github.com/aya-rs/aya/commit/5b0e5186414749c6e135aa6c1ceb7d67259fc4a1))
    - Formatting ([`07e3824`](https://github.com/aya-rs/aya/commit/07e3824aa4972fee73bbb0c9e3b96a417615aafb))
    - Stub `kernel_version` for tests ([`49f6a8e`](https://github.com/aya-rs/aya/commit/49f6a8e81949e127559d7f5698abe19fca4be853))
    - Fix lint issues ([`d966881`](https://github.com/aya-rs/aya/commit/d966881e46ce191bb29d624fed9c740f3078567e))
    - Make maps compatible with kernel <= 4.14 ([`fc08611`](https://github.com/aya-rs/aya/commit/fc0861105a632deb15b17855160e0b375d7c5305))
</details>

## v0.10.6 (2021-11-13)

<csr-id-352e54b72405b5e9f21a947ff0146f3ba162b78a/>
<csr-id-2136f0546161adb55947c1a3ad002b236106b737/>
<csr-id-1e6b1afbe42b191f18bef28e9dc3adff9c739eae/>
<csr-id-27d803b634d3f540fa36163c6f6eb146ffdb7e27/>
<csr-id-6b6d4af932a31632e8b1ee0a23be4ec6636194fb/>
<csr-id-6539cbb555fc7e597c814f56b3ef8bacd2bcd895/>
<csr-id-99f6f9e14d4cdcdd53b3df3cf107d041e662ea06/>
<csr-id-4df4e9c14eb1019a8c2299c48b15420ee7f20855/>
<csr-id-c99dcfb9d33ba762ed005ac6d53a2290901a83d7/>

### Other

 - <csr-id-352e54b72405b5e9f21a947ff0146f3ba162b78a/> fix name parsing for sk_skb sections
   This commit fixes name parsing of sk_skb sections such that both named
   and unnamed variants will work correctly.
 - <csr-id-2136f0546161adb55947c1a3ad002b236106b737/> netlink: use NETLINK_EXT_ACK from libc crate
   NETLINK_EXT_ACK is available since libc crate version 0.2.105, see
   https://github.com/rust-lang/libc/releases/tag/0.2.105
 - <csr-id-1e6b1afbe42b191f18bef28e9dc3adff9c739eae/> fix incorrect section size for .bss
 - <csr-id-27d803b634d3f540fa36163c6f6eb146ffdb7e27/> improve map errors to be more descriptive
 - <csr-id-6b6d4af932a31632e8b1ee0a23be4ec6636194fb/> pass Btf by reference instead of loading new Btf in Lsm::load
 - <csr-id-6539cbb555fc7e597c814f56b3ef8bacd2bcd895/> implement btf tracepoint programs
 - <csr-id-99f6f9e14d4cdcdd53b3df3cf107d041e662ea06/> fix include_bytes_aligned! macro to work in some corner cases
   I found a corner case in my own development workflow that caused the existing macro to not
   work properly. The following changes appear to fix things. Ideally, we could add some test
   cases to CI to prevent regressions.  This would require creating a dedicated directory to
   hold test cases so that we can "include" them at compile time.
 - <csr-id-4df4e9c14eb1019a8c2299c48b15420ee7f20855/> introduce include_bytes_aligned!() macro
   This is a helper macro that can be used to include bytes at compile-time that can then be
   used in Bpf::load(). Unlike std's include_bytes!(), this macro also ensures that the
   resulting byte array is correctly aligned so that it can be parsed as an ELF binary.
 - <csr-id-c99dcfb9d33ba762ed005ac6d53a2290901a83d7/> update object requirement from 0.26 to 0.27
   Updates the requirements on [object](https://github.com/gimli-rs/object) to permit the latest version.
   - [Release notes](https://github.com/gimli-rs/object/releases)
   - [Changelog](https://github.com/gimli-rs/object/blob/master/CHANGELOG.md)
   - [Commits](https://github.com/gimli-rs/object/compare/0.26.0...0.27.0)
   
   ---
   updated-dependencies:
   - dependency-name: object
     dependency-type: direct:production
   ...

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 22 commits contributed to the release.
 - 28 days passed between releases.
 - 9 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - (cargo-release) version 0.10.6 ([`182182d`](https://github.com/aya-rs/aya/commit/182182d8404fefaf9b34f432c4b06c14ef4f78f8))
    - Merge pull request #104 from dave-tucker/fix_skskb_load ([`daf8630`](https://github.com/aya-rs/aya/commit/daf863013360c834428bef8ecbe82b9f71dd023e))
    - Fix name parsing for sk_skb sections ([`352e54b`](https://github.com/aya-rs/aya/commit/352e54b72405b5e9f21a947ff0146f3ba162b78a))
    - Merge pull request #98 from aya-rs/codegen ([`f632f81`](https://github.com/aya-rs/aya/commit/f632f81db152fd1185047550ec819926a83b0eae))
    - Update libbpf to 16dfb4ffe4aed03fafc00e0557b1ce1310a09731 ([`4a7f47d`](https://github.com/aya-rs/aya/commit/4a7f47d93a4e392072df06c8c2f3bbb9aaee6df7))
    - Merge pull request #94 from tklauser/netlink-ext-ack-libc ([`563d4ba`](https://github.com/aya-rs/aya/commit/563d4ba1c38a420e408ae17df9c73acd5d244eb3))
    - Netlink: use NETLINK_EXT_ACK from libc crate ([`2136f05`](https://github.com/aya-rs/aya/commit/2136f0546161adb55947c1a3ad002b236106b737))
    - Merge pull request #90 from willfindlay/fix-bss ([`dd7e1de`](https://github.com/aya-rs/aya/commit/dd7e1de348fc14e6e1e40e6498ccc5488f8b1456))
    - Fix incorrect section size for .bss ([`1e6b1af`](https://github.com/aya-rs/aya/commit/1e6b1afbe42b191f18bef28e9dc3adff9c739eae))
    - Merge pull request #89 from willfindlay/errors ([`3a8e4fe`](https://github.com/aya-rs/aya/commit/3a8e4fe9b91538a0fafd8c91ae96185c1a017651))
    - Improve map errors to be more descriptive ([`27d803b`](https://github.com/aya-rs/aya/commit/27d803b634d3f540fa36163c6f6eb146ffdb7e27))
    - Merge pull request #85 from willfindlay/tp_btf ([`17b730c`](https://github.com/aya-rs/aya/commit/17b730c717b3696196b3a7c1562991f880d921a0))
    - Pass Btf by reference instead of loading new Btf in Lsm::load ([`6b6d4af`](https://github.com/aya-rs/aya/commit/6b6d4af932a31632e8b1ee0a23be4ec6636194fb))
    - Implement btf tracepoint programs ([`6539cbb`](https://github.com/aya-rs/aya/commit/6539cbb555fc7e597c814f56b3ef8bacd2bcd895))
    - Merge pull request #68 from vadorovsky/lsm ([`140005d`](https://github.com/aya-rs/aya/commit/140005d9e30818e86bc27ff79767075d0cca62ff))
    - Add support for raw tracepoint and LSM programs ([`169478c`](https://github.com/aya-rs/aya/commit/169478c863adea838ef9a73a8b3323b4815b4ee2))
    - Merge pull request #78 from willfindlay/main ([`56fd09c`](https://github.com/aya-rs/aya/commit/56fd09c443e1d1e00ffba18497d786b71a6b5292))
    - Fix include_bytes_aligned! macro to work in some corner cases ([`99f6f9e`](https://github.com/aya-rs/aya/commit/99f6f9e14d4cdcdd53b3df3cf107d041e662ea06))
    - Merge pull request #76 from willfindlay/load_include_bytes ([`a947747`](https://github.com/aya-rs/aya/commit/a94774755f3198d972d5ddd5225beef614b2fc5d))
    - Introduce include_bytes_aligned!() macro ([`4df4e9c`](https://github.com/aya-rs/aya/commit/4df4e9c14eb1019a8c2299c48b15420ee7f20855))
    - Bump libbpf to 92c1e61a605410b16d6330fdd4a7a4e03add86d4 ([`03e9935`](https://github.com/aya-rs/aya/commit/03e993535827aa4b654ca489726da3cc6b275408))
    - Update object requirement from 0.26 to 0.27 ([`c99dcfb`](https://github.com/aya-rs/aya/commit/c99dcfb9d33ba762ed005ac6d53a2290901a83d7))
</details>

## v0.10.5 (2021-10-15)

<csr-id-59a1854a6bd74845e3c45227ade757399a376897/>
<csr-id-dc4b928ec5a1a40fa19af5a4f8f5141fa7f91425/>
<csr-id-52c51895ba1fdcd2ee627e7b7d3d8bb4622c2a1d/>
<csr-id-64e3fb4cc82eb944327a4decc46c66d85305a564/>
<csr-id-5f8f18e3a1b13b2452294d6c8a33dde961fa511c/>

### Other

 - <csr-id-59a1854a6bd74845e3c45227ade757399a376897/> fix call relocation bug
   Take the section offset into account when looking up relocation entries
 - <csr-id-dc4b928ec5a1a40fa19af5a4f8f5141fa7f91425/> Disable Stacked Borrows and skip some tests
   The perf_buffer code fails due to stacked borrows, skip this for now.
   munmap isn't supported by miri.
 - <csr-id-52c51895ba1fdcd2ee627e7b7d3d8bb4622c2a1d/> fix clippy
 - <csr-id-64e3fb4cc82eb944327a4decc46c66d85305a564/> improve docs a bit and make BpfLoader default to loading BTF if available
 - <csr-id-5f8f18e3a1b13b2452294d6c8a33dde961fa511c/> loader: take BTF info as reference
   Allows sharing the same BTF info across many loaders

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 7 commits contributed to the release.
 - 24 days passed between releases.
 - 5 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - (cargo-release) version 0.10.5 ([`4152e8b`](https://github.com/aya-rs/aya/commit/4152e8b1a43f24d005870cb68a0ef3dbd76169c7))
    - Fix call relocation bug ([`59a1854`](https://github.com/aya-rs/aya/commit/59a1854a6bd74845e3c45227ade757399a376897))
    - Disable Stacked Borrows and skip some tests ([`dc4b928`](https://github.com/aya-rs/aya/commit/dc4b928ec5a1a40fa19af5a4f8f5141fa7f91425))
    - Fix clippy ([`52c5189`](https://github.com/aya-rs/aya/commit/52c51895ba1fdcd2ee627e7b7d3d8bb4622c2a1d))
    - Improve docs a bit and make BpfLoader default to loading BTF if available ([`64e3fb4`](https://github.com/aya-rs/aya/commit/64e3fb4cc82eb944327a4decc46c66d85305a564))
    - Loader: take BTF info as reference ([`5f8f18e`](https://github.com/aya-rs/aya/commit/5f8f18e3a1b13b2452294d6c8a33dde961fa511c))
    - Implement Pinning For Programs and Maps ([`9426f36`](https://github.com/aya-rs/aya/commit/9426f36f79101e296ec3ffc4bbef8913a1130eff))
</details>

## v0.10.4 (2021-09-21)

<csr-id-98361a4c931cbfe5190da64d3efc70547219a877/>
<csr-id-b0a05e759e49a164eead2990d93c793ca494f7c6/>
<csr-id-c56a6b16aa3fdafeb531c280c7a5d8dae7a4612a/>
<csr-id-d9fc0f484ffbe17a5a8b8e7b697ee9de4d46ff65/>
<csr-id-9c27910f76d7152091973dfe99c37ae448c25541/>
<csr-id-4e1ce2534c23a51a67cd3e56fe389e207bdcf3b3/>
<csr-id-569b8ca39ed0aac5b814f86d6f54ed44dc6295c4/>
<csr-id-753a683704f685582da37b0290a66cf37e1092d7/>

### Other

 - <csr-id-98361a4c931cbfe5190da64d3efc70547219a877/> minor PerfEvent API tweaks
 - <csr-id-b0a05e759e49a164eead2990d93c793ca494f7c6/> run xtask codegen aya
 - <csr-id-c56a6b16aa3fdafeb531c280c7a5d8dae7a4612a/> only consider Text symbols as relocatable functions
 - <csr-id-d9fc0f484ffbe17a5a8b8e7b697ee9de4d46ff65/> fix bug with nested call relocations
   Use the correct offset when looking up relocation entries while doing
   nested call relocations.
 - <csr-id-9c27910f76d7152091973dfe99c37ae448c25541/> update authors and repository link
 - <csr-id-4e1ce2534c23a51a67cd3e56fe389e207bdcf3b3/> Fix size of Unknown variant
   The size of Unknown should be ty_size, otherwise when it is encountered,
   we never advance the cursor and it creates an infinite loop.
 - <csr-id-569b8ca39ed0aac5b814f86d6f54ed44dc6295c4/> Add some tests for reading btf data
 - <csr-id-753a683704f685582da37b0290a66cf37e1092d7/> Add bindings for BTF_KIND_FLOAT

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 13 commits contributed to the release.
 - 52 days passed between releases.
 - 8 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - (cargo-release) version 0.10.4 ([`a7f5b37`](https://github.com/aya-rs/aya/commit/a7f5b3775d27c89e226c49c4a2f21d0e90b08591))
    - Bump obj to 0.26 ([`a10a7b3`](https://github.com/aya-rs/aya/commit/a10a7b3bf2a7719e2c08c7474b7b89b1f5b4a35a))
    - Minor PerfEvent API tweaks ([`98361a4`](https://github.com/aya-rs/aya/commit/98361a4c931cbfe5190da64d3efc70547219a877))
    - Run xtask codegen aya ([`b0a05e7`](https://github.com/aya-rs/aya/commit/b0a05e759e49a164eead2990d93c793ca494f7c6))
    - Add support for PerfEvent programs. ([`c39dff6`](https://github.com/aya-rs/aya/commit/c39dff602530b757367f93099a867a4307a7d519))
    - Only consider Text symbols as relocatable functions ([`c56a6b1`](https://github.com/aya-rs/aya/commit/c56a6b16aa3fdafeb531c280c7a5d8dae7a4612a))
    - Fix bug with nested call relocations ([`d9fc0f4`](https://github.com/aya-rs/aya/commit/d9fc0f484ffbe17a5a8b8e7b697ee9de4d46ff65))
    - Make Clippy Happy ([`e9bad0b`](https://github.com/aya-rs/aya/commit/e9bad0b61d95afb3ffc119be7a6fd9a109758a7b))
    - Update authors and repository link ([`9c27910`](https://github.com/aya-rs/aya/commit/9c27910f76d7152091973dfe99c37ae448c25541))
    - Remove docs. Update URLs to aya-rs ([`8acb92d`](https://github.com/aya-rs/aya/commit/8acb92d61cd21ebaaf7a529b977947ef7e10abfc))
    - Fix size of Unknown variant ([`4e1ce25`](https://github.com/aya-rs/aya/commit/4e1ce2534c23a51a67cd3e56fe389e207bdcf3b3))
    - Add some tests for reading btf data ([`569b8ca`](https://github.com/aya-rs/aya/commit/569b8ca39ed0aac5b814f86d6f54ed44dc6295c4))
    - Add bindings for BTF_KIND_FLOAT ([`753a683`](https://github.com/aya-rs/aya/commit/753a683704f685582da37b0290a66cf37e1092d7))
</details>

## v0.10.3 (2021-07-31)

<csr-id-66a12ffcf70b2702a9eee7f89cabe64aa9c46126/>
<csr-id-8c03ba052a168d390c9d997f4bbf32d610864042/>
<csr-id-fa2cbe2f825cc0c257e983793af58aa63aea6287/>
<csr-id-c2a90c2c010e69508c5704542f1133d82f793aa0/>
<csr-id-0a9d02140acdaa35c5f5c7e17ea08a6823922e20/>
<csr-id-abb199e6f436b67485ed77211daca3e990ca6c0d/>
<csr-id-9185f32f6f7bb33c160ded526e7122462fef77dd/>
<csr-id-d996a88de47d60053504695036a14157ce6b3aa6/>
<csr-id-0878c4505a95931c745b6b0bdbcb5413579acd85/>
<csr-id-21e01df242376d4a9d4f67664277263f0dc8d173/>
<csr-id-b657930a3ee61f88ada0630afdac6b1c77459244/>
<csr-id-9c8e78b7d4192b376ec2e532d9ddcf81c3c5182e/>
<csr-id-08c71dfeb19b2b4358d75baf5b95f8d4e6521935/>
<csr-id-35f15f70e0d83f5e19153c9d2917add10c154d1e/>
<csr-id-bb15e82c1d8373700dda52f69d6c4bf6f5489a03/>
<csr-id-d8d311738c974f3b6fad22006ab2b827d0925ce8/>
<csr-id-5f0ff1698a12141ffe50e160de252f664773c140/>
<csr-id-7f2ceaf12e3aeadd81a55a75c268f254192cf866/>
<csr-id-d9b5ab575f6e2cbca793881094e1846a39332fa1/>
<csr-id-c240a2c73381a6864f343c79069abfd5f9e9b729/>
<csr-id-bb595c4e69ff0c72c8327e7f64d43ca7a4bc16a3/>
<csr-id-018862258064a39f5613ecc81c1e257bea2c4e74/>
<csr-id-a0151dd48520ac801042da3c26bf4739b549d1b1/>

### Bug Fixes

 - <csr-id-b4b019e447c9829a0405b0fd40f1f2f66652db8f/> pass BTF object by reference in order to allow multiple eBPF programs to share it and save memory (closes #30).

### Other

 - <csr-id-66a12ffcf70b2702a9eee7f89cabe64aa9c46126/> programs: tweak LircMode2::query doc.
 - <csr-id-8c03ba052a168d390c9d997f4bbf32d610864042/> netlink: fix clippy lint
 - <csr-id-fa2cbe2f825cc0c257e983793af58aa63aea6287/> fix clippy warnings
 - <csr-id-c2a90c2c010e69508c5704542f1133d82f793aa0/> tc: add qdisc_detach_program
   qdisc_detach_program can be used to detach all the programs that have
   the given name. It's useful when you want to detach programs that were
   attached by some other process (eg. iproute2), or when you want to
   detach programs that were previously left attached because the program
   that attached them was killed.
 - <csr-id-0a9d02140acdaa35c5f5c7e17ea08a6823922e20/> netlink: fix alignment when writing attributes
 - <csr-id-abb199e6f436b67485ed77211daca3e990ca6c0d/> netlink: fix handling of multipart messages
 - <csr-id-9185f32f6f7bb33c160ded526e7122462fef77dd/> tc: clean up netlink code a bit
 - <csr-id-d996a88de47d60053504695036a14157ce6b3aa6/> fix formatting
 - <csr-id-0878c4505a95931c745b6b0bdbcb5413579acd85/> fix clippy warnings
 - <csr-id-21e01df242376d4a9d4f67664277263f0dc8d173/> obj: improve parse_map_def tests
   Add a test that checks that we handle ELF section padding correctly and
   simplify the other tests.
 - <csr-id-b657930a3ee61f88ada0630afdac6b1c77459244/> don't error out parsing padded map sections
 - <csr-id-9c8e78b7d4192b376ec2e532d9ddcf81c3c5182e/> tc: make qdisc_add_clsact return io::Error
 - <csr-id-08c71dfeb19b2b4358d75baf5b95f8d4e6521935/> kprobe: remove pid argument
   Kprobes can only be attached globally. Per-pid logic needs to be
   implemented on the BPF side with bpf_get_current_pid_tgid.
 - <csr-id-35f15f70e0d83f5e19153c9d2917add10c154d1e/> add minimum kernel version for each map and program type
 - <csr-id-bb15e82c1d8373700dda52f69d6c4bf6f5489a03/> add missing load() in kprobe example
 - <csr-id-d8d311738c974f3b6fad22006ab2b827d0925ce8/> support both bpf_map_def layout variants
   Libbpf and iproute2 use two slightly different `bpf_map_def` layouts. This change implements support for loading both.
 - <csr-id-5f0ff1698a12141ffe50e160de252f664773c140/> netlink: tc: use ptr::read_unaligned instead of dereferencing a potentially unaligned ptr
 - <csr-id-7f2ceaf12e3aeadd81a55a75c268f254192cf866/> netlink: port TC code to using new nlattr utils
 - <csr-id-d9b5ab575f6e2cbca793881094e1846a39332fa1/> netlink: refactor nlattr writing code
 - <csr-id-c240a2c73381a6864f343c79069abfd5f9e9b729/> netlink: introduce NestedAttrs builder and switch XDP to it
   NestedAttrs is a safe interface for writing nlattrs. This is the first
   step towards making the netlink code safer and easier to maintain.
 - <csr-id-bb595c4e69ff0c72c8327e7f64d43ca7a4bc16a3/> refactor program section parsing
   This renames aya::obj::ProgramKind to aya::obj::ProgramSection and moves
   all the program section parsing to ProgramSection::from_str.
 - <csr-id-018862258064a39f5613ecc81c1e257bea2c4e74/> fix tracepoint prefix in a couple more places
 - <csr-id-a0151dd48520ac801042da3c26bf4739b549d1b1/> fix trace point section name
   Trace points have prefix "tracepoint" not "trace_point".

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 29 commits contributed to the release.
 - 43 days passed between releases.
 - 24 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 3 unique issues were worked on: [#18](https://github.com/aya-rs/aya/issues/18), [#31](https://github.com/aya-rs/aya/issues/31), [#32](https://github.com/aya-rs/aya/issues/32)

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **[#18](https://github.com/aya-rs/aya/issues/18)**
    - Add minimum kernel version for each map and program type ([`35f15f7`](https://github.com/aya-rs/aya/commit/35f15f70e0d83f5e19153c9d2917add10c154d1e))
 * **[#31](https://github.com/aya-rs/aya/issues/31)**
    - Pass BTF object by reference in order to allow multiple eBPF programs to share it and save memory (closes #30). ([`b4b019e`](https://github.com/aya-rs/aya/commit/b4b019e447c9829a0405b0fd40f1f2f66652db8f))
 * **[#32](https://github.com/aya-rs/aya/issues/32)**
    - Implement query for lirc programs ([`81e07e9`](https://github.com/aya-rs/aya/commit/81e07e96611652b1b1ec4bb9121732862692cf2d))
 * **Uncategorized**
    - (cargo-release) version 0.10.3 ([`f30abca`](https://github.com/aya-rs/aya/commit/f30abca15e77ea841643f31a4bab0c30113dcda4))
    - Programs: tweak LircMode2::query doc. ([`66a12ff`](https://github.com/aya-rs/aya/commit/66a12ffcf70b2702a9eee7f89cabe64aa9c46126))
    - Netlink: fix clippy lint ([`8c03ba0`](https://github.com/aya-rs/aya/commit/8c03ba052a168d390c9d997f4bbf32d610864042))
    - Fix clippy warnings ([`fa2cbe2`](https://github.com/aya-rs/aya/commit/fa2cbe2f825cc0c257e983793af58aa63aea6287))
    - Tc: add qdisc_detach_program ([`c2a90c2`](https://github.com/aya-rs/aya/commit/c2a90c2c010e69508c5704542f1133d82f793aa0))
    - Netlink: fix alignment when writing attributes ([`0a9d021`](https://github.com/aya-rs/aya/commit/0a9d02140acdaa35c5f5c7e17ea08a6823922e20))
    - Netlink: fix handling of multipart messages ([`abb199e`](https://github.com/aya-rs/aya/commit/abb199e6f436b67485ed77211daca3e990ca6c0d))
    - Tc: clean up netlink code a bit ([`9185f32`](https://github.com/aya-rs/aya/commit/9185f32f6f7bb33c160ded526e7122462fef77dd))
    - Fix formatting ([`d996a88`](https://github.com/aya-rs/aya/commit/d996a88de47d60053504695036a14157ce6b3aa6))
    - Fix clippy warnings ([`0878c45`](https://github.com/aya-rs/aya/commit/0878c4505a95931c745b6b0bdbcb5413579acd85))
    - Obj: improve parse_map_def tests ([`21e01df`](https://github.com/aya-rs/aya/commit/21e01df242376d4a9d4f67664277263f0dc8d173))
    - Don't error out parsing padded map sections ([`b657930`](https://github.com/aya-rs/aya/commit/b657930a3ee61f88ada0630afdac6b1c77459244))
    - Added support for armv7-unknown-linux-gnueabi and armv7-unknown-linux-gnueabihf ([`8311abf`](https://github.com/aya-rs/aya/commit/8311abfdcbbe70da6abdd67b78b831d53998aad5))
    - Tc: make qdisc_add_clsact return io::Error ([`9c8e78b`](https://github.com/aya-rs/aya/commit/9c8e78b7d4192b376ec2e532d9ddcf81c3c5182e))
    - Aya, aya-bpf-bindings: regenerate bindings ([`122a530`](https://github.com/aya-rs/aya/commit/122a5306e72c7560629bcef160e7f676b84eabd7))
    - Kprobe: remove pid argument ([`08c71df`](https://github.com/aya-rs/aya/commit/08c71dfeb19b2b4358d75baf5b95f8d4e6521935))
    - Add missing load() in kprobe example ([`bb15e82`](https://github.com/aya-rs/aya/commit/bb15e82c1d8373700dda52f69d6c4bf6f5489a03))
    - Support both bpf_map_def layout variants ([`d8d3117`](https://github.com/aya-rs/aya/commit/d8d311738c974f3b6fad22006ab2b827d0925ce8))
    - Netlink: tc: use ptr::read_unaligned instead of deferencing a potentially unaligned ptr ([`5f0ff16`](https://github.com/aya-rs/aya/commit/5f0ff1698a12141ffe50e160de252f664773c140))
    - Netlink: port TC code to using new nlattr utils ([`7f2ceaf`](https://github.com/aya-rs/aya/commit/7f2ceaf12e3aeadd81a55a75c268f254192cf866))
    - Netlink: refactor nlattr writing code ([`d9b5ab5`](https://github.com/aya-rs/aya/commit/d9b5ab575f6e2cbca793881094e1846a39332fa1))
    - Netlink: introduce NestedAttrs builder and switch XDP to it ([`c240a2c`](https://github.com/aya-rs/aya/commit/c240a2c73381a6864f343c79069abfd5f9e9b729))
    - Refactor program section parsing ([`bb595c4`](https://github.com/aya-rs/aya/commit/bb595c4e69ff0c72c8327e7f64d43ca7a4bc16a3))
    - Fix tracepoint prefix in a couple more places ([`0188622`](https://github.com/aya-rs/aya/commit/018862258064a39f5613ecc81c1e257bea2c4e74))
    - Fix trace point section name ([`a0151dd`](https://github.com/aya-rs/aya/commit/a0151dd48520ac801042da3c26bf4739b549d1b1))
    - Merge pull request #4 from seanyoung/doctest ([`521ef09`](https://github.com/aya-rs/aya/commit/521ef09463278588004bcec8dcd22d4f8caeb1ab))
</details>

## v0.10.2 (2021-06-17)

<csr-id-fee71b42f16e4d1f683e94f64b038f6e8b2f4f0a/>

### Other

 - <csr-id-fee71b42f16e4d1f683e94f64b038f6e8b2f4f0a/> tc: fix QdiscRequest layout

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 5 commits contributed to the release.
 - 1 day passed between releases.
 - 1 commit was understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - (cargo-release) version 0.10.2 ([`d70e291`](https://github.com/aya-rs/aya/commit/d70e29158037a083d5886d30d2029bd054974af5))
    - Tc: fix QdiscRequest layout ([`fee71b4`](https://github.com/aya-rs/aya/commit/fee71b42f16e4d1f683e94f64b038f6e8b2f4f0a))
    - Fix doctest and run them during CI ([`1196ba1`](https://github.com/aya-rs/aya/commit/1196ba1dccebfb0953d0e4d5244f81612600fdb0))
    - Merge pull request #3 from seanyoung/lirc ([`59cfbc5`](https://github.com/aya-rs/aya/commit/59cfbc51c824d576ae9c0ea0815ad44d40107ac4))
    - Add support for lirc programs ([`b49ba69`](https://github.com/aya-rs/aya/commit/b49ba69d09576a4dd34fbc703a938acd50cb6e7a))
</details>

## v0.10.1 (2021-06-16)

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 3 commits contributed to the release.
 - 0 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - (cargo-release) version 0.10.1 ([`304abfb`](https://github.com/aya-rs/aya/commit/304abfbfeb05058be40a8832d5f7682f46a81fa0))
    - Merge pull request #1 from aquarhead/fix-load-file ([`cdc7374`](https://github.com/aya-rs/aya/commit/cdc737490df927b131de5b5868eeb43c6ecaa58a))
    - Fix Bpf::load_file when BTF doesn't exist ([`f1fc304`](https://github.com/aya-rs/aya/commit/f1fc30411d7d0b65b52a7e9312c8fd20340bd2d2))
</details>

## v0.10.0 (2021-06-15)

<csr-id-7694bacf04f5ba3cf58b4e432ff746ce2987d67d/>
<csr-id-9f7b017d5d4a4eb63c98c258e3b382628e711253/>
<csr-id-768640dd4696eaf8c76d7a8b15ab195b3979b281/>
<csr-id-ad58e171ff1645d02998b399db6535a226b5a5ec/>
<csr-id-28158e6028b12efad61d159c3b505d58a03bfd8a/>
<csr-id-6ecf7dabf35f22869a95a8cd176b6f217ee57b05/>
<csr-id-6772595f3ea2d0178e02efc97a2fe2a789a04b24/>
<csr-id-4bde0c54bdcf6f749f6b6034874cf1bfecb0b08f/>
<csr-id-2cda5dbbe74e5d41ce7e2c895678b853d2867001/>
<csr-id-2d7b9b2e904e2435527d6640e631195ffbd7e050/>
<csr-id-08a68faf8a8baa344dd6fee64529ad2dcc0a0846/>
<csr-id-fb3e2f7f9d06b22c7fe44eccefc2ce94ad322ed0/>
<csr-id-665802594c2181ae890b3655867944a3fef11508/>
<csr-id-81a0b61164079ca276d23e0f31f2853087650198/>
<csr-id-b92b1e18a97135684907d238578146f7aabacc84/>
<csr-id-20b2d4c77dbc1597f68e6ae16a55d129e42b5c5d/>
<csr-id-6974d349e8f86c98f450122788efeedecbf61970/>
<csr-id-31f8d71604f4eddd7981cd72e1deb01d2076f7f4/>
<csr-id-40b7da6655aca6aed5dfe72a0db80bf0e67c2ce1/>
<csr-id-dc4e020f29acc544bb49a74bbad4c553f370d0f3/>
<csr-id-5effc972ac04960d0346e1f5504b595a206fc019/>
<csr-id-4222b140ec594e99e77cda8539b16f21820ae155/>
<csr-id-3b7ffd0048a5250ca160f8a7b584bf0ea73eb249/>
<csr-id-30d2b25f1173904b2542a25792d7dff5b97b837f/>
<csr-id-607cf68a692be60eb9f44d26352c513ea6295456/>
<csr-id-bb7728a2c5905923534e51bd53d8d5720f7319e1/>
<csr-id-9e12c9324c623bf751053ff874bc47055343753e/>
<csr-id-9a24f20e6f85d9ff2e438dddb3530b88e9583851/>
<csr-id-144175434f5b07ac7379be6e30a4b613c225f21b/>
<csr-id-dad300c88bdfade10f8318fcbbe9a8b5e4de89ce/>
<csr-id-ca4b3bfc0462b445f2aae56f9d4c2a80581eda39/>
<csr-id-b57cace941333910891462127ce0199ae01c3c7c/>
<csr-id-b6cd813af5fbd290a1f2e80b08c170ab868dfb3f/>
<csr-id-0b3e532d7a4a8fe575b41f64d94cfedab10c36ea/>
<csr-id-79f1b385a5366cc6f9a6a84172ab131850028a87/>
<csr-id-683a58ea6dfaeb65d00ea3cf63b215cd82fd3d5a/>
<csr-id-ae863bc663bde69eb71d5c1ec265b0d4c205f7ff/>
<csr-id-d9634ae945ba09bedfc10c748e4e35a6ca3bfde8/>
<csr-id-67c9cc03597e6f00bb6917a493cd9bb405a05b4d/>
<csr-id-2cdb10e7f2734d85bd8ab115a081f4d1a8b2e2ed/>
<csr-id-ad6d0596ab076aac84c12425ab493e6b6f24477d/>
<csr-id-f4642797408d31c8375562ead9f4480e8579f59d/>
<csr-id-9ad2a5e72d269724953f0f311e803a88637af2ee/>
<csr-id-b0364f76aba500464470628f719b5ca7aab4b36a/>
<csr-id-74d5f17559036c2eb42d4679ff98fe2ab7e76d4f/>
<csr-id-aa3a30d1965d96f3b6fc345be763561e6270f2ae/>
<csr-id-1746bbf5b83a5b392f39eefe02fc3731db77d893/>
<csr-id-c3b902137becc48b72091ba59a9a4e297ba56d33/>
<csr-id-6cec8be564a590717e9af7eb007f3f5d10ffff0e/>
<csr-id-7a989b43b9ee5b4807f53001c2d7d8824a162a34/>
<csr-id-635dcd44b9135dd75d958909f76da28676e6efe7/>
<csr-id-fd142e467c32b6aa4b0d2e8d62816a63c1fa4220/>
<csr-id-3a5b28916385b35824bc2a05606808e5e8c1968a/>
<csr-id-d5098c9e575b7d5447506648ebeae146192eeda1/>
<csr-id-6a12a48f0360456452c34737c5d52cd289ce23e8/>
<csr-id-ac83273da86c5d10100f58563a9d764a79183367/>
<csr-id-46e0a2ede4e423e620acd55f3ed4f755aa8c8b38/>
<csr-id-7c6ae769756a9605f7823e36243b69a3a88a1370/>
<csr-id-04fde468556ace883009b4abe63840aa7b89f29f/>
<csr-id-eea27f52f3d6455d97838e833b36f6c846c99cb7/>
<csr-id-5aa9cb12ade0014d64582864e66bbeae593f6edc/>
<csr-id-d94bfde29521fa6fc1d661d1976d4800dd10b1d8/>
<csr-id-ce3f83acb11388f2c0b07a8b1de95c7df22b97f9/>
<csr-id-e28da8812ed5d9e76e764fbc28312e8588aff2af/>
<csr-id-24f7c37158ede0217354d8c6305904737980f292/>
<csr-id-3fddc8165c6e2c28c4fda19e72156b640da4a0c7/>
<csr-id-6682a5ff395d8fbea20393ff81140adcfc2a0c09/>
<csr-id-1bbbf616b6bedef4a6d42cd630ecd7e3b9366dc5/>
<csr-id-563ce46118258805892bdff97f0e57b2838e0de8/>
<csr-id-f9554d6db5c1fe3c906c798bc9b2a9c28fb0db7b/>
<csr-id-a92bfebf50df2c56bca242c6a9c3dedd04135675/>
<csr-id-42e0a659b2f82cca537d70f906e0a475f0ab6b03/>
<csr-id-d3482c063ca888a6465f3e8866d5d3de93cbbd99/>
<csr-id-ee05f9d9497ea83ee9cfffbaa0d1b87d9d57c26e/>
<csr-id-92b4ed2664264b4af36b29c7b08d13505eae9b08/>
<csr-id-8b0eee317d71f0139ec030b1f0583edf8670c296/>
<csr-id-318c16cea32731613339d22fad11a29be8d79976/>
<csr-id-286e117fe0bab8542f2e1d5fd309562689d88c00/>
<csr-id-0199e4b29704df4cebf65d3d5f09ab1af6982cbd/>
<csr-id-dcb5121985113e1b90a5e50a43d71b4f00826ebe/>
<csr-id-ed53f7470b386f3a870e34399bbb52c6ea72d07d/>
<csr-id-0a493baed6b4d020ed7d5d87191d912662eb2159/>
<csr-id-29f2d9b2d9e4265d0d0d2f13c314ef27d5c4ebcf/>
<csr-id-59ed237343c16ba0b96f917991a7ec2f971ecd5d/>
<csr-id-8327ffbb8d77e39046f851ca0f38ed153e140715/>
<csr-id-1e779c520a90daa642a67cf3b986536aa50ad5ef/>
<csr-id-f11df77f859feee2a88a69b96da4a1a22839c45a/>
<csr-id-b7369d2763fe8c7061071986c41d1bcb0682f5a7/>
<csr-id-82bcef37906472e7a32fa602cf26a97387590057/>
<csr-id-245cd46baba5e1b532c7bf8b3eb732ab398bb529/>
<csr-id-68a633fe51299ab6feaea370fd7b86740d284731/>
<csr-id-f56c32b46bdd4c634b1ce6136ecab3c88d202040/>
<csr-id-0cf5d17e383d240a27d463c89bec5d3a19854e4f/>
<csr-id-2cec04c5781bc7b03c601dbb0cb1c23f3df22385/>
<csr-id-55d8bcf3860d2cf5db7f59b8b5caaa32de6e668d/>
<csr-id-d326038cf4b0a6fe7966de038054966bf3016380/>
<csr-id-f88ca1f1f1449db1a4a323a67edf0ac5a4878ee1/>
<csr-id-ba992a2414430387737e76db2e10b04c98f56847/>
<csr-id-14c98455a940d6cead424b7e30a62845c256ae26/>
<csr-id-fdc4dad5ff88a419d982f67568f5271c69e73f0a/>
<csr-id-4be0c45305f0b0c639bfb6b645848fd4e1e0774f/>
<csr-id-95a24c6f8b2483f05afabb0b3afaacfea4ebe061/>

### Other

 - <csr-id-7694bacf04f5ba3cf58b4e432ff746ce2987d67d/> add more fields to Cargo.toml
 - <csr-id-9f7b017d5d4a4eb63c98c258e3b382628e711253/> bump version to 0.10
 - <csr-id-768640dd4696eaf8c76d7a8b15ab195b3979b281/> add doc aliases for maps and programs
 - <csr-id-ad58e171ff1645d02998b399db6535a226b5a5ec/> refactor tc code a bit and add docs
 - <csr-id-28158e6028b12efad61d159c3b505d58a03bfd8a/> improve async perf map docs
 - <csr-id-6ecf7dabf35f22869a95a8cd176b6f217ee57b05/> tweak PerfEventArray docs
 - <csr-id-6772595f3ea2d0178e02efc97a2fe2a789a04b24/> ProgramArray: more doc fixes
 - <csr-id-4bde0c54bdcf6f749f6b6034874cf1bfecb0b08f/> ProgramArray: tweak docs
 - <csr-id-2cda5dbbe74e5d41ce7e2c895678b853d2867001/> implement ProgramFd for CgroupSkb
 - <csr-id-2d7b9b2e904e2435527d6640e631195ffbd7e050/> fix CgroupSkb docs
 - <csr-id-08a68faf8a8baa344dd6fee64529ad2dcc0a0846/> programs: add support for BPF_PROG_TYPE_CGROUP_SKB programs
 - <csr-id-fb3e2f7f9d06b22c7fe44eccefc2ce94ad322ed0/> programs: fix detaching programs attached with bpf_prog_attach
 - <csr-id-665802594c2181ae890b3655867944a3fef11508/> programs: fix syscall name in errors
 - <csr-id-81a0b61164079ca276d23e0f31f2853087650198/> handle reordered functions
   LLVM will split .text into .text.hot .text.unlikely etc and move the
   content around in order to improve locality. We need to parse all the
   text sections or relocations can potentially fail.
 - <csr-id-b92b1e18a97135684907d238578146f7aabacc84/> improve call relocation error messages
 - <csr-id-20b2d4c77dbc1597f68e6ae16a55d129e42b5c5d/> BpfError: set the #[source] attribute for RelocationErrors
 - <csr-id-6974d349e8f86c98f450122788efeedecbf61970/> add support for attaching and detaching TC programs
   This change adds support for attaching TC programs directly from aya, without
   having to use iproute2/tc.
 - <csr-id-31f8d71604f4eddd7981cd72e1deb01d2076f7f4/> add support for Stack and Queue maps
 - <csr-id-40b7da6655aca6aed5dfe72a0db80bf0e67c2ce1/> add id and pinning fields to bpf_map_def
 - <csr-id-dc4e020f29acc544bb49a74bbad4c553f370d0f3/> netlink: improve error messages
 - <csr-id-5effc972ac04960d0346e1f5504b595a206fc019/> add support for BPF_PROG_TYPE_SCHED_CLS programs
 - <csr-id-4222b140ec594e99e77cda8539b16f21820ae155/> perf_map: fix bug when max_entries=0
   When a perf map has max_entries=0, max_entries is dynamically set at
   load time to the number of possible cpus as reported by
   /sys/devices/system/cpu/possible.
   
   This change fixes a bug where instead of setting max_entries to the
   number of possible cpus, we were setting it to the cpu index of the last
   possible cpu.
 - <csr-id-3b7ffd0048a5250ca160f8a7b584bf0ea73eb249/> update generated bindings
   Update generated bindings with kernel headers from libbpf 4ccc1f0
 - <csr-id-30d2b25f1173904b2542a25792d7dff5b97b837f/> xdp: fix detaching on kernels older than 5.7
   XDP_FLAGS_REPLACE was added in 5.7. Now for kernels >= 5.7 whenever we
   detach an XDP program we pass along the program fd we expect to be
   detaching. For older kernels, we just detach whatever is attached, which
   is not great but it's the way the API worked pre XDP_FLAGS_REPLACE.
 - <csr-id-607cf68a692be60eb9f44d26352c513ea6295456/> xdp: set flags when attaching with netlink
 - <csr-id-bb7728a2c5905923534e51bd53d8d5720f7319e1/> fix BpfError display strings
 - <csr-id-9e12c9324c623bf751053ff874bc47055343753e/> fix warnings
 - <csr-id-9a24f20e6f85d9ff2e438dddb3530b88e9583851/> programs: rework load_program() retry code a bit
 - <csr-id-144175434f5b07ac7379be6e30a4b613c225f21b/> programs: add support for SkMsg programs
 - <csr-id-dad300c88bdfade10f8318fcbbe9a8b5e4de89ce/> maps: add SockHash
 - <csr-id-ca4b3bfc0462b445f2aae56f9d4c2a80581eda39/> add support for SockOps programs
 - <csr-id-b57cace941333910891462127ce0199ae01c3c7c/> add support BPF_PROG_TYPE_SK_SKB programs and SockMaps
 - <csr-id-b6cd813af5fbd290a1f2e80b08c170ab868dfb3f/> fix program array key size
 - <csr-id-0b3e532d7a4a8fe575b41f64d94cfedab10c36ea/> small doc fixes
 - <csr-id-79f1b385a5366cc6f9a6a84172ab131850028a87/> more docs
 - <csr-id-683a58ea6dfaeb65d00ea3cf63b215cd82fd3d5a/> consolidate errors into ProgramError::SyscallError
 - <csr-id-ae863bc663bde69eb71d5c1ec265b0d4c205f7ff/> split aya::programs::probe into ::kprobe and ::uprobe & add docs
 - <csr-id-d9634ae945ba09bedfc10c748e4e35a6ca3bfde8/> add maps::StackTraceMap
   Map type for BPF_MAP_TYPE_STACK_TRACE.
 - <csr-id-67c9cc03597e6f00bb6917a493cd9bb405a05b4d/> add util::kernel_symbols()
   kernel_symbols() can be used to load /proc/kallsyms in a BTreeMap.
   Useful for looking up symbols from stack addresses.
 - <csr-id-2cdb10e7f2734d85bd8ab115a081f4d1a8b2e2ed/> add bpf_map_lookup_elem_ptr
 - <csr-id-ad6d0596ab076aac84c12425ab493e6b6f24477d/> tweak docs
 - <csr-id-f4642797408d31c8375562ead9f4480e8579f59d/> rename ProgramArray::unset to ProgramArray::clear_index
 - <csr-id-9ad2a5e72d269724953f0f311e803a88637af2ee/> rename ProgramArray::keys to ProgramArray::indices
 - <csr-id-b0364f76aba500464470628f719b5ca7aab4b36a/> maps: add PerCpuArray
 - <csr-id-74d5f17559036c2eb42d4679ff98fe2ab7e76d4f/> rework IterableMap and ProgramArray
   Make MapKeys not use IterableMap. Leave only ProgramArray::get,
   ProgramArray::set and ProgramArray::unset exposed as the other syscalls
   don't work consistently for program arrays.
 - <csr-id-aa3a30d1965d96f3b6fc345be763561e6270f2ae/> PerCpuKernelMem doesn't need to be public
 - <csr-id-1746bbf5b83a5b392f39eefe02fc3731db77d893/> add aya::maps::Array
 - <csr-id-c3b902137becc48b72091ba59a9a4e297ba56d33/> add aya::maps::array and move ProgramArray under it
 - <csr-id-6cec8be564a590717e9af7eb007f3f5d10ffff0e/> hash_map: add doc aliases for HASH and LRU_HASH
 - <csr-id-7a989b43b9ee5b4807f53001c2d7d8824a162a34/> per_cpu_hash_map: add support for BPF_MAP_TYPE_LRU_PERCPU_HASH
 - <csr-id-635dcd44b9135dd75d958909f76da28676e6efe7/> maps: introduce MapError::KeyNotFound
   Change get() from -> Result<Option<V>, MapError> to -> Result<V,
   MapError> where MapError::KeyNotFound is returned instead of Ok(None) to
   signify that the key is not present.
 - <csr-id-fd142e467c32b6aa4b0d2e8d62816a63c1fa4220/> rename MapError::NotFound to MapError::MapNotFound
 - <csr-id-3a5b28916385b35824bc2a05606808e5e8c1968a/> add PerCpuHashMap
 - <csr-id-d5098c9e575b7d5447506648ebeae146192eeda1/> move hash_map.rs to hash_map/hash_map.rs
 - <csr-id-6a12a48f0360456452c34737c5d52cd289ce23e8/> hash_map: factor out common hash code
   This is in preparation of adding new hash map types
 - <csr-id-ac83273da86c5d10100f58563a9d764a79183367/> fix warnings
 - <csr-id-46e0a2ede4e423e620acd55f3ed4f755aa8c8b38/> don't export VerifierLog
 - <csr-id-7c6ae769756a9605f7823e36243b69a3a88a1370/> HashMap: add support for LRU maps
 - <csr-id-04fde468556ace883009b4abe63840aa7b89f29f/> more docs
 - <csr-id-eea27f52f3d6455d97838e833b36f6c846c99cb7/> tweak docs
 - <csr-id-5aa9cb12ade0014d64582864e66bbeae593f6edc/> rename perf map and add docs
   Rename the perf_map module to just perf, and rename PerfMap to
   PerfEventArray.
 - <csr-id-d94bfde29521fa6fc1d661d1976d4800dd10b1d8/> maps: add docs and make the hash_map and program_array modules public
 - <csr-id-ce3f83acb11388f2c0b07a8b1de95c7df22b97f9/> add HashMap docs
 - <csr-id-e28da8812ed5d9e76e764fbc28312e8588aff2af/> make HashMap::new private
 - <csr-id-24f7c37158ede0217354d8c6305904737980f292/> add ProgramArray docs
 - <csr-id-3fddc8165c6e2c28c4fda19e72156b640da4a0c7/> make ProgramArray::new private
 - <csr-id-6682a5ff395d8fbea20393ff81140adcfc2a0c09/> remove pop()
   lookup_and_delete_elem is only supported for QUEUE and STACK maps at the
   moment.
 - <csr-id-1bbbf616b6bedef4a6d42cd630ecd7e3b9366dc5/> add some docs for the crate and `Bpf`
 - <csr-id-563ce46118258805892bdff97f0e57b2838e0de8/> maps: group syscall errors into MapError::SyscallError
 - <csr-id-f9554d6db5c1fe3c906c798bc9b2a9c28fb0db7b/> fix bindings for PERF_EVENT_IOC_{ENABLE|DISABLE|SET_BPF}
 - <csr-id-a92bfebf50df2c56bca242c6a9c3dedd04135675/> remove TryInto magic from program()/program_mut() too
   For programs it's actually useful being able to get the underlying
   Program enum, for example when iterating/loading all the programs
 - <csr-id-42e0a659b2f82cca537d70f906e0a475f0ab6b03/> remove TryInto cleverness from map() and map_mut()
   Require callers to call try_into() explicitly. It's more characters, but
   it's easier to understand/document.
   
   Also introduce MapError::NotFound instead of returning Result<Option<_>>.
 - <csr-id-d3482c063ca888a6465f3e8866d5d3de93cbbd99/> fix some badly completed match arms
 - <csr-id-ee05f9d9497ea83ee9cfffbaa0d1b87d9d57c26e/> fix verifier log handling
 - <csr-id-92b4ed2664264b4af36b29c7b08d13505eae9b08/> add support for function calls
 - <csr-id-8b0eee317d71f0139ec030b1f0583edf8670c296/> section: collecting relocations can't fail anymore
 - <csr-id-318c16cea32731613339d22fad11a29be8d79976/> obj: rename symbol_table to symbols_by_index
 - <csr-id-286e117fe0bab8542f2e1d5fd309562689d88c00/> add Program::name() and make ::prog_type() public
 - <csr-id-0199e4b29704df4cebf65d3d5f09ab1af6982cbd/> bpf: Add Bpf::programs()
 - <csr-id-dcb5121985113e1b90a5e50a43d71b4f00826ebe/> bpf: remove lifetime param from previous signature
 - <csr-id-ed53f7470b386f3a870e34399bbb52c6ea72d07d/> maps: add Map::name() and Map::map_type()
 - <csr-id-0a493baed6b4d020ed7d5d87191d912662eb2159/> add Bpf::maps() to get all the maps
 - <csr-id-29f2d9b2d9e4265d0d0d2f13c314ef27d5c4ebcf/> switch to rustified enums
 - <csr-id-59ed237343c16ba0b96f917991a7ec2f971ecd5d/> generate code with xtask
 - <csr-id-8327ffbb8d77e39046f851ca0f38ed153e140715/> xdp BPF_LINK_CREATE was added in 5.9
 - <csr-id-1e779c520a90daa642a67cf3b986536aa50ad5ef/> obj: implement sane defaults for license and kernel version
   Default to license=GPL and kernel_version=any
 - <csr-id-f11df77f859feee2a88a69b96da4a1a22839c45a/> implement missing bit of retprobes
 - <csr-id-b7369d2763fe8c7061071986c41d1bcb0682f5a7/> sys: fix warning
 - <csr-id-82bcef37906472e7a32fa602cf26a97387590057/> rename gen-bindings to gen-bindings.sh
 - <csr-id-245cd46baba5e1b532c7bf8b3eb732ab398bb529/> tweak error display
 - <csr-id-68a633fe51299ab6feaea370fd7b86740d284731/> support max_entries=0
   When a PerfMap has max_entries=0, set max_entries to the number of
   available CPUs.
 - <csr-id-f56c32b46bdd4c634b1ce6136ecab3c88d202040/> add possible_cpus()
 - <csr-id-0cf5d17e383d240a27d463c89bec5d3a19854e4f/> enable only the std feature for the futures crate
 - <csr-id-2cec04c5781bc7b03c601dbb0cb1c23f3df22385/> add explicit BTF argument to the load API
   Add a `target_btf: Option<Btf>` argument to Bpf::load. None can be
   passed to indicate to skip BTF relocation, for example for kernels that
   don't support it. Some(btf) can be used to pass BTF parsed with
   Btf::from_sys_fs() or Btf::parse/parse_file.
   
   Finally, add a simpler Bpf::load_file(path) that uses from_sys_fs()
   internally to simplify the common case.
 - <csr-id-55d8bcf3860d2cf5db7f59b8b5caaa32de6e668d/> add support for attaching with custom xdp flags
 - <csr-id-d326038cf4b0a6fe7966de038054966bf3016380/> rework ProgramError a bit
   Move type specific errors to XdpError SocketFilterError etc.
   
   Annotate all source errors with #[source]
 - <csr-id-f88ca1f1f1449db1a4a323a67edf0ac5a4878ee1/> add internal API to create links
 - <csr-id-ba992a2414430387737e76db2e10b04c98f56847/> fail new() for high level wrappers if the underlying map hasn't been created
 - <csr-id-14c98455a940d6cead424b7e30a62845c256ae26/> remove unused methods
 - <csr-id-fdc4dad5ff88a419d982f67568f5271c69e73f0a/> add AsyncPerfMap
   When the async_tokio or async_std features are enabled, AsyncPerfMap
   provides an async version of PerfMap which returns a future from
   read_events()
 - <csr-id-4be0c45305f0b0c639bfb6b645848fd4e1e0774f/> split in sub modules
 - <csr-id-95a24c6f8b2483f05afabb0b3afaacfea4ebe061/> implement AsRawFd

### Commit Statistics

<csr-read-only-do-not-edit/>

 - 121 commits contributed to the release over the course of 110 calendar days.
 - 102 commits were understood as [conventional](https://www.conventionalcommits.org).
 - 0 issues like '(#ID)' were seen in commit messages

### Commit Details

<csr-read-only-do-not-edit/>

<details><summary>view details</summary>

 * **Uncategorized**
    - Copy readme into aya/ ([`94b5e2e`](https://github.com/aya-rs/aya/commit/94b5e2e4e6a535ca74113c5f62c4bd1a7f265469))
    - Add more fields to Cargo.toml ([`7694bac`](https://github.com/aya-rs/aya/commit/7694bacf04f5ba3cf58b4e432ff746ce2987d67d))
    - Doc fixes ([`be0b7bb`](https://github.com/aya-rs/aya/commit/be0b7bbd832a0321018c78b0c008a4280bd1da6e))
    - Bump version to 0.10 ([`9f7b017`](https://github.com/aya-rs/aya/commit/9f7b017d5d4a4eb63c98c258e3b382628e711253))
    - Add doc aliases for maps and programs ([`768640d`](https://github.com/aya-rs/aya/commit/768640dd4696eaf8c76d7a8b15ab195b3979b281))
    - More docs ([`293e66a`](https://github.com/aya-rs/aya/commit/293e66af65566942b424bbc0c9e5a2cd1be69599))
    - Refactor tc code a bit and add docs ([`ad58e17`](https://github.com/aya-rs/aya/commit/ad58e171ff1645d02998b399db6535a226b5a5ec))
    - More docs ([`11e21e8`](https://github.com/aya-rs/aya/commit/11e21e83bedc8de2b7290d5546b36f47a981266a))
    - More doc fixes ([`6c7df27`](https://github.com/aya-rs/aya/commit/6c7df27bd03e658ebe7855d865377c2cc6e57e52))
    - Improve async perf map docs ([`28158e6`](https://github.com/aya-rs/aya/commit/28158e6028b12efad61d159c3b505d58a03bfd8a))
    - Tweak PerfEventArray docs ([`6ecf7da`](https://github.com/aya-rs/aya/commit/6ecf7dabf35f22869a95a8cd176b6f217ee57b05))
    - ProgramArray: more doc fixes ([`6772595`](https://github.com/aya-rs/aya/commit/6772595f3ea2d0178e02efc97a2fe2a789a04b24))
    - ProgramArray: tweak docs ([`4bde0c5`](https://github.com/aya-rs/aya/commit/4bde0c54bdcf6f749f6b6034874cf1bfecb0b08f))
    - Implement ProgramFd for CgroupSkb ([`2cda5db`](https://github.com/aya-rs/aya/commit/2cda5dbbe74e5d41ce7e2c895678b853d2867001))
    - Fix CgroupSkb docs ([`2d7b9b2`](https://github.com/aya-rs/aya/commit/2d7b9b2e904e2435527d6640e631195ffbd7e050))
    - Programs: add support for BPF_PROG_TYPE_CGROUP_SKB programs ([`08a68fa`](https://github.com/aya-rs/aya/commit/08a68faf8a8baa344dd6fee64529ad2dcc0a0846))
    - Programs: fix detaching programs attached with bpf_prog_attach ([`fb3e2f7`](https://github.com/aya-rs/aya/commit/fb3e2f7f9d06b22c7fe44eccefc2ce94ad322ed0))
    - Programs: fix syscall name in errors ([`6658025`](https://github.com/aya-rs/aya/commit/665802594c2181ae890b3655867944a3fef11508))
    - Handle reordered functions ([`81a0b61`](https://github.com/aya-rs/aya/commit/81a0b61164079ca276d23e0f31f2853087650198))
    - Improve call relocation error messages ([`b92b1e1`](https://github.com/aya-rs/aya/commit/b92b1e18a97135684907d238578146f7aabacc84))
    - BpfError: set the #[source] attribute for RelocationErrors ([`20b2d4c`](https://github.com/aya-rs/aya/commit/20b2d4c77dbc1597f68e6ae16a55d129e42b5c5d))
    - Add support for attaching and detaching TC programs ([`6974d34`](https://github.com/aya-rs/aya/commit/6974d349e8f86c98f450122788efeedecbf61970))
    - Add support for Stack and Queue maps ([`31f8d71`](https://github.com/aya-rs/aya/commit/31f8d71604f4eddd7981cd72e1deb01d2076f7f4))
    - Add id and pinning fields to bpf_map_def ([`40b7da6`](https://github.com/aya-rs/aya/commit/40b7da6655aca6aed5dfe72a0db80bf0e67c2ce1))
    - Netlink: improve error messages ([`dc4e020`](https://github.com/aya-rs/aya/commit/dc4e020f29acc544bb49a74bbad4c553f370d0f3))
    - Add support for BPF_PROG_TYPE_SCHED_CLS programs ([`5effc97`](https://github.com/aya-rs/aya/commit/5effc972ac04960d0346e1f5504b595a206fc019))
    - Perf_map: fix bug when max_entries=0 ([`4222b14`](https://github.com/aya-rs/aya/commit/4222b140ec594e99e77cda8539b16f21820ae155))
    - Update generated bindings ([`3b7ffd0`](https://github.com/aya-rs/aya/commit/3b7ffd0048a5250ca160f8a7b584bf0ea73eb249))
    - Xdp: fix detaching on kernels older than 5.7 ([`30d2b25`](https://github.com/aya-rs/aya/commit/30d2b25f1173904b2542a25792d7dff5b97b837f))
    - Xdp: set flags when attaching with netlink ([`607cf68`](https://github.com/aya-rs/aya/commit/607cf68a692be60eb9f44d26352c513ea6295456))
    - Fix BpfError display strings ([`bb7728a`](https://github.com/aya-rs/aya/commit/bb7728a2c5905923534e51bd53d8d5720f7319e1))
    - Fix warnings ([`9e12c93`](https://github.com/aya-rs/aya/commit/9e12c9324c623bf751053ff874bc47055343753e))
    - Programs: rework load_program() retry code a bit ([`9a24f20`](https://github.com/aya-rs/aya/commit/9a24f20e6f85d9ff2e438dddb3530b88e9583851))
    - Programs: add support for SkMsg programs ([`1441754`](https://github.com/aya-rs/aya/commit/144175434f5b07ac7379be6e30a4b613c225f21b))
    - Maps: add SockHash ([`dad300c`](https://github.com/aya-rs/aya/commit/dad300c88bdfade10f8318fcbbe9a8b5e4de89ce))
    - Add support for SockOps programs ([`ca4b3bf`](https://github.com/aya-rs/aya/commit/ca4b3bfc0462b445f2aae56f9d4c2a80581eda39))
    - Add support BPF_PROG_TYPE_SK_SKB programs and SockMaps ([`b57cace`](https://github.com/aya-rs/aya/commit/b57cace941333910891462127ce0199ae01c3c7c))
    - Fix program array key size ([`b6cd813`](https://github.com/aya-rs/aya/commit/b6cd813af5fbd290a1f2e80b08c170ab868dfb3f))
    - Small doc fixes ([`0b3e532`](https://github.com/aya-rs/aya/commit/0b3e532d7a4a8fe575b41f64d94cfedab10c36ea))
    - More docs ([`79f1b38`](https://github.com/aya-rs/aya/commit/79f1b385a5366cc6f9a6a84172ab131850028a87))
    - Consolidate errors into ProgramError::SyscallError ([`683a58e`](https://github.com/aya-rs/aya/commit/683a58ea6dfaeb65d00ea3cf63b215cd82fd3d5a))
    - Split aya::programs::probe into ::kprobe and ::uprobe & add docs ([`ae863bc`](https://github.com/aya-rs/aya/commit/ae863bc663bde69eb71d5c1ec265b0d4c205f7ff))
    - Add maps::StackTraceMap ([`d9634ae`](https://github.com/aya-rs/aya/commit/d9634ae945ba09bedfc10c748e4e35a6ca3bfde8))
    - Add util::kernel_symbols() ([`67c9cc0`](https://github.com/aya-rs/aya/commit/67c9cc03597e6f00bb6917a493cd9bb405a05b4d))
    - Add bpf_map_lookup_elem_ptr ([`2cdb10e`](https://github.com/aya-rs/aya/commit/2cdb10e7f2734d85bd8ab115a081f4d1a8b2e2ed))
    - Tweak docs ([`ad6d059`](https://github.com/aya-rs/aya/commit/ad6d0596ab076aac84c12425ab493e6b6f24477d))
    - Rename ProgramArray::unset to ProgramArray::clear_index ([`f464279`](https://github.com/aya-rs/aya/commit/f4642797408d31c8375562ead9f4480e8579f59d))
    - Rename ProgramArray::keys to ProgramArray::indices ([`9ad2a5e`](https://github.com/aya-rs/aya/commit/9ad2a5e72d269724953f0f311e803a88637af2ee))
    - Maps: add PerCpuArray ([`b0364f7`](https://github.com/aya-rs/aya/commit/b0364f76aba500464470628f719b5ca7aab4b36a))
    - Rework IterableMap and ProgramArray ([`74d5f17`](https://github.com/aya-rs/aya/commit/74d5f17559036c2eb42d4679ff98fe2ab7e76d4f))
    - PerCpuKernelMem doesn't need to be public ([`aa3a30d`](https://github.com/aya-rs/aya/commit/aa3a30d1965d96f3b6fc345be763561e6270f2ae))
    - Add aya::maps::Array ([`1746bbf`](https://github.com/aya-rs/aya/commit/1746bbf5b83a5b392f39eefe02fc3731db77d893))
    - Add aya::maps::array and move ProgramArray under it ([`c3b9021`](https://github.com/aya-rs/aya/commit/c3b902137becc48b72091ba59a9a4e297ba56d33))
    - Hash_map: add doc aliases for HASH and LRU_HASH ([`6cec8be`](https://github.com/aya-rs/aya/commit/6cec8be564a590717e9af7eb007f3f5d10ffff0e))
    - Per_cpu_hash_map: add support for BPF_MAP_TYPE_LRU_PERCPU_HASH ([`7a989b4`](https://github.com/aya-rs/aya/commit/7a989b43b9ee5b4807f53001c2d7d8824a162a34))
    - Maps: introduce MapError::KeyNotFound ([`635dcd4`](https://github.com/aya-rs/aya/commit/635dcd44b9135dd75d958909f76da28676e6efe7))
    - Rename MapError::NotFound to MapError::MapNotFound ([`fd142e4`](https://github.com/aya-rs/aya/commit/fd142e467c32b6aa4b0d2e8d62816a63c1fa4220))
    - Add PerCpuHashMap ([`3a5b289`](https://github.com/aya-rs/aya/commit/3a5b28916385b35824bc2a05606808e5e8c1968a))
    - Move hash_map.rs to hash_map/hash_map.rs ([`d5098c9`](https://github.com/aya-rs/aya/commit/d5098c9e575b7d5447506648ebeae146192eeda1))
    - Hash_map: factor out common hash code ([`6a12a48`](https://github.com/aya-rs/aya/commit/6a12a48f0360456452c34737c5d52cd289ce23e8))
    - Fix warnings ([`ac83273`](https://github.com/aya-rs/aya/commit/ac83273da86c5d10100f58563a9d764a79183367))
    - Don't export VerifierLog ([`46e0a2e`](https://github.com/aya-rs/aya/commit/46e0a2ede4e423e620acd55f3ed4f755aa8c8b38))
    - HashMap: add support for LRU maps ([`7c6ae76`](https://github.com/aya-rs/aya/commit/7c6ae769756a9605f7823e36243b69a3a88a1370))
    - More docs ([`04fde46`](https://github.com/aya-rs/aya/commit/04fde468556ace883009b4abe63840aa7b89f29f))
    - Tweak docs ([`eea27f5`](https://github.com/aya-rs/aya/commit/eea27f52f3d6455d97838e833b36f6c846c99cb7))
    - Rename perf map and add docs ([`5aa9cb1`](https://github.com/aya-rs/aya/commit/5aa9cb12ade0014d64582864e66bbeae593f6edc))
    - Maps: add docs and make the hash_map and program_array modules public ([`d94bfde`](https://github.com/aya-rs/aya/commit/d94bfde29521fa6fc1d661d1976d4800dd10b1d8))
    - Add HashMap docs ([`ce3f83a`](https://github.com/aya-rs/aya/commit/ce3f83acb11388f2c0b07a8b1de95c7df22b97f9))
    - Make HashMap::new private ([`e28da88`](https://github.com/aya-rs/aya/commit/e28da8812ed5d9e76e764fbc28312e8588aff2af))
    - Add ProgramArray docs ([`24f7c37`](https://github.com/aya-rs/aya/commit/24f7c37158ede0217354d8c6305904737980f292))
    - Make ProgramArray::new private ([`3fddc81`](https://github.com/aya-rs/aya/commit/3fddc8165c6e2c28c4fda19e72156b640da4a0c7))
    - Remove pop() ([`6682a5f`](https://github.com/aya-rs/aya/commit/6682a5ff395d8fbea20393ff81140adcfc2a0c09))
    - Add some docs for the crate and `Bpf` ([`1bbbf61`](https://github.com/aya-rs/aya/commit/1bbbf616b6bedef4a6d42cd630ecd7e3b9366dc5))
    - Maps: group syscall errors into MapError::SyscallError ([`563ce46`](https://github.com/aya-rs/aya/commit/563ce46118258805892bdff97f0e57b2838e0de8))
    - Fix bindings for PERF_EVENT_IOC_{ENABLE|DISABLE|SET_BPF} ([`f9554d6`](https://github.com/aya-rs/aya/commit/f9554d6db5c1fe3c906c798bc9b2a9c28fb0db7b))
    - Remove TryInto magic from program()/program_mut() too ([`a92bfeb`](https://github.com/aya-rs/aya/commit/a92bfebf50df2c56bca242c6a9c3dedd04135675))
    - Remove TryInto cleverness from map() and map_mut() ([`42e0a65`](https://github.com/aya-rs/aya/commit/42e0a659b2f82cca537d70f906e0a475f0ab6b03))
    - Fix some badly completed match arms ([`d3482c0`](https://github.com/aya-rs/aya/commit/d3482c063ca888a6465f3e8866d5d3de93cbbd99))
    - Fix verifier log handling ([`ee05f9d`](https://github.com/aya-rs/aya/commit/ee05f9d9497ea83ee9cfffbaa0d1b87d9d57c26e))
    - Add support for function calls ([`92b4ed2`](https://github.com/aya-rs/aya/commit/92b4ed2664264b4af36b29c7b08d13505eae9b08))
    - Section: collecting relocations can't fail anymore ([`8b0eee3`](https://github.com/aya-rs/aya/commit/8b0eee317d71f0139ec030b1f0583edf8670c296))
    - Obj: rename symbol_table to symbols_by_index ([`318c16c`](https://github.com/aya-rs/aya/commit/318c16cea32731613339d22fad11a29be8d79976))
    - Add Program::name() and make ::prog_type() public ([`286e117`](https://github.com/aya-rs/aya/commit/286e117fe0bab8542f2e1d5fd309562689d88c00))
    - Bpf: Add Bpf::programs() ([`0199e4b`](https://github.com/aya-rs/aya/commit/0199e4b29704df4cebf65d3d5f09ab1af6982cbd))
    - Bpf: remove lifetime param from previous signature ([`dcb5121`](https://github.com/aya-rs/aya/commit/dcb5121985113e1b90a5e50a43d71b4f00826ebe))
    - Maps: add Map::name() and Map::map_type() ([`ed53f74`](https://github.com/aya-rs/aya/commit/ed53f7470b386f3a870e34399bbb52c6ea72d07d))
    - Add Bpf::maps() to get all the maps ([`0a493ba`](https://github.com/aya-rs/aya/commit/0a493baed6b4d020ed7d5d87191d912662eb2159))
    - Switch to rustified enums ([`29f2d9b`](https://github.com/aya-rs/aya/commit/29f2d9b2d9e4265d0d0d2f13c314ef27d5c4ebcf))
    - Generate code with xtask ([`59ed237`](https://github.com/aya-rs/aya/commit/59ed237343c16ba0b96f917991a7ec2f971ecd5d))
    - Xdp BPF_LINK_CREATE was added in 5.9 ([`8327ffb`](https://github.com/aya-rs/aya/commit/8327ffbb8d77e39046f851ca0f38ed153e140715))
    - Obj: implement sane defaults for license and kernel version ([`1e779c5`](https://github.com/aya-rs/aya/commit/1e779c520a90daa642a67cf3b986536aa50ad5ef))
    - Implement missing bit of retprobes ([`f11df77`](https://github.com/aya-rs/aya/commit/f11df77f859feee2a88a69b96da4a1a22839c45a))
    - Sys: fix warning ([`b7369d2`](https://github.com/aya-rs/aya/commit/b7369d2763fe8c7061071986c41d1bcb0682f5a7))
    - Rename gen-bindings to gen-bindings.sh ([`82bcef3`](https://github.com/aya-rs/aya/commit/82bcef37906472e7a32fa602cf26a97387590057))
    - Tweak error display ([`245cd46`](https://github.com/aya-rs/aya/commit/245cd46baba5e1b532c7bf8b3eb732ab398bb529))
    - Fix build with musl ([`3e8a279`](https://github.com/aya-rs/aya/commit/3e8a279a5910badd4720c06f2a046e47e6a6f657))
    - Support max_entries=0 ([`68a633f`](https://github.com/aya-rs/aya/commit/68a633fe51299ab6feaea370fd7b86740d284731))
    - Add possible_cpus() ([`f56c32b`](https://github.com/aya-rs/aya/commit/f56c32b46bdd4c634b1ce6136ecab3c88d202040))
    - Format fixes ([`a3ab2ef`](https://github.com/aya-rs/aya/commit/a3ab2eff57c55faf323d9663e9198851abdc3e2f))
    - Enable only the std feature for the futures crate ([`0cf5d17`](https://github.com/aya-rs/aya/commit/0cf5d17e383d240a27d463c89bec5d3a19854e4f))
    - Fix RawFd import paths ([`3abe9bb`](https://github.com/aya-rs/aya/commit/3abe9bb859320063484c5d222f8322bf8392fec2))
    - Add explicit BTF argument to the load API ([`2cec04c`](https://github.com/aya-rs/aya/commit/2cec04c5781bc7b03c601dbb0cb1c23f3df22385))
    - Add support for attaching with custom xdp flags ([`55d8bcf`](https://github.com/aya-rs/aya/commit/55d8bcf3860d2cf5db7f59b8b5caaa32de6e668d))
    - Rework ProgramError a bit ([`d326038`](https://github.com/aya-rs/aya/commit/d326038cf4b0a6fe7966de038054966bf3016380))
    - Add internal API to create links ([`f88ca1f`](https://github.com/aya-rs/aya/commit/f88ca1f1f1449db1a4a323a67edf0ac5a4878ee1))
    - Fail new() for high level wrappers if the underlying map hasn't been created ([`ba992a2`](https://github.com/aya-rs/aya/commit/ba992a2414430387737e76db2e10b04c98f56847))
    - Trim deps a bit more ([`873691d`](https://github.com/aya-rs/aya/commit/873691d050e5156c9f4fb271d6b13a25d0952564))
    - The futures crate is only needed when async is enabled ([`f1da541`](https://github.com/aya-rs/aya/commit/f1da5412342e6839e80555912f08a13a9e3a976c))
    - Remove unused methods ([`14c9845`](https://github.com/aya-rs/aya/commit/14c98455a940d6cead424b7e30a62845c256ae26))
    - Fix warnings ([`a5e19fc`](https://github.com/aya-rs/aya/commit/a5e19fc4ac3cd53ca8f1d1d43fbc0dfa08aa8d55))
    - Add AsyncPerfMap ([`fdc4dad`](https://github.com/aya-rs/aya/commit/fdc4dad5ff88a419d982f67568f5271c69e73f0a))
    - Split in sub modules ([`4be0c45`](https://github.com/aya-rs/aya/commit/4be0c45305f0b0c639bfb6b645848fd4e1e0774f))
    - Implement AsRawFd ([`95a24c6`](https://github.com/aya-rs/aya/commit/95a24c6f8b2483f05afabb0b3afaacfea4ebe061))
    - Add IOError variants to PerfMapError and PerfBufferError ([`5d6fe8b`](https://github.com/aya-rs/aya/commit/5d6fe8bdf4f31bbb694b83c83127cf9f598f3716))
    - Make aya::maps::perf_map public ([`b9be2f1`](https://github.com/aya-rs/aya/commit/b9be2f1a9b61631df0189b40881b778e9e278e43))
    - Change the suffix of errors from *Failed to *Error ([`160e0be`](https://github.com/aya-rs/aya/commit/160e0be6d6aec27a31c6108810fc4853f25f6a53))
    - Bpf, perf_map: make maps usable from multiple threads ([`d4e2825`](https://github.com/aya-rs/aya/commit/d4e282535b9a780006786758a4b91856b401ac77))
    - Make online_cpus() util public ([`d7c91ef`](https://github.com/aya-rs/aya/commit/d7c91efb2deb77f1a76489375888d01b27f0e710))
    - Generate arch  specific bindings ([`2215e20`](https://github.com/aya-rs/aya/commit/2215e202f431fc25449541fcbbdb65ff096f3132))
    - Add src/generated/netlink_bindings.rs to repo ([`1de3929`](https://github.com/aya-rs/aya/commit/1de392964b8f447615579d231a36e3bb9260b027))
    - Turn the project into a workspace, move code under aya/ ([`af8f769`](https://github.com/aya-rs/aya/commit/af8f769b509e4a002c3bd3138fe745ae962de2db))
</details>

