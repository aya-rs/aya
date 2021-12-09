mod expand;

use expand::{
    Args, BtfTracePoint, CgroupSkb, FEntry, FExit, Lsm, Map, PerfEvent, Probe, ProbeKind,
    RawTracePoint, SchedClassifier, SkMsg, SkSkb, SkSkbKind, SockOps, SocketFilter, TracePoint,
    Xdp,
};
use proc_macro::TokenStream;
use syn::{parse_macro_input, ItemFn, ItemStatic};

#[proc_macro_attribute]
pub fn map(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemStatic);

    Map::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::KProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn kretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::KRetProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn uprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::UProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn uretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::URetProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn sock_ops(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    SockOps::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn sk_msg(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    SkMsg::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn xdp(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    Xdp::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn classifier(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    SchedClassifier::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn cgroup_skb(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    CgroupSkb::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

fn probe(kind: ProbeKind, attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    Probe::from_syn(kind, args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    TracePoint::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn perf_event(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    PerfEvent::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as a raw tracepoint eBPF program that can be attached at a
/// pre-defined kernel trace point.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See `/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.7.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::raw_tracepoint, programs::RawTracePointContext};
///
/// #[raw_tracepoint(name = "sys_enter")]
/// pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
///     match unsafe { try_sys_enter(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_sys_enter(_ctx: RawTracePointContext) -> Result<i32, i32> {
///     Ok(0)
/// }
/// ```
#[proc_macro_attribute]
pub fn raw_tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    RawTracePoint::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as an LSM program that can be attached to Linux LSM hooks.
/// Used to implement security policy and audit logging.
///
/// LSM probes can be attached to the kernel's [security hooks][1] to implement mandatory
/// access control policy and security auditing.
///
/// LSM probes require a kernel compiled with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
/// In order for the probes to fire, you also need the BPF LSM to be enabled through your
/// kernel's boot paramters (like `lsm=lockdown,yama,bpf`).
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.7.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::lsm, programs::LsmContext};
///
/// #[lsm(name = "file_open")]
/// pub fn file_open(ctx: LsmContext) -> i32 {
///     match unsafe { try_file_open(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_file_open(_ctx: LsmContext) -> Result<i32, i32> {
///     Ok(0)
/// }
/// ```
#[proc_macro_attribute]
pub fn lsm(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    Lsm::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as a [BTF-enabled raw tracepoint][1] eBPF program that can be attached at
/// a pre-defined kernel trace point.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See `/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
///
/// #[btf_tracepoint(name = "sched_process_fork")]
/// pub fn sched_process_fork(ctx: BtfTracePointContext) -> u32 {
///     match unsafe { try_sched_process_fork(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_sched_process_fork(_ctx: BtfTracePointContext) -> Result<u32, u32> {
///     Ok(0)
/// }
/// ```
///
/// [1]: https://github.com/torvalds/linux/commit/9e15db66136a14cde3f35691f1d839d950118826
#[proc_macro_attribute]
pub fn btf_tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    BtfTracePoint::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as a SK_SKB Stream Parser eBPF program that can be attached
/// to a SockMap
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::stream_parser, programs::SkBuffContext};
///
///
///#[stream_parser]
///fn stream_parser(ctx: SkBuffContext) -> u32 {
///    match { try_stream_parser(ctx) } {
///        Ok(ret) => ret,
///        Err(ret) => ret,
///    }
///}
///
///fn try_stream_parser(ctx: SkBuffContext) -> Result<u32, u32> {
///    Ok(ctx.len())
///}
/// ```
#[proc_macro_attribute]
pub fn stream_parser(attrs: TokenStream, item: TokenStream) -> TokenStream {
    sk_skb(SkSkbKind::StreamParser, attrs, item)
}

/// Marks a function as a SK_SKB Stream Verdict eBPF program that can be attached
/// to a SockMap
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::stream_verdict, programs::SkBuffContext, bindings::sk_action};
///
///
///#[stream_verdict]
///fn stream_verdict(ctx: SkBuffContext) -> u32 {
///    match { try_stream_verdict(ctx) } {
///        Ok(ret) => ret,
///        Err(ret) => ret,
///    }
///}
///
///fn try_stream_verdict(_ctx: SkBuffContext) -> Result<u32, u32> {
///    Ok(sk_action::SK_PASS)
///}
/// ```
#[proc_macro_attribute]
pub fn stream_verdict(attrs: TokenStream, item: TokenStream) -> TokenStream {
    sk_skb(SkSkbKind::StreamVerdict, attrs, item)
}

fn sk_skb(kind: SkSkbKind, attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    SkSkb::from_syn(kind, args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as a eBPF Socket Filter program that can be attached to
/// a socket.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::socket_filter, programs::SkBuffContext};
///
/// #[socket_filter(name = "accept_all")]
/// pub fn accept_all(_ctx: SkBuffContext) -> i64 {
///     return 0
/// }
/// ```
#[proc_macro_attribute]
pub fn socket_filter(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    SocketFilter::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as a fentry eBPF program that can be attached to almost
/// any function inside the kernel. The difference between fentry and kprobe
/// is that fexit has practically zero overhead to call before kernel function.
/// fentry programs can be also attached to other eBPF programs.
///
/// # Minimumm kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::fentry, programs::FEntryContext};
/// use vmlinux::{filename, path};
///
/// #[fentry(name = "filename_lookup")]
/// fn filename_lookup(ctx: FEntryContext) -> i32 {
///     match { try_filename_lookup(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_filename_lookup(ctx: FEntryContext) -> Result<u32, u32> {
///     let _f: *const filename = ctx.arg(1);
///     let _p: *const path = ctx.arg(3);
///
///     Ok(0)
/// }
/// ```
#[proc_macro_attribute]
pub fn fentry(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    FEntry::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Marks a function as a fexit eBPF program that can be attached to almost
/// any function inside the kernel. The difference between fexit and kretprobe
/// is that fexit has practically zero overhead to call after kernel function
/// and it focuses on access to arguments rather than the return value. fexit
/// programs can be also attached to other eBPF programs
///
/// # Minimumm kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::fexit, programs::FExitContext};
/// use vmlinux::{filename, path};
///
/// #[fexit(name = "filename_lookup")]
/// fn filename_lookup(ctx: FExitContext) -> i32 {
///     match { try_filename_lookup(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_filename_lookup(ctx: FExitContext) -> Result<u32, u32> {
///     let _f: *const filename = ctx.arg(1);
///     let _p: *const path = ctx.arg(3);
///
///     Ok(0)
/// }
/// ```
#[proc_macro_attribute]
pub fn fexit(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    FExit::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
