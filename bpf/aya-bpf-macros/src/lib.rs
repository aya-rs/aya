mod expand;

use expand::{
    Args, Lsm, Map, PerfEvent, Probe, ProbeKind, RawTracePoint, SchedClassifier, SkMsg, SockOps,
    TracePoint, Xdp,
};
use proc_macro::TokenStream;
use syn::{parse_macro_input, ItemFn, ItemStatic};

use crate::expand::CgroupSkb;

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
