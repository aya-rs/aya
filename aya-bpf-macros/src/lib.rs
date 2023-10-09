pub(crate) mod args;
mod btf_tracepoint;
mod cgroup_device;
mod cgroup_skb;
mod cgroup_sock;
mod cgroup_sock_addr;
mod cgroup_sockopt;
mod cgroup_sysctl;
mod fentry;
mod fexit;
mod flow_dissector;
mod kprobe;
mod lsm;
mod map;
mod perf_event;
mod raw_tracepoint;
mod sk_lookup;
mod sk_msg;
mod sk_skb;
mod sock_ops;
mod socket_filter;
mod tc;
mod tracepoint;
mod uprobe;
mod xdp;

use btf_tracepoint::BtfTracePoint;
use cgroup_device::CgroupDevice;
use cgroup_skb::CgroupSkb;
use cgroup_sock::CgroupSock;
use cgroup_sock_addr::CgroupSockAddr;
use cgroup_sockopt::CgroupSockopt;
use cgroup_sysctl::CgroupSysctl;
use fentry::FEntry;
use fexit::FExit;
use flow_dissector::FlowDissector;
use kprobe::{KProbe, KProbeKind};
use lsm::Lsm;
use map::Map;
use perf_event::PerfEvent;
use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use raw_tracepoint::RawTracePoint;
use sk_lookup::SkLookup;
use sk_msg::SkMsg;
use sk_skb::{SkSkb, SkSkbKind};
use sock_ops::SockOps;
use socket_filter::SocketFilter;
use tc::SchedClassifier;
use tracepoint::TracePoint;
use uprobe::{UProbe, UProbeKind};
use xdp::Xdp;
#[proc_macro_error]
#[proc_macro_attribute]
pub fn map(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match Map::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match KProbe::parse(KProbeKind::KProbe, attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn kretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match KProbe::parse(KProbeKind::KRetProbe, attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn uprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match UProbe::parse(UProbeKind::UProbe, attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn uretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match UProbe::parse(UProbeKind::URetProbe, attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn sock_ops(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SockOps::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn sk_msg(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SkMsg::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Marks a function as an eBPF XDP program that can be attached to a network interface.
///
/// On some NIC drivers, XDP probes are compatible with jumbo frames through the use of
/// multi-buffer packets. Programs can opt-in this support by passing the `frags` argument.
///
/// XDP programs can also be chained through the use of CPU maps and dev maps, but must opt-in
/// with the `map = "cpumap"` or `map = "devmap"` arguments.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.8.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};
///
/// #[xdp(frags)]
/// pub fn xdp(ctx: XdpContext) -> u32 {
///     XDP_PASS
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn xdp(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match Xdp::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn classifier(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SchedClassifier::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_attribute]
pub fn cgroup_sysctl(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match CgroupSysctl::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn cgroup_sockopt(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match CgroupSockopt::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn cgroup_skb(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match CgroupSkb::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Marks a function as a [`CgroupSockAddr`] eBPF program.
///
/// [`CgroupSockAddr`] programs can be used to inspect or modify socket addresses passed to
/// various syscalls within a [cgroup]. The `attach_type` argument specifies a place to attach
/// the eBPF program to. See [`CgroupSockAddrAttachType`] for more details.
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
/// [`CgroupSockAddrAttachType`]: ../aya/programs/cgroup_sock_addr/enum.CgroupSockAddrAttachType.html
/// [`CgroupSockAddr`]: ../aya/programs/cgroup_sock_addr/struct.CgroupSockAddr.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.17.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
///
/// #[cgroup_sock_addr(connect4)]
/// pub fn connect4(ctx: SockAddrContext) -> i32 {
///     match try_connect4(ctx) {
///         Ok(ret) => ret,
///         Err(ret) => match ret.try_into() {
///             Ok(rt) => rt,
///             Err(_) => 1,
///         },
///     }
/// }
///
/// fn try_connect4(ctx: SockAddrContext) -> Result<i32, i64> {
///     Ok(0)
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn cgroup_sock_addr(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match CgroupSockAddr::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
#[proc_macro_error]
#[proc_macro_attribute]
pub fn cgroup_sock(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match CgroupSock::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match TracePoint::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn perf_event(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match PerfEvent::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
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
/// #[raw_tracepoint(tracepoint = "sys_enter")]
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
#[proc_macro_error]
#[proc_macro_attribute]
pub fn raw_tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match RawTracePoint::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Marks a function as an LSM program that can be attached to Linux LSM hooks.
/// Used to implement security policy and audit logging.
///
/// The hook name is the first argument to the macro.
/// You may also provide `sleepable` to mark the program as sleepable.
/// Arguments should be comma separated.
///
/// LSM probes can be attached to the kernel's security hooks to implement mandatory
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
/// #[lsm(hook = "file_open")]
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
#[proc_macro_error]
#[proc_macro_attribute]
pub fn lsm(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match Lsm::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
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
/// #[btf_tracepoint(function = "sched_process_fork")]
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
#[proc_macro_error]
#[proc_macro_attribute]
pub fn btf_tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match BtfTracePoint::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
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
#[proc_macro_error]
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
#[proc_macro_error]
#[proc_macro_attribute]
pub fn stream_verdict(attrs: TokenStream, item: TokenStream) -> TokenStream {
    sk_skb(SkSkbKind::StreamVerdict, attrs, item)
}

fn sk_skb(kind: SkSkbKind, attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SkSkb::parse(kind, attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
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
/// #[socket_filter]
/// pub fn accept_all(_ctx: SkBuffContext) -> i64 {
///     return 0
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn socket_filter(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SocketFilter::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
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
/// # #![allow(non_camel_case_types)]
/// use aya_bpf::{macros::fentry, programs::FEntryContext};
/// # type filename = u32;
/// # type path = u32;
///
/// #[fentry(function = "filename_lookup")]
/// fn filename_lookup(ctx: FEntryContext) -> i32 {
///     match unsafe { try_filename_lookup(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_filename_lookup(ctx: FEntryContext) -> Result<i32, i32> {
///     let _f: *const filename = ctx.arg(1);
///     let _p: *const path = ctx.arg(3);
///
///     Ok(0)
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn fentry(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match FEntry::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
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
/// # #![allow(non_camel_case_types)]
/// use aya_bpf::{macros::fexit, programs::FExitContext};
/// # type filename = u32;
/// # type path = u32;
///
/// #[fexit(function = "filename_lookup")]
/// fn filename_lookup(ctx: FExitContext) -> i32 {
///     match unsafe { try_filename_lookup(ctx) } {
///         Ok(ret) => ret,
///         Err(ret) => ret,
///     }
/// }
///
/// unsafe fn try_filename_lookup(ctx: FExitContext) -> Result<i32, i32> {
///     let _f: *const filename = ctx.arg(1);
///     let _p: *const path = ctx.arg(3);
///
///     Ok(0)
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn fexit(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match FExit::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Marks a function as an eBPF Flow Dissector program that can be attached to
/// a network namespace.
///
#[proc_macro_error]
#[proc_macro_attribute]
pub fn flow_dissector(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match FlowDissector::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Marks a function as an eBPF Socket Lookup program that can be attached to
/// a network namespace.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.9
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::sk_lookup, programs::SkLookupContext};
///
/// #[sk_lookup]
/// pub fn accept_all(_ctx: SkLookupContext) -> u32 {
///     // use sk_assign to redirect
///     return 0
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn sk_lookup(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SkLookup::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Marks a function as a cgroup device eBPF program that can be attached to a
/// cgroup.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.15.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{
///     macros::cgroup_device,
///     programs::DeviceContext,
/// };
///
/// #[cgroup_device]
/// pub fn cgroup_dev(ctx: DeviceContext) -> i32 {
///     // Reject all device access
///     return 0;
/// }
/// ```
#[proc_macro_error]
#[proc_macro_attribute]
pub fn cgroup_device(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match CgroupDevice::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}
