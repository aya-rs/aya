//! A collection of system calls for performing eBPF related operations.

mod bpf;
mod netlink;
mod perf_event;

#[cfg(test)]
mod fake;

use std::{
    ffi::{c_int, c_void},
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd},
};

pub(crate) use bpf::*;
#[cfg(test)]
pub(crate) use fake::*;
use libc::{pid_t, SYS_bpf, SYS_perf_event_open};
#[doc(hidden)]
pub use netlink::netlink_set_link_up;
pub(crate) use netlink::*;
pub(crate) use perf_event::*;

use crate::{
    errors::SysError,
    generated::{bpf_attr, bpf_cmd, perf_event_attr},
};

pub(crate) type SysResult<T> = Result<T, (i64, SysError)>;

pub(crate) enum Syscall<'a> {
    Ebpf {
        cmd: BpfCmd,
        attr: &'a mut bpf_attr,
    },
    PerfEventOpen {
        attr: perf_event_attr,
        pid: pid_t,
        cpu: i32,
        group: i32,
        flags: u32,
    },
    PerfEventIoctl {
        fd: BorrowedFd<'a>,
        request: c_int,
        arg: c_int,
    },
}

#[derive(Copy, Clone)]
pub(crate) enum BpfCmd {
    MapCreate,
    MapLookupElem,
    MapUpdateElem,
    MapDeleteElem,
    MapGetNextKey,
    ProgLoad,
    ObjPin,
    ObjGet,
    ProgAttach,
    ProgDetach,
    ProgTestRun,
    ProgGetNextId,
    MapGetNextId,
    ProgGetFdById,
    MapGetFdById,
    ObjGetInfoByFd,
    ProgQuery,
    RawTracepointOpen,
    BtfLoad,
    BtfGetFdById,
    TaskFdQuery,
    MapLookupAndDeleteElem,
    MapFreeze,
    BtfGetNextId,
    MapLookupBatch,
    MapLookupAndDeleteBatch,
    MapUpdateBatch,
    MapDeleteBatch,
    LinkCreate,
    LinkUpdate,
    LinkGetFdById,
    LinkGetNextId,
    EnableStats,
    IterCreate,
    LinkDetach,
    ProgBindMap,
    TokenCreate,
    Max,
}

impl From<bpf_cmd> for BpfCmd {
    fn from(value: bpf_cmd) -> Self {
        use bpf_cmd::*;
        match value {
            BPF_MAP_CREATE => Self::MapCreate,
            BPF_MAP_LOOKUP_ELEM => Self::MapLookupElem,
            BPF_MAP_UPDATE_ELEM => Self::MapUpdateElem,
            BPF_MAP_DELETE_ELEM => Self::MapDeleteElem,
            BPF_MAP_GET_NEXT_KEY => Self::MapGetNextKey,
            BPF_PROG_LOAD => Self::ProgLoad,
            BPF_OBJ_PIN => Self::ObjPin,
            BPF_OBJ_GET => Self::ObjGet,
            BPF_PROG_ATTACH => Self::ProgAttach,
            BPF_PROG_DETACH => Self::ProgDetach,
            BPF_PROG_TEST_RUN => Self::ProgTestRun,
            BPF_PROG_GET_NEXT_ID => Self::ProgGetNextId,
            BPF_MAP_GET_NEXT_ID => Self::MapGetNextId,
            BPF_PROG_GET_FD_BY_ID => Self::ProgGetFdById,
            BPF_MAP_GET_FD_BY_ID => Self::MapGetFdById,
            BPF_OBJ_GET_INFO_BY_FD => Self::ObjGetInfoByFd,
            BPF_PROG_QUERY => Self::ProgQuery,
            BPF_RAW_TRACEPOINT_OPEN => Self::RawTracepointOpen,
            BPF_BTF_LOAD => Self::BtfLoad,
            BPF_BTF_GET_FD_BY_ID => Self::BtfGetFdById,
            BPF_TASK_FD_QUERY => Self::TaskFdQuery,
            BPF_MAP_LOOKUP_AND_DELETE_ELEM => Self::MapLookupAndDeleteElem,
            BPF_MAP_FREEZE => Self::MapFreeze,
            BPF_BTF_GET_NEXT_ID => Self::BtfGetNextId,
            BPF_MAP_LOOKUP_BATCH => Self::MapLookupBatch,
            BPF_MAP_LOOKUP_AND_DELETE_BATCH => Self::MapLookupAndDeleteBatch,
            BPF_MAP_UPDATE_BATCH => Self::MapUpdateBatch,
            BPF_MAP_DELETE_BATCH => Self::MapDeleteBatch,
            BPF_LINK_CREATE => Self::LinkCreate,
            BPF_LINK_UPDATE => Self::LinkUpdate,
            BPF_LINK_GET_FD_BY_ID => Self::LinkGetFdById,
            BPF_LINK_GET_NEXT_ID => Self::LinkGetNextId,
            BPF_ENABLE_STATS => Self::EnableStats,
            BPF_ITER_CREATE => Self::IterCreate,
            BPF_LINK_DETACH => Self::LinkDetach,
            BPF_PROG_BIND_MAP => Self::ProgBindMap,
            BPF_TOKEN_CREATE => Self::TokenCreate,
            __MAX_BPF_CMD => Self::Max,
        }
    }
}

impl std::fmt::Debug for BpfCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MapCreate => f.write_str("bpf_map_create"),
            Self::MapLookupElem => f.write_str("bpf_map_lookup_elem"),
            Self::MapUpdateElem => f.write_str("bpf_map_update_elem"),
            Self::MapDeleteElem => f.write_str("bpf_map_delete_elem"),
            Self::MapGetNextKey => f.write_str("bpf_map_get_next_key"),
            Self::ProgLoad => f.write_str("bpf_prog_load"),
            Self::ObjPin => f.write_str("bpf_obj_pin"),
            Self::ObjGet => f.write_str("bpf_obj_get"),
            Self::ProgAttach => f.write_str("bpf_prog_attach"),
            Self::ProgDetach => f.write_str("bpf_prog_detach"),
            Self::ProgTestRun => f.write_str("bpf_prog_test_run"),
            Self::ProgGetNextId => f.write_str("bpf_prog_get_next_id"),
            Self::MapGetNextId => f.write_str("bpf_map_get_next_id"),
            Self::ProgGetFdById => f.write_str("bpf_prog_get_fd_by_id"),
            Self::MapGetFdById => f.write_str("bpf_map_get_fd_by_id"),
            Self::ObjGetInfoByFd => f.write_str("bpf_obj_get_info_by_fd"),
            Self::ProgQuery => f.write_str("bpf_prog_query"),
            Self::RawTracepointOpen => f.write_str("bpf_raw_tracepoint_open"),
            Self::BtfLoad => f.write_str("bpf_btf_load"),
            Self::BtfGetFdById => f.write_str("bpf_btf_get_fd_by_id"),
            Self::TaskFdQuery => f.write_str("bpf_task_fd_query"),
            Self::MapLookupAndDeleteElem => f.write_str("bpf_map_lookup_and_delete_elem"),
            Self::MapFreeze => f.write_str("bpf_map_freeze"),
            Self::BtfGetNextId => f.write_str("bpf_btf_get_next_id"),
            Self::MapLookupBatch => f.write_str("bpf_map_lookup_batch"),
            Self::MapLookupAndDeleteBatch => f.write_str("bpf_map_lookup_and_delete_batch"),
            Self::MapUpdateBatch => f.write_str("bpf_map_update_batch"),
            Self::MapDeleteBatch => f.write_str("bpf_map_delete_batch"),
            Self::LinkCreate => f.write_str("bpf_link_create"),
            Self::LinkUpdate => f.write_str("bpf_link_update"),
            Self::LinkGetFdById => f.write_str("bpf_link_get_fd_by_id"),
            Self::LinkGetNextId => f.write_str("bpf_link_get_next_id"),
            Self::EnableStats => f.write_str("bpf_enable_stats"),
            Self::IterCreate => f.write_str("bpf_iter_create"),
            Self::LinkDetach => f.write_str("bpf_link_detach"),
            Self::ProgBindMap => f.write_str("bpf_prog_bind_map"),
            Self::TokenCreate => f.write_str("bpf_token_create"),
            Self::Max => f.write_str("MAX"),
        }
    }
}

impl std::fmt::Debug for Syscall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ebpf { cmd, attr: _ } => f
                .debug_struct("Syscall::Ebpf")
                .field("cmd", cmd)
                .field("attr", &format_args!("_"))
                .finish(),
            Self::PerfEventOpen {
                attr: _,
                pid,
                cpu,
                group,
                flags,
            } => f
                .debug_struct("Syscall::PerfEventOpen")
                .field("attr", &format_args!("_"))
                .field("pid", pid)
                .field("cpu", cpu)
                .field("group", group)
                .field("flags", flags)
                .finish(),
            Self::PerfEventIoctl { fd, request, arg } => f
                .debug_struct("Syscall::PerfEventIoctl")
                .field("fd", fd)
                .field("request", request)
                .field("arg", arg)
                .finish(),
        }
    }
}

fn syscall(call: Syscall<'_>) -> SysResult<i64> {
    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });

    #[cfg_attr(test, allow(unreachable_code))]
    {
        let call_name = format!("{:?}", call);
        let ret = unsafe {
            match call {
                Syscall::Ebpf { cmd, attr } => {
                    libc::syscall(SYS_bpf, cmd, attr, mem::size_of::<bpf_attr>())
                }
                Syscall::PerfEventOpen {
                    attr,
                    pid,
                    cpu,
                    group,
                    flags,
                } => libc::syscall(SYS_perf_event_open, &attr, pid, cpu, group, flags),
                Syscall::PerfEventIoctl { fd, request, arg } => {
                    let ret = libc::ioctl(fd.as_raw_fd(), request.try_into().unwrap(), arg);
                    // `libc::ioctl` returns i32 on x86_64 while `libc::syscall` returns i64.
                    #[allow(clippy::useless_conversion)]
                    ret.into()
                }
            }
        };

        // `libc::syscall` returns i32 on armv7.
        #[allow(clippy::useless_conversion)]
        match ret.into() {
            ret @ 0.. => Ok(ret),
            ret => Err((
                ret,
                SysError::Syscall {
                    call: call_name,
                    io_error: io::Error::last_os_error(),
                },
            )),
        }
    }
}

#[cfg_attr(test, allow(unused_variables))]
pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: BorrowedFd<'_>,
    offset: libc::off_t,
) -> *mut c_void {
    #[cfg(not(test))]
    return libc::mmap(addr, len, prot, flags, fd.as_raw_fd(), offset);

    #[cfg(test)]
    TEST_MMAP_RET.with(|ret| *ret.borrow())
}

/// The type of eBPF statistic to enable.
#[non_exhaustive]
#[doc(alias = "bpf_stats_type")]
#[derive(Copy, Clone, Debug)]
pub enum Stats {
    /// Tracks [`run_time`](crate::programs::ProgramInfo::run_time) and
    /// [`run_count`](crate::programs::ProgramInfo::run_count) fields.
    #[doc(alias = "BPF_STATS_RUN_TIME")]
    RunTime,
}

impl From<Stats> for crate::generated::bpf_stats_type {
    fn from(value: Stats) -> Self {
        use crate::generated::bpf_stats_type::*;

        match value {
            Stats::RunTime => BPF_STATS_RUN_TIME,
        }
    }
}

/// Enable global statistics tracking for eBPF programs and returns a
/// [file descriptor](`OwnedFd`) handler.
///
/// Statistics tracking is disabled when the [file descriptor](`OwnedFd`) is
/// dropped (either automatically when the variable goes out of scope or
/// manually through [`Drop`]).
///
/// Usage:
/// 1. Obtain fd from [`enable_stats`] and bind it to a variable.
/// 2. Record the statistic of interest.
/// 3. Wait for a recorded period of time.
/// 4. Record the statistic of interest again, and calculate the difference.
/// 5. Close/release fd automatically or manually.
///
/// Introduced in kernel v5.8.
///
/// # Examples
///
/// ```no_run
/// # use aya::errors::{SysError};
/// use aya::sys::{enable_stats, Stats};
///
/// let _fd = enable_stats(Stats::RunTime)?;
/// # Ok::<(), SysError>(())
/// ```
#[doc(alias = "BPF_ENABLE_STATS")]
pub fn enable_stats(stats_type: Stats) -> Result<OwnedFd, Box<dyn std::error::Error + 'static>> {
    Ok(bpf_enable_stats(stats_type.into())
        .map(|fd| fd.into_inner())
        .map_err(Box::new)?)
}
