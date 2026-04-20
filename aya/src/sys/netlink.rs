use std::{
    ffi::{CStr, CString, FromBytesWithNulError},
    io, iter, mem,
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _},
    ptr,
};

use aya_obj::generated::{
    IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS, TC_H_CLSACT, TC_H_INGRESS, TC_H_MAJ_MASK,
    TC_H_UNSPEC, TCA_BPF_FD, TCA_BPF_FLAG_ACT_DIRECT, TCA_BPF_FLAGS, TCA_BPF_NAME, TCA_KIND,
    TCA_OPTIONS, XDP_FLAGS_REPLACE, ifinfomsg, nlmsgerr_attrs::NLMSGERR_ATTR_MSG, tcmsg,
};
use libc::{
    AF_NETLINK, AF_UNSPEC, ETH_P_ALL, IFF_UP, IFLA_XDP, NETLINK_CAP_ACK, NETLINK_EXT_ACK,
    NETLINK_ROUTE, NLA_ALIGNTO, NLA_F_NESTED, NLA_TYPE_MASK, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP,
    NLM_F_ECHO, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, RTM_DELTFILTER,
    RTM_GETTFILTER, RTM_NEWQDISC, RTM_NEWTFILTER, RTM_SETLINK, SOCK_RAW, SOL_NETLINK, getsockname,
    iovec, nlattr, nlmsgerr, nlmsghdr, recv, setsockopt, sockaddr_nl, socket, writev,
};
use thiserror::Error;

use crate::{
    Pod,
    programs::TcAttachType,
    util::{bytes_of, tc_handler_make},
};

const _: () = assert!(NLA_ALIGNTO < u8::MAX as i32);
macro_rules! nla_align {
    ($v:expr) => {{
        // TODO(https://github.com/rust-lang/rust/issues/143874): use .into() when const_trait_impl is stable.
        #[expect(clippy::as_underscore, reason = "statically known to be less than u8::MAX")]
        let result = $v.next_multiple_of(NLA_ALIGNTO as _);
        result
    }};
}

/// `CLS_BPF_NAME_LEN` from the Linux kernel.
/// <https://github.com/torvalds/linux/blob/v6.19/net/sched/cls_bpf.c#L28>
const CLS_BPF_NAME_LEN: usize = 256;

/// A private error type for internal use in this module.
#[derive(Error, Debug)]
pub(crate) enum NetlinkErrorInternal {
    #[error("netlink error: {messages:?}")]
    Error {
        messages: Vec<CString>,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    NlAttrError(#[from] NlAttrError),
}

/// An error occurred during a netlink operation.
#[derive(Error, Debug)]
#[error(transparent)]
#[expect(
    unnameable_types,
    reason = "the internal error is crate-private but transparently wrapped"
)]
pub struct NetlinkError(#[from] NetlinkErrorInternal);

impl NetlinkError {
    pub fn raw_os_error(&self) -> Option<i32> {
        let Self(inner) = self;
        match inner {
            NetlinkErrorInternal::Error { source, .. } => source.raw_os_error(),
            NetlinkErrorInternal::IoError(err) => err.raw_os_error(),
            NetlinkErrorInternal::NlAttrError(err) => match err {
                NlAttrError::BufferLength { .. }
                | NlAttrError::HeaderLength { .. }
                | NlAttrError::CStrFromBytesWithNul { .. } => None,
            },
        }
    }
}

fn attr_header(attr_type: u16, payload_len: usize) -> [u8; nla_align!(size_of::<nlattr>())] {
    let attr = nlattr {
        nla_type: attr_type,
        nla_len: (size_of::<nlattr>() + payload_len) as u16,
    };
    let mut buf = [0; _];
    buf[..size_of::<nlattr>()].copy_from_slice(bytes_of(&attr));
    buf
}

const fn attr_aligned_len(payload_len: usize) -> usize {
    nla_align!(size_of::<nlattr>() + payload_len)
}

fn attr_padding(payload_len: usize) -> &'static [u8] {
    const ZERO_PADDING: [u8; NLA_ALIGNTO as usize] = [0; NLA_ALIGNTO as usize];

    &ZERO_PADDING[..nla_align!(payload_len) - payload_len]
}

/// # Safety
///
/// This function uses raw file descriptors supplied by the caller.
pub(crate) unsafe fn netlink_set_xdp_fd(
    if_index: i32,
    fd: Option<BorrowedFd<'_>>,
    old_fd: Option<BorrowedFd<'_>>,
    flags: u32,
) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let if_info = ifinfomsg {
        ifi_family: AF_UNSPEC as u8,
        ifi_index: if_index,
        ..unsafe { mem::zeroed() }
    };

    // write the attrs
    let xdp_fd = fd.map_or(-1, |fd| fd.as_raw_fd());
    let xdp_fd_attr = attr_header(IFLA_XDP_FD as u16, size_of_val(&xdp_fd));

    let flags_attr = attr_header(IFLA_XDP_FLAGS as u16, size_of_val(&flags));
    let flags_len = if flags > 0 {
        attr_aligned_len(size_of_val(&flags))
    } else {
        0
    };

    let old_fd = if flags & XDP_FLAGS_REPLACE != 0 {
        old_fd.map(|fd| fd.as_raw_fd()).unwrap()
    } else {
        0
    };
    let expected_fd_attr = attr_header(IFLA_XDP_EXPECTED_FD as u16, size_of_val(&old_fd));
    let expected_fd_len = if flags & XDP_FLAGS_REPLACE != 0 {
        attr_aligned_len(size_of_val(&old_fd))
    } else {
        0
    };

    let xdp_inner_len = attr_aligned_len(size_of_val(&xdp_fd)) + flags_len + expected_fd_len;
    let xdp_attr = attr_header(NLA_F_NESTED as u16 | IFLA_XDP, xdp_inner_len);
    let attrs_len = attr_aligned_len(xdp_inner_len);
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of_val(&if_info) + attrs_len) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    let xdp_outer_padding = attr_padding(xdp_inner_len);
    let fd = bytes_of(&xdp_fd);
    let flags = bytes_of(&flags);
    let old_fd = bytes_of(&old_fd);
    let empty: &[u8] = &[];

    let (flags_attr, flags, flags_padding) = if flags_len == 0 {
        (empty, empty, empty)
    } else {
        (&flags_attr[..], flags, attr_padding(flags.len()))
    };

    let (expected_fd_attr, old_fd, expected_fd_padding) = if expected_fd_len == 0 {
        (empty, empty, empty)
    } else {
        (&expected_fd_attr[..], old_fd, attr_padding(old_fd.len()))
    };

    sock.send([
        bytes_of(&header),
        bytes_of(&if_info),
        &xdp_attr,
        &xdp_fd_attr,
        fd,
        attr_padding(fd.len()),
        flags_attr,
        flags,
        flags_padding,
        expected_fd_attr,
        old_fd,
        expected_fd_padding,
        xdp_outer_padding,
    ])?;
    for msg in sock.recv() {
        msg?;
    }
    Ok(())
}

pub(crate) unsafe fn netlink_qdisc_add_clsact(if_index: i32) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let tc_info = tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm_ifindex: if_index,
        tcm_handle: tc_handler_make(TC_H_CLSACT, TC_H_UNSPEC),
        tcm_parent: tc_handler_make(TC_H_CLSACT, TC_H_INGRESS),
        tcm_info: 0,
        ..unsafe { mem::zeroed() }
    };

    // add the TCA_KIND attribute
    let kind = c"clsact".to_bytes_with_nul();
    let kind_attr = attr_header(TCA_KIND as u16, kind.len());
    let attrs_len = attr_aligned_len(kind.len());
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of_val(&tc_info) + attrs_len) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
        nlmsg_type: RTM_NEWQDISC,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    sock.send([
        bytes_of(&header),
        bytes_of(&tc_info),
        &kind_attr,
        kind,
        attr_padding(kind.len()),
    ])?;
    for msg in sock.recv() {
        msg?;
    }

    Ok(())
}

pub(crate) unsafe fn netlink_qdisc_attach(
    if_index: i32,
    attach_type: &TcAttachType,
    prog_fd: BorrowedFd<'_>,
    prog_name: &CStr,
    priority: u16,
    handle: u32,
    create: bool,
) -> Result<(u16, u32), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    // When create=true, we're creating a new attachment so we must set NLM_F_CREATE. Then we also
    // set NLM_F_EXCL so that attaching fails if there's already a program attached to the given
    // handle.
    //
    // When create=false we're replacing an existing attachment so we must not set either flags.
    //
    // See https://github.com/torvalds/linux/blob/3a87498/net/sched/cls_api.c#L2304
    let request_flags = if create {
        NLM_F_CREATE | NLM_F_EXCL
    } else {
        // NLM_F_REPLACE exists, but seems unused by cls_bpf
        0
    };
    let tc_info = tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm_handle: handle, // auto-assigned, if zero
        tcm_ifindex: if_index,
        tcm_parent: attach_type.tc_parent(),
        tcm_info: tc_handler_make(
            u32::from(priority) << 16,
            u32::from(htons(ETH_P_ALL as u16)),
        ),
        ..unsafe { mem::zeroed() }
    };

    let prog_name = prog_name.to_bytes_with_nul();
    if prog_name.len() > CLS_BPF_NAME_LEN {
        return Err(NetlinkError(NetlinkErrorInternal::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TC BPF name exceeds CLS_BPF_NAME_LEN",
        ))));
    }

    let kind = c"bpf".to_bytes_with_nul();
    let prog_fd = prog_fd.as_raw_fd();
    let flags = TCA_BPF_FLAG_ACT_DIRECT;

    let kind_attr = attr_header(TCA_KIND as u16, kind.len());
    let fd_attr = attr_header(TCA_BPF_FD as u16, size_of_val(&prog_fd));
    let name_attr = attr_header(TCA_BPF_NAME as u16, prog_name.len());
    let flags_attr = attr_header(TCA_BPF_FLAGS as u16, size_of_val(&flags));

    let options_inner_len = attr_aligned_len(size_of_val(&prog_fd))
        + attr_aligned_len(prog_name.len())
        + attr_aligned_len(size_of_val(&flags));
    let options_attr = attr_header(NLA_F_NESTED as u16 | TCA_OPTIONS as u16, options_inner_len);
    let options_len = attr_aligned_len(options_inner_len);
    let attrs_len = attr_aligned_len(kind.len()) + options_len;
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of_val(&tc_info) + attrs_len) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO | request_flags) as u16,
        nlmsg_type: RTM_NEWTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    let prog_fd = bytes_of(&prog_fd);
    let flags = bytes_of(&flags);
    sock.send([
        bytes_of(&header),
        bytes_of(&tc_info),
        &kind_attr,
        kind,
        attr_padding(kind.len()),
        &options_attr,
        &fd_attr,
        prog_fd,
        attr_padding(prog_fd.len()),
        &name_attr,
        prog_name,
        attr_padding(prog_name.len()),
        &flags_attr,
        flags,
        attr_padding(flags.len()),
        attr_padding(options_inner_len),
    ])?;

    // find the RTM_NEWTFILTER reply and read the tcm_info and tcm_handle fields
    // which we'll need to detach
    //
    // always parse the entire response to ensure we don't miss any replies
    let mut tc_msg: Vec<tcmsg> = Vec::new();
    for msg in sock.recv() {
        let msg = msg?;
        if msg.header.nlmsg_type == RTM_NEWTFILTER {
            tc_msg.push(unsafe { ptr::read_unaligned(msg.data.as_ptr().cast()) });
        }
    }
    match tc_msg.as_slice() {
        [] => Err(NetlinkError(NetlinkErrorInternal::IoError(
            io::Error::other("no RTM_NEWTFILTER reply received, this is a bug in the kernel"),
        ))),
        [tc_msg] => {
            let priority = ((tc_msg.tcm_info & TC_H_MAJ_MASK) >> 16) as u16;
            Ok((priority, tc_msg.tcm_handle))
        }
        _tc_msg => Err(NetlinkError(NetlinkErrorInternal::IoError(
            io::Error::other(
                "multiple RTM_NEWTFILTER replies received, this is a bug in the kernel",
            ),
        ))),
    }
}

pub(crate) unsafe fn netlink_qdisc_detach(
    if_index: i32,
    attach_type: TcAttachType,
    priority: u16,
    handle: u32,
) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let tc_info = tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm_handle: handle, // auto-assigned, if zero
        tcm_info: tc_handler_make(
            u32::from(priority) << 16,
            u32::from(htons(ETH_P_ALL as u16)),
        ),
        tcm_parent: attach_type.tc_parent(),
        tcm_ifindex: if_index,
        ..unsafe { mem::zeroed() }
    };
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of_val(&tc_info)) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_DELTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    sock.send([bytes_of(&header), bytes_of(&tc_info)])?;

    for msg in sock.recv() {
        msg?;
    }

    Ok(())
}

pub(crate) fn netlink_find_filter_with_name(
    sock: &NetlinkSocket,
    if_index: i32,
    attach_type: TcAttachType,
    name: &CStr,
) -> Result<impl Iterator<Item = Result<(u16, u32), NetlinkError>>, NetlinkError> {
    let tc_info = tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm_handle: 0, // auto-assigned, if zero
        tcm_ifindex: if_index,
        tcm_parent: attach_type.tc_parent(),
        ..unsafe { mem::zeroed() }
    };
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of_val(&tc_info)) as u32,
        nlmsg_type: RTM_GETTFILTER,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_DUMP) as u16,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    sock.send([bytes_of(&header), bytes_of(&tc_info)])?;
    let mut resp = sock.recv();

    Ok(iter::from_fn(move || {
        loop {
            let msg = resp.next()?;
            if let Some(result) = (|| {
                let msg = msg?;
                if msg.header.nlmsg_type != RTM_NEWTFILTER {
                    return Ok(None);
                }

                let (tc_msg_buf, attrs_buf) = msg
                    .data
                    .split_at_checked(size_of_val(&tc_info))
                    .ok_or_else(|| {
                        NetlinkError(NetlinkErrorInternal::IoError(io::Error::other(
                            "RTM_NEWTFILTER payload smaller than tcmsg",
                        )))
                    })?;
                let tc_msg: tcmsg = unsafe { ptr::read_unaligned(tc_msg_buf.as_ptr().cast()) };
                let priority = (tc_msg.tcm_info >> 16) as u16;

                let mut filter = None;
                for opt in NlAttrsIterator::new(attrs_buf) {
                    let opt =
                        opt.map_err(|e| NetlinkError(NetlinkErrorInternal::NlAttrError(e)))?;
                    if opt.header.nla_type & NLA_TYPE_MASK as u16 != TCA_OPTIONS as u16 {
                        continue;
                    }
                    for opt in NlAttrsIterator::new(opt.data) {
                        let opt =
                            opt.map_err(|e| NetlinkError(NetlinkErrorInternal::NlAttrError(e)))?;
                        if opt.header.nla_type & NLA_TYPE_MASK as u16 != TCA_BPF_NAME as u16 {
                            continue;
                        }
                        let f_name = CStr::from_bytes_with_nul(opt.data)
                            .map_err(NlAttrError::CStrFromBytesWithNul)
                            .map_err(|e| NetlinkError(NetlinkErrorInternal::NlAttrError(e)))?;
                        if f_name != name {
                            continue;
                        }
                        filter = Some((priority, tc_msg.tcm_handle));
                    }
                }
                Ok(filter)
            })()
            .transpose()
            {
                break Some(result);
            }
        }
    }))
}

#[doc(hidden)]
pub unsafe fn netlink_set_link_up(if_index: i32) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let if_info = ifinfomsg {
        ifi_family: AF_UNSPEC as u8,
        ifi_index: if_index,
        ifi_flags: IFF_UP as u32,
        ifi_change: IFF_UP as u32,
        ..unsafe { mem::zeroed() }
    };
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of_val(&if_info)) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    sock.send([bytes_of(&header), bytes_of(&if_info)])?;
    for msg in sock.recv() {
        msg?;
    }

    Ok(())
}

pub(crate) struct NetlinkSocket {
    sock: crate::MockableFd,
    _nl_pid: u32,
}

impl NetlinkSocket {
    pub(crate) fn open() -> Result<Self, NetlinkErrorInternal> {
        // Safety: libc wrapper
        let sock = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if sock < 0 {
            return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
        }
        // SAFETY: `socket` returns a file descriptor.
        let sock = unsafe { crate::MockableFd::from_raw_fd(sock) };

        let enable = 1i32;
        // Safety: libc wrapper
        unsafe {
            // Set NETLINK_EXT_ACK to get extended attributes.
            if setsockopt(
                sock.as_raw_fd(),
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                ptr::from_ref(&enable).cast(),
                size_of_val(&enable) as u32,
            ) < 0
            {
                return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
            }

            // Set NETLINK_CAP_ACK to avoid getting copies of request payload.
            if setsockopt(
                sock.as_raw_fd(),
                SOL_NETLINK,
                NETLINK_CAP_ACK,
                ptr::from_ref(&enable).cast(),
                size_of_val(&enable) as u32,
            ) < 0
            {
                return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
            }
        }

        // Safety: sockaddr_nl is POD so this is safe
        let mut addr = unsafe { mem::zeroed::<sockaddr_nl>() };
        addr.nl_family = AF_NETLINK as u16;
        let mut addr_len = size_of_val(&addr) as u32;
        // Safety: libc wrapper
        if unsafe {
            getsockname(
                sock.as_raw_fd(),
                ptr::from_mut(&mut addr).cast(),
                ptr::from_mut(&mut addr_len).cast(),
            )
        } < 0
        {
            return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
        }

        Ok(Self {
            sock,
            _nl_pid: addr.nl_pid,
        })
    }

    fn send<const N: usize>(&self, bufs: [&[u8]; N]) -> Result<(), NetlinkErrorInternal> {
        let iovs = bufs.map(|buf| iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        });
        let iovcnt = i32::try_from(N).map_err(|std::num::TryFromIntError { .. }| {
            NetlinkErrorInternal::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many netlink write buffers",
            ))
        })?;
        let expected = bufs.iter().map(|buf| buf.len()).sum();
        let written = unsafe { writev(self.sock.as_raw_fd(), iovs.as_ptr(), iovcnt) };
        if written < 0 {
            return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
        }
        let written =
            usize::try_from(written).map_err(|std::num::TryFromIntError { .. }| {
                NetlinkErrorInternal::IoError(io::Error::last_os_error())
            })?;
        if written != expected {
            return Err(NetlinkErrorInternal::IoError(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink write",
            )));
        }
        Ok(())
    }

    fn recv(&self) -> impl Iterator<Item = Result<NetlinkMessage, NetlinkErrorInternal>> {
        let mut scratch = [0u8; 4096];
        let mut len = 0;
        let mut offset = 0;
        let mut multipart = true;
        iter::from_fn(move || {
            (|| {
                loop {
                    while offset < len {
                        let message = NetlinkMessage::read(&scratch[offset..len])?;
                        offset += nla_align!(message.header.nlmsg_len as usize);
                        multipart = message.header.nlmsg_flags & NLM_F_MULTI as u16 != 0;
                        return match i32::from(message.header.nlmsg_type) {
                            NLMSG_ERROR => {
                                let error = message.error.unwrap();
                                if error.error == 0 {
                                    // this is an ACK
                                    continue;
                                }
                                let mut messages = Vec::new();
                                for attr in NlAttrsIterator::new(&message.data) {
                                    let attr = attr?;
                                    if attr.header.nla_type & NLA_TYPE_MASK as u16
                                        != NLMSGERR_ATTR_MSG as u16
                                    {
                                        continue;
                                    }
                                    let message = CStr::from_bytes_with_nul(attr.data)
                                        .map_err(NlAttrError::CStrFromBytesWithNul)?;
                                    messages.push(message.to_owned());
                                }
                                let source = io::Error::from_raw_os_error(-error.error);
                                Err(NetlinkErrorInternal::Error { messages, source })
                            }
                            NLMSG_DONE => Ok(None),
                            _ => Ok(Some(message)),
                        };
                    }
                    if !multipart {
                        return Ok(None);
                    }
                    let recv_len = unsafe {
                        recv(
                            self.sock.as_raw_fd(),
                            scratch.as_mut_ptr().cast(),
                            scratch.len(),
                            0,
                        )
                    };
                    let recv_len = usize::try_from(recv_len).map_err(
                        |std::num::TryFromIntError { .. }| {
                            NetlinkErrorInternal::IoError(io::Error::last_os_error())
                        },
                    )?;
                    if recv_len == 0 {
                        return Ok(None);
                    }
                    len = recv_len;
                    offset = 0;
                }
            })()
            .transpose()
        })
    }
}

struct NetlinkMessage {
    header: nlmsghdr,
    data: Vec<u8>,
    error: Option<nlmsgerr>,
}

impl NetlinkMessage {
    fn read(buf: &[u8]) -> io::Result<Self> {
        let header_buf = buf
            .get(..size_of::<nlmsghdr>())
            .ok_or_else(|| io::Error::other("buffer smaller than nlmsghdr"))?;

        // Safety: nlmsghdr is POD so read is safe
        let header: nlmsghdr = unsafe { ptr::read_unaligned(header_buf.as_ptr().cast()) };
        let msg_len = header.nlmsg_len as usize;
        if msg_len < size_of::<nlmsghdr>() {
            return Err(io::Error::other("invalid nlmsg_len"));
        }
        let msg = buf
            .get(..msg_len)
            .ok_or_else(|| io::Error::other("invalid nlmsg_len"))?;

        let data = msg
            .get(nla_align!(size_of::<nlmsghdr>())..)
            .ok_or_else(|| io::Error::other("need more data"))?;

        let (rest, error) = if header.nlmsg_type == NLMSG_ERROR as u16 {
            let (err_buf, rest) = data
                .split_at_checked(size_of::<nlmsgerr>())
                .ok_or_else(|| io::Error::other("NLMSG_ERROR but not enough space for nlmsgerr"))?;
            // Safety: nlmsgerr is POD so read is safe
            let err = unsafe { ptr::read_unaligned(err_buf.as_ptr().cast()) };
            (rest, Some(err))
        } else {
            (data, None)
        };

        Ok(Self {
            header,
            data: rest.to_vec(),
            error,
        })
    }
}

const fn htons(u: u16) -> u16 {
    u.to_be()
}

unsafe impl Pod for ifinfomsg {}
unsafe impl Pod for nlattr {}
unsafe impl Pod for nlmsghdr {}
unsafe impl Pod for tcmsg {}

struct NlAttrsIterator<'a> {
    buf: &'a [u8],
}

impl<'a> NlAttrsIterator<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for NlAttrsIterator<'a> {
    type Item = Result<NlAttr<'a>, NlAttrError>;

    fn next(&mut self) -> Option<Self::Item> {
        let Self { buf } = self;
        if buf.is_empty() {
            return None;
        }
        let buf = mem::take(buf);

        let header_len = size_of::<nlattr>();

        let Some((header_buf, buf)) = buf.split_at_checked(header_len) else {
            return Some(Err(NlAttrError::BufferLength {
                size: buf.len(),
                expected: header_len,
            }));
        };

        let attr: nlattr = unsafe { ptr::read_unaligned(header_buf.as_ptr().cast()) };
        let len = usize::from(attr.nla_len);
        let Some(payload_len) = len.checked_sub(size_of::<nlattr>()) else {
            return Some(Err(NlAttrError::HeaderLength(len)));
        };
        let align_len = nla_align!(len);
        let payload_align_len = align_len - size_of::<nlattr>();
        let Some((data, buf)) = buf.split_at_checked(payload_align_len) else {
            return Some(Err(NlAttrError::BufferLength {
                size: buf.len(),
                expected: payload_align_len,
            }));
        };
        let data = &data[..payload_len];

        self.buf = buf;

        Some(Ok(NlAttr { header: attr, data }))
    }
}

#[derive(Clone, Debug)]
struct NlAttr<'a> {
    header: nlattr,
    data: &'a [u8],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum NlAttrError {
    #[error("invalid buffer size `{size}`, expected `{expected}`")]
    BufferLength { size: usize, expected: usize },

    #[error("invalid nlattr header length `{0}`")]
    HeaderLength(usize),

    #[error("invalid CStr from bytes with nul: {0}")]
    CStrFromBytesWithNul(#[from] FromBytesWithNulError),
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    fn append_attr(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        let attr = attr_header(attr_type, value.len());
        buf.extend_from_slice(&attr);
        buf.extend_from_slice(value);
        buf.extend_from_slice(attr_padding(value.len()));
    }

    fn append_nested_attr(buf: &mut Vec<u8>, attr_type: u16, nested: &[u8]) {
        let attr = attr_header(NLA_F_NESTED as u16 | attr_type, nested.len());
        buf.extend_from_slice(&attr);
        buf.extend_from_slice(nested);
        buf.extend_from_slice(attr_padding(nested.len()));
    }

    #[test]
    fn test_nlattr_iterator_empty() {
        let mut iter = NlAttrsIterator::new(&[]);
        assert_matches!(iter.next(), None);
    }

    #[test]
    fn test_nlattr_iterator_one() {
        let mut buf = Vec::new();
        append_attr(&mut buf, IFLA_XDP_FD as u16, bytes_of(&42u32));

        let mut iter = NlAttrsIterator::new(&buf);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.data.len(), size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);

        assert_matches!(iter.next(), None);
    }

    #[test]
    fn test_nlattr_iterator_many() {
        let mut buf = Vec::new();
        append_attr(&mut buf, IFLA_XDP_FD as u16, bytes_of(&42u32));
        append_attr(&mut buf, IFLA_XDP_EXPECTED_FD as u16, bytes_of(&12u32));

        let mut iter = NlAttrsIterator::new(&buf);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.data.len(), size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(attr.data.len(), size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 12);

        assert_matches!(iter.next(), None);
    }

    #[test]
    fn test_nlattr_iterator_nested() {
        let mut inner = Vec::new();
        append_attr(&mut inner, TCA_BPF_FD as u16, bytes_of(&42i32));

        let name = CString::new("foo").unwrap();
        append_attr(&mut inner, TCA_BPF_NAME as u16, name.to_bytes_with_nul());

        let mut outer = Vec::new();
        append_nested_attr(&mut outer, TCA_OPTIONS as u16, &inner);

        let mut iter = NlAttrsIterator::new(&outer);
        let outer = iter.next().unwrap().unwrap();
        assert_eq!(
            outer.header.nla_type & NLA_TYPE_MASK as u16,
            TCA_OPTIONS as u16
        );

        let mut iter = NlAttrsIterator::new(outer.data);
        let inner = iter.next().unwrap().unwrap();
        assert_eq!(
            inner.header.nla_type & NLA_TYPE_MASK as u16,
            TCA_BPF_FD as u16
        );
        let inner = iter.next().unwrap().unwrap();
        assert_eq!(
            inner.header.nla_type & NLA_TYPE_MASK as u16,
            TCA_BPF_NAME as u16
        );
        let name = CStr::from_bytes_with_nul(inner.data).unwrap();
        assert_eq!(name.to_str().unwrap(), "foo");

        assert_matches!(iter.next(), None);
    }

    #[test]
    fn xdp_attrs_layout() {
        let fd = 42i32;
        let flags = XDP_FLAGS_REPLACE;
        let old_fd = 24i32;

        let mut nested = Vec::new();
        append_attr(&mut nested, IFLA_XDP_FD as u16, bytes_of(&fd));
        append_attr(&mut nested, IFLA_XDP_FLAGS as u16, bytes_of(&flags));
        append_attr(&mut nested, IFLA_XDP_EXPECTED_FD as u16, bytes_of(&old_fd));

        let mut attrs = Vec::new();
        append_nested_attr(&mut attrs, IFLA_XDP, &nested);

        let mut iter = NlAttrsIterator::new(&attrs);
        let xdp = iter.next().unwrap().unwrap();
        assert_eq!(xdp.header.nla_type, NLA_F_NESTED as u16 | IFLA_XDP);
        assert_eq!(
            usize::from(xdp.header.nla_len),
            size_of::<nlattr>() + nested.len()
        );
        assert_matches!(iter.next(), None);

        let mut iter = NlAttrsIterator::new(xdp.data);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(i32::from_ne_bytes(attr.data.try_into().unwrap()), fd);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FLAGS as u16);
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), flags);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(i32::from_ne_bytes(attr.data.try_into().unwrap()), old_fd);
        assert_matches!(iter.next(), None);
    }

    #[test]
    fn tc_bpf_attrs_layout_accepts_max_name() {
        let kind = c"bpf".to_bytes_with_nul();
        let prog_fd = 42i32;
        let name = [b'a'; CLS_BPF_NAME_LEN];
        let flags = TCA_BPF_FLAG_ACT_DIRECT;

        let mut options = Vec::new();
        append_attr(&mut options, TCA_BPF_FD as u16, bytes_of(&prog_fd));
        append_attr(&mut options, TCA_BPF_NAME as u16, &name);
        append_attr(&mut options, TCA_BPF_FLAGS as u16, bytes_of(&flags));

        let mut attrs = Vec::new();
        append_attr(&mut attrs, TCA_KIND as u16, kind);
        append_nested_attr(&mut attrs, TCA_OPTIONS as u16, &options);

        let mut iter = NlAttrsIterator::new(&attrs);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, TCA_KIND as u16);
        assert_eq!(attr.data, kind);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(
            attr.header.nla_type,
            NLA_F_NESTED as u16 | TCA_OPTIONS as u16
        );
        assert_eq!(
            usize::from(attr.header.nla_len),
            size_of::<nlattr>() + options.len()
        );
        assert_matches!(iter.next(), None);

        let mut iter = NlAttrsIterator::new(attr.data);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, TCA_BPF_FD as u16);
        assert_eq!(i32::from_ne_bytes(attr.data.try_into().unwrap()), prog_fd);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, TCA_BPF_NAME as u16);
        assert_eq!(attr.data, name);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, TCA_BPF_FLAGS as u16);
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), flags);
        assert_matches!(iter.next(), None);
    }
}
