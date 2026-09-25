use std::{
    ffi::{CStr, CString, FromBytesWithNulError},
    io, iter, mem,
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _},
    ptr,
};

use aya_obj::generated::{
    TC_H_CLSACT, TC_H_INGRESS, TC_H_MAJ_MASK, TC_H_UNSPEC, TCA_BPF_FLAG_ACT_DIRECT, TCA_BPF_NAME,
    TCA_OPTIONS, XDP_FLAGS_REPLACE, XDP_FLAGS_UPDATE_IF_NOEXIST, ifinfomsg,
    nlmsgerr_attrs::NLMSGERR_ATTR_MSG, tcmsg,
};
use libc::{
    AF_NETLINK, AF_UNSPEC, ETH_P_ALL, NETLINK_CAP_ACK, NETLINK_EXT_ACK, NETLINK_ROUTE, NLA_ALIGNTO,
    NLA_TYPE_MASK, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_ECHO, NLM_F_EXCL, NLM_F_MULTI,
    NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, RTM_NEWTFILTER, SOCK_RAW, SOL_NETLINK, UIO_MAXIOV,
    iovec, nlattr, nlmsgerr, nlmsghdr, recv, setsockopt, socket, writev,
};
use thiserror::Error;

use crate::{
    Pod,
    programs::{TcAttachType, TcHandle, XdpMode},
    util::tc_handler_make,
};

mod request;
// `doctest` lets rustdoc collect the tests without type-checking the intentionally
// invalid fixture bodies; each doctest compiles its fixture separately.
// `rust_analyzer` includes the fixtures for IDE navigation and diagnostics.
#[cfg(any(doctest, rust_analyzer))]
mod request_tests;

const NLMSG_HDR_LEN: usize = size_of::<nlmsghdr>();
const NLMSG_HDR_ALIGN_LEN: usize = NLMSG_HDR_LEN.next_multiple_of(NLA_ALIGNTO as usize);
const NLA_HDR_LEN: usize = size_of::<nlattr>();

/// `CLS_BPF_NAME_LEN` from the Linux kernel, plus the trailing NUL.
/// The kernel's `NLA_NUL_STRING` limit excludes the terminator.
/// <https://github.com/torvalds/linux/blob/05f7e89ab/net/sched/cls_bpf.c#L28>
const CLS_BPF_NAME_LEN: usize = 256 + 1;

// These wire structures contain only integers, with all padding represented by
// explicit fields in the kernel headers.
unsafe impl Pod for nlmsghdr {}
unsafe impl Pod for ifinfomsg {}
unsafe impl Pod for tcmsg {}
unsafe impl Pod for nlattr {}

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
pub struct NetlinkError(#[from] NetlinkErrorInternal);

impl NetlinkError {
    /// Returns the raw OS error code, if one is available.
    ///
    /// Returns `None` if the error does not wrap an OS error (e.g. buffer
    /// length or header length errors from the netlink attribute parser).
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

pub(crate) fn netlink_set_xdp_fd(
    if_index: i32,
    fd: Option<BorrowedFd<'_>>,
    expected_fd: Option<BorrowedFd<'_>>,
    mode: XdpMode,
) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let flags = mode.flags() | XDP_FLAGS_UPDATE_IF_NOEXIST;
    let (flags, expected_fd) = match expected_fd {
        None => (flags, None),
        Some(fd) => (flags | XDP_FLAGS_REPLACE, Some(fd.as_raw_fd())),
    };

    request::Link::new(ifinfomsg {
        ifi_family: AF_UNSPEC as u8,
        __ifi_pad: 0,
        ifi_type: 0,
        ifi_index: if_index,
        ifi_flags: 0,
        ifi_change: 0,
    })
    .xdp(request::Xdp::new(fd.map_or(-1, |fd| fd.as_raw_fd()), flags).expected_fd(expected_fd))
    .send(&sock, (NLM_F_REQUEST | NLM_F_ACK) as u16)?;
    for msg in sock.recv() {
        msg?;
    }
    Ok(())
}

pub(crate) fn netlink_qdisc_add_clsact(if_index: i32) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    request::Tc::add_clsact(tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm__pad1: 0,
        tcm__pad2: 0,
        tcm_ifindex: if_index,
        tcm_handle: tc_handler_make(TC_H_CLSACT, TC_H_UNSPEC),
        tcm_parent: tc_handler_make(TC_H_CLSACT, TC_H_INGRESS),
        tcm_info: 0,
    })
    .send(
        &sock,
        (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
    )?;
    for msg in sock.recv() {
        msg?;
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "internal netlink helper")]
pub(crate) fn netlink_qdisc_attach(
    if_index: i32,
    attach_type: TcAttachType,
    prog_fd: BorrowedFd<'_>,
    prog_name: &CStr,
    priority: u16,
    handle: TcHandle,
    classid: Option<TcHandle>,
    create: bool,
) -> Result<(u16, TcHandle), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    // When create=true, we're creating a new attachment so we must set NLM_F_CREATE. Then we also
    // set NLM_F_EXCL so that attaching fails if there's already a program attached to the given
    // handle.
    //
    // When create=false we're replacing an existing attachment so we must not set either flags.
    //
    // See https://github.com/torvalds/linux/blob/3a8749886/net/sched/cls_api.c#L2304
    let request_flags = if create {
        NLM_F_CREATE | NLM_F_EXCL
    } else {
        // NLM_F_REPLACE exists, but seems unused by cls_bpf
        0
    };
    if prog_name.to_bytes_with_nul().len() > CLS_BPF_NAME_LEN {
        return Err(NetlinkError(NetlinkErrorInternal::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program name exceeds CLS_BPF_NAME_LEN",
        ))));
    }
    request::Tc::new_filter(
        tcmsg {
            tcm_family: AF_UNSPEC as u8,
            tcm__pad1: 0,
            tcm__pad2: 0,
            tcm_ifindex: if_index,
            tcm_handle: handle.into(),
            tcm_parent: attach_type.tc_parent(),
            tcm_info: tc_handler_make(
                u32::from(priority) << 16,
                u32::from((ETH_P_ALL as u16).to_be()),
            ),
        },
        request::Bpf::new(
            prog_fd.as_raw_fd() as u32,
            prog_name,
            TCA_BPF_FLAG_ACT_DIRECT,
        )
        .classid(classid.map(u32::from)),
    )
    .send(
        &sock,
        (NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO | request_flags) as u16,
    )?;

    // find the RTM_NEWTFILTER reply and read the tcm_info and tcm_handle fields
    // which we'll need to detach
    //
    // always parse the entire response to ensure we don't miss any replies
    let mut tc_msg: Vec<tcmsg> = Vec::new();
    for msg in sock.recv() {
        let msg = msg?;
        if msg.header.nlmsg_type == RTM_NEWTFILTER {
            let (msg, _attrs) = msg.tcmsg()?;
            tc_msg.push(msg);
        }
    }
    match tc_msg.as_slice() {
        [] => Err(NetlinkError(NetlinkErrorInternal::IoError(
            io::Error::other("no RTM_NEWTFILTER reply received, this is a bug in the kernel"),
        ))),
        [tc_msg] => {
            let priority = ((tc_msg.tcm_info & TC_H_MAJ_MASK) >> 16) as u16;
            Ok((priority, tc_msg.tcm_handle.into()))
        }
        _tc_msg => Err(NetlinkError(NetlinkErrorInternal::IoError(
            io::Error::other(
                "multiple RTM_NEWTFILTER replies received, this is a bug in the kernel",
            ),
        ))),
    }
}

pub(crate) fn netlink_qdisc_detach(
    if_index: i32,
    attach_type: TcAttachType,
    priority: u16,
    handle: TcHandle,
) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    request::Tc::delete_filter(tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm__pad1: 0,
        tcm__pad2: 0,
        tcm_ifindex: if_index,
        tcm_handle: handle.into(),
        tcm_parent: attach_type.tc_parent(),
        tcm_info: tc_handler_make(
            u32::from(priority) << 16,
            u32::from((ETH_P_ALL as u16).to_be()),
        ),
    })
    .send(&sock, (NLM_F_REQUEST | NLM_F_ACK) as u16)?;

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
) -> Result<impl Iterator<Item = Result<(u16, TcHandle), NetlinkError>>, NetlinkError> {
    request::Tc::get_filter(tcmsg {
        tcm_family: AF_UNSPEC as u8,
        tcm__pad1: 0,
        tcm__pad2: 0,
        tcm_ifindex: if_index,
        tcm_handle: 0,
        tcm_parent: attach_type.tc_parent(),
        tcm_info: 0,
    })
    .send(sock, (NLM_F_REQUEST | NLM_F_DUMP) as u16)?;
    let mut resp = sock.recv();

    Ok(iter::from_fn(move || {
        loop {
            let msg = resp.next()?;
            if let Some(result) = (|| {
                let msg = msg?;
                if msg.header.nlmsg_type != RTM_NEWTFILTER {
                    return Ok(None);
                }

                let (tc_msg, attrs_buf) = msg.tcmsg()?;
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
                        filter = Some((priority, tc_msg.tcm_handle.into()));
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

#[cfg(feature = "test-helpers")]
pub(crate) fn netlink_set_link_up(if_index: i32) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    request::Link::new(ifinfomsg {
        ifi_family: AF_UNSPEC as u8,
        __ifi_pad: 0,
        ifi_type: 0,
        ifi_index: if_index,
        ifi_flags: libc::IFF_UP as u32,
        ifi_change: libc::IFF_UP as u32,
    })
    .send(&sock, (NLM_F_REQUEST | NLM_F_ACK) as u16)?;
    for msg in sock.recv() {
        msg?;
    }

    Ok(())
}

pub(crate) struct NetlinkSocket {
    sock: crate::MockableFd,
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

        Ok(Self { sock })
    }

    // Each row holds a header, payload and alignment padding:
    // - The netlink header is followed by the family header (ifinfomsg or tcmsg).
    // - A nested attribute has only a header; its children occupy subsequent rows.
    // - A regular attribute has a header and payload, followed by zero padding.
    // - An absent optional attribute has three empty slices.
    // Arrays keep the iovec count known at compile time. Empty slices contribute
    // no bytes to the single datagram sent by writev.
    fn send<const N: usize>(&self, bufs: [[&[u8]; 3]; N]) -> Result<(), NetlinkErrorInternal> {
        let Self { sock } = self;
        const { assert!(N * 3 <= UIO_MAXIOV as usize) };
        let iovs = bufs.map(|bufs| {
            bufs.map(|buf| iovec {
                iov_base: buf.as_ptr().cast_mut().cast(),
                iov_len: buf.len(),
            })
        });
        let iovs = iovs.as_flattened();
        // SAFETY: every iovec borrows a live slice, and writev only reads them.
        // Netlink sends one complete datagram or returns an error.
        if unsafe { writev(sock.as_raw_fd(), iovs.as_ptr(), iovs.len() as i32) } < 0 {
            return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn recv(&self) -> impl Iterator<Item = Result<NetlinkMessage, NetlinkErrorInternal>> {
        let Self { sock } = self;
        let mut scratch = [0u8; 4096];
        let mut len = 0;
        let mut offset = 0;
        let mut multipart = true;
        iter::from_fn(move || {
            (|| {
                loop {
                    while offset < len {
                        let message = NetlinkMessage::read(&scratch[offset..len])?;
                        offset += (message.header.nlmsg_len as usize)
                            .next_multiple_of(NLA_ALIGNTO as usize);
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
                            sock.as_raw_fd(),
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
    fn tcmsg(&self) -> Result<(tcmsg, &[u8]), NetlinkErrorInternal> {
        let Self {
            header: _header,
            data,
            error: _error,
        } = self;
        let (header, attrs) = data
            .split_at_checked(size_of::<tcmsg>())
            .ok_or_else(|| io::Error::other("RTM_NEWTFILTER payload smaller than tcmsg"))?;
        // SAFETY: the checked prefix contains a complete tcmsg, whose integer fields
        // accept any bit pattern.
        let header = unsafe { ptr::read_unaligned(header.as_ptr().cast()) };
        Ok((header, attrs))
    }

    fn read(buf: &[u8]) -> io::Result<Self> {
        let header_buf = buf
            .get(..NLMSG_HDR_LEN)
            .ok_or_else(|| io::Error::other("buffer smaller than nlmsghdr"))?;

        // Safety: nlmsghdr is POD so read is safe
        let header: nlmsghdr = unsafe { ptr::read_unaligned(header_buf.as_ptr().cast()) };
        let msg_len = header.nlmsg_len as usize;
        if msg_len < NLMSG_HDR_LEN {
            return Err(io::Error::other("invalid nlmsg_len"));
        }
        let msg = buf
            .get(..msg_len)
            .ok_or_else(|| io::Error::other("invalid nlmsg_len"))?;

        let data = msg
            .get(NLMSG_HDR_ALIGN_LEN..)
            .ok_or_else(|| io::Error::other("need more data"))?;

        let (rest, error) = if header.nlmsg_type == NLMSG_ERROR as u16 {
            let (err_buf, rest) = data
                .split_at_checked(size_of::<nlmsgerr>())
                .ok_or_else(|| io::Error::other("NLMSG_ERROR but not enough space for nlmsgerr"))?;
            // Safety: nlmsgerr is POD so read is safe
            let err: nlmsgerr = unsafe { ptr::read_unaligned(err_buf.as_ptr().cast()) };
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

        let Some((header_buf, buf)) = buf.split_at_checked(NLA_HDR_LEN) else {
            return Some(Err(NlAttrError::BufferLength {
                size: buf.len(),
                expected: NLA_HDR_LEN,
            }));
        };

        let attr: nlattr = unsafe { ptr::read_unaligned(header_buf.as_ptr().cast()) };
        let len = attr.nla_len as usize;
        let Some(payload_len) = len.checked_sub(NLA_HDR_LEN) else {
            return Some(Err(NlAttrError::HeaderLength(len)));
        };
        let align_len = len.next_multiple_of(NLA_ALIGNTO as usize);
        let payload_align_len = align_len - NLA_HDR_LEN;
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

#[derive(Clone)]
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
    use std::{io::Read as _, os::unix::net::UnixStream};

    use assert_matches::assert_matches;
    use aya_obj::generated::{
        IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS, TCA_BPF_CLASSID, TCA_BPF_FD,
        TCA_BPF_FLAGS, TCA_KIND,
    };
    use libc::NLA_F_NESTED;
    use rstest::rstest;

    use super::*;
    use crate::util::bytes_of;

    #[rstest]
    #[case::empty(0)]
    #[case::truncated(size_of::<tcmsg>() - 1)]
    fn test_short_tcmsg(#[case] payload_len: usize) {
        let msg = NetlinkMessage {
            header: nlmsghdr {
                nlmsg_len: (NLMSG_HDR_LEN + payload_len) as u32,
                nlmsg_type: RTM_NEWTFILTER,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
            data: vec![0; payload_len],
            error: None,
        };
        let err = assert_matches!(msg.tcmsg(), Err(NetlinkErrorInternal::IoError(err)) => err);
        assert_eq!(err.to_string(), "RTM_NEWTFILTER payload smaller than tcmsg");
    }

    #[test]
    fn test_nlattr_iterator_empty() {
        let mut iter = NlAttrsIterator::new(&[]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlattr_iterator_one() {
        let header = nlattr {
            nla_len: 8,
            nla_type: IFLA_XDP_FD as u16,
        };
        let buf = [bytes_of(&header), bytes_of(&42u32)].concat();
        let mut iter = NlAttrsIterator::new(&buf);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlattr_iterator_many() {
        let fd = nlattr {
            nla_len: 8,
            nla_type: IFLA_XDP_FD as u16,
        };
        let expected_fd = nlattr {
            nla_len: 8,
            nla_type: IFLA_XDP_EXPECTED_FD as u16,
        };
        let buf = [
            bytes_of(&fd),
            bytes_of(&42u32),
            bytes_of(&expected_fd),
            bytes_of(&12u32),
        ]
        .concat();
        let mut iter = NlAttrsIterator::new(&buf);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 12);
        assert!(iter.next().is_none());
    }

    #[rstest]
    #[case::unset(request::Bpf::new(123, c"ab", TCA_BPF_FLAG_ACT_DIRECT), None)]
    #[case::absent(request::Bpf::new(123, c"ab", TCA_BPF_FLAG_ACT_DIRECT).classid(None), None)]
    #[case::present(request::Bpf::new(123, c"ab", TCA_BPF_FLAG_ACT_DIRECT).classid(Some(42)), Some(42))]
    fn test_send_bpf<C: request::Optional<u32>>(
        #[case] bpf: request::Bpf<'_, C>,
        #[case] classid: Option<u32>,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sock = NetlinkSocket {
            sock: sender.into(),
        };
        let body = tcmsg {
            tcm_family: AF_UNSPEC as u8,
            tcm__pad1: 0,
            tcm__pad2: 0,
            tcm_ifindex: 1,
            tcm_handle: 0,
            tcm_parent: TC_H_INGRESS,
            tcm_info: 0,
        };
        request::Tc::new_filter(body, bpf)
            .send(&sock, NLM_F_REQUEST as u16)
            .unwrap();
        drop(sock);

        // 16-byte message header, 20-byte tcmsg, 4-byte nested header and up to
        // five 8-byte attributes. One extra byte detects an oversized message.
        let mut buf = Vec::new();
        let len = receiver.take(81).read_to_end(&mut buf).unwrap();
        assert_eq!(len, if classid.is_some() { 80 } else { 72 });
        let msg = NetlinkMessage::read(&buf).unwrap();
        assert_eq!(msg.header.nlmsg_len as usize, len);
        assert_eq!(msg.header.nlmsg_type, RTM_NEWTFILTER);
        assert_eq!(msg.header.nlmsg_flags, NLM_F_REQUEST as u16);

        let (received_body, attrs) = msg.tcmsg().unwrap();
        assert_eq!(bytes_of(&received_body), bytes_of(&body));
        let mut iter = NlAttrsIterator::new(attrs);
        let kind = iter.next().unwrap().unwrap();
        assert_eq!(kind.header.nla_type, TCA_KIND as u16);
        assert_eq!(CStr::from_bytes_with_nul(kind.data).unwrap(), c"bpf");
        let outer = iter.next().unwrap().unwrap();
        assert_eq!(
            outer.header.nla_type,
            TCA_OPTIONS as u16 | NLA_F_NESTED as u16
        );
        assert!(iter.next().is_none());
        let mut iter = NlAttrsIterator::new(outer.data);
        if let Some(classid) = classid {
            let inner = iter.next().unwrap().unwrap();
            assert_eq!(inner.header.nla_type, TCA_BPF_CLASSID as u16);
            assert_eq!(u32::from_ne_bytes(inner.data.try_into().unwrap()), classid);
        }
        let inner = iter.next().unwrap().unwrap();
        assert_eq!(inner.header.nla_type, TCA_BPF_FD as u16);
        assert_eq!(u32::from_ne_bytes(inner.data.try_into().unwrap()), 123);
        let inner = iter.next().unwrap().unwrap();
        assert_eq!(inner.header.nla_type, TCA_BPF_NAME as u16);
        assert_eq!(CStr::from_bytes_with_nul(inner.data).unwrap(), c"ab");
        let inner = iter.next().unwrap().unwrap();
        assert_eq!(inner.header.nla_type, TCA_BPF_FLAGS as u16);
        assert_eq!(
            u32::from_ne_bytes(inner.data.try_into().unwrap()),
            TCA_BPF_FLAG_ACT_DIRECT
        );
        assert!(iter.next().is_none());
    }

    #[rstest]
    #[case::unset(request::Xdp::new(-1, XDP_FLAGS_REPLACE), None)]
    #[case::absent(request::Xdp::new(-1, XDP_FLAGS_REPLACE).expected_fd(None), None)]
    #[case::present(request::Xdp::new(-1, XDP_FLAGS_REPLACE).expected_fd(Some(12)), Some(12))]
    fn test_send_xdp<E: request::Optional<i32>>(
        #[case] xdp: request::Xdp<E>,
        #[case] expected_fd: Option<i32>,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sock = NetlinkSocket {
            sock: sender.into(),
        };
        let body = ifinfomsg {
            ifi_family: AF_UNSPEC as u8,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 1,
            ifi_flags: 0,
            ifi_change: 0,
        };
        request::Link::new(body)
            .xdp(xdp)
            .send(&sock, NLM_F_REQUEST as u16)
            .unwrap();
        drop(sock);

        // 16-byte message header, 16-byte ifinfomsg, 4-byte nested header,
        // and up to three 8-byte attributes, plus one byte to detect overflow.
        let mut buf = Vec::new();
        let len = receiver.take(61).read_to_end(&mut buf).unwrap();
        assert_eq!(len, if expected_fd.is_some() { 60 } else { 52 });
        let msg = NetlinkMessage::read(&buf).unwrap();
        assert_eq!(msg.header.nlmsg_len as usize, len);
        assert_eq!(msg.header.nlmsg_type, libc::RTM_SETLINK);
        let (received_body, attrs) = msg.data.split_at(size_of::<ifinfomsg>());
        assert_eq!(received_body, bytes_of(&body));
        let mut iter = NlAttrsIterator::new(attrs);
        let outer = iter.next().unwrap().unwrap();
        assert_eq!(outer.header.nla_type, libc::IFLA_XDP | NLA_F_NESTED as u16);
        assert!(iter.next().is_none());
        let mut iter = NlAttrsIterator::new(outer.data);
        for (kind, bytes) in [
            (IFLA_XDP_FD, (-1i32).to_ne_bytes()),
            (IFLA_XDP_FLAGS, XDP_FLAGS_REPLACE.to_ne_bytes()),
        ]
        .into_iter()
        .chain(expected_fd.map(|fd| (IFLA_XDP_EXPECTED_FD, fd.to_ne_bytes())))
        {
            let attr = iter.next().unwrap().unwrap();
            assert_eq!(attr.header.nla_type, kind as u16);
            assert_eq!(attr.data, bytes);
        }
        assert!(iter.next().is_none());
    }
}
