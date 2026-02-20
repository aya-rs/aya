use std::{
    collections::HashMap,
    ffi::CStr,
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _},
    ptr, slice,
};

use aya_obj::generated::{
    IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS, NLMSG_ALIGNTO, TC_H_CLSACT, TC_H_INGRESS,
    TC_H_MAJ_MASK, TC_H_UNSPEC, TCA_BPF_FD, TCA_BPF_FLAG_ACT_DIRECT, TCA_BPF_FLAGS, TCA_BPF_NAME,
    TCA_KIND, TCA_OPTIONS, XDP_FLAGS_REPLACE, ifinfomsg, nlmsgerr_attrs::NLMSGERR_ATTR_MSG, tcmsg,
};
use libc::{
    AF_NETLINK, AF_UNSPEC, ETH_P_ALL, IFF_UP, IFLA_XDP, NETLINK_CAP_ACK, NETLINK_EXT_ACK,
    NETLINK_ROUTE, NLA_ALIGNTO, NLA_F_NESTED, NLA_TYPE_MASK, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP,
    NLM_F_ECHO, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, RTM_DELTFILTER,
    RTM_GETTFILTER, RTM_NEWQDISC, RTM_NEWTFILTER, RTM_SETLINK, SOCK_RAW, SOL_NETLINK, getsockname,
    nlattr, nlmsgerr, nlmsghdr, recv, send, setsockopt, sockaddr_nl, socket,
};
use thiserror::Error;

use crate::{
    Pod,
    programs::TcAttachType,
    util::{bytes_of, tc_handler_make},
};

const NLA_HDR_LEN: usize = align_to(size_of::<nlattr>(), NLA_ALIGNTO as usize);

/// `CLS_BPF_NAME_LEN` from the Linux kernel.
/// <https://github.com/torvalds/linux/blob/v6.19/net/sched/cls_bpf.c#L28>
const CLS_BPF_NAME_LEN: usize = 256;

// Size of the attribute buffer needed by write_tc_attach_attrs:
// TCA_KIND + nested TCA_OPTIONS containing TCA_BPF_FD, TCA_BPF_NAME, TCA_BPF_FLAGS.
const fn tc_request_attrs_size() -> usize {
    let al = NLA_ALIGNTO as usize;
    // TCA_KIND
    NLA_HDR_LEN + align_to(c"bpf".count_bytes() + 1, al)
    // TCA_OPTIONS header
    + NLA_HDR_LEN
    // TCA_BPF_FD
    + NLA_HDR_LEN + align_to(size_of::<i32>(), al)
    // TCA_BPF_NAME
    + NLA_HDR_LEN + align_to(CLS_BPF_NAME_LEN, al)
    // TCA_BPF_FLAGS
    + NLA_HDR_LEN + align_to(size_of::<u32>(), al)
}

const _: () = assert!(tc_request_attrs_size() == 288);

/// A private error type for internal use in this module.
#[derive(Error, Debug)]
pub(crate) enum NetlinkErrorInternal {
    #[error("netlink error: {message}")]
    Error {
        message: String,
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
                NlAttrError::InvalidBufferLength { .. }
                | NlAttrError::InvalidHeaderLength { .. } => None,
            },
        }
    }
}

/// # Safety
///
/// This function performs pointer arithmetic to satisfy netlink alignments.
pub(crate) unsafe fn netlink_set_xdp_fd(
    if_index: i32,
    fd: Option<BorrowedFd<'_>>,
    old_fd: Option<BorrowedFd<'_>>,
    flags: u32,
) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = unsafe { mem::zeroed::<Request>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;

    // write the attrs
    let attrs_buf = unsafe { request_attributes(&mut req, nlmsg_len) };
    let mut attrs = NestedAttrs::new(attrs_buf, IFLA_XDP);
    attrs
        .write_attr(IFLA_XDP_FD as u16, fd.map_or(-1, |fd| fd.as_raw_fd()))
        .map_err(|e| NetlinkError(NetlinkErrorInternal::IoError(e)))?;

    if flags > 0 {
        attrs
            .write_attr(IFLA_XDP_FLAGS as u16, flags)
            .map_err(|e| NetlinkError(NetlinkErrorInternal::IoError(e)))?;
    }

    if flags & XDP_FLAGS_REPLACE != 0 {
        attrs
            .write_attr(
                IFLA_XDP_EXPECTED_FD as u16,
                old_fd.map(|fd| fd.as_raw_fd()).unwrap(),
            )
            .map_err(|e| NetlinkError(NetlinkErrorInternal::IoError(e)))?;
    }

    let nla_len = attrs
        .finish()
        .map_err(|e| NetlinkError(NetlinkErrorInternal::IoError(e)))?;
    req.header.nlmsg_len += align_to(nla_len, NLA_ALIGNTO as usize) as u32;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;
    Ok(())
}

pub(crate) unsafe fn netlink_qdisc_add_clsact(if_index: i32) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let mut req = unsafe { mem::zeroed::<TcRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<tcmsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
        nlmsg_type: RTM_NEWQDISC,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_ifindex = if_index;
    req.tc_info.tcm_handle = tc_handler_make(TC_H_CLSACT, TC_H_UNSPEC);
    req.tc_info.tcm_parent = tc_handler_make(TC_H_CLSACT, TC_H_INGRESS);
    req.tc_info.tcm_info = 0;

    // add the TCA_KIND attribute
    let attrs_buf = unsafe { request_attributes(&mut req, nlmsg_len) };
    let attr_len = write_attr_bytes(attrs_buf, 0, TCA_KIND as u16, b"clsact\0")
        .map_err(|e| NetlinkError(NetlinkErrorInternal::IoError(e)))?;
    req.header.nlmsg_len += align_to(attr_len, NLA_ALIGNTO as usize) as u32;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

    Ok(())
}

fn write_tc_attach_attrs(
    req: &mut TcRequest,
    nlmsg_len: usize,
    prog_fd: i32,
    prog_name: &[u8],
) -> Result<(), io::Error> {
    let attrs_buf = unsafe { request_attributes(req, nlmsg_len) };

    let kind_len = write_attr_bytes(attrs_buf, 0, TCA_KIND as u16, c"bpf".to_bytes_with_nul())?;

    let mut options = NestedAttrs::new(&mut attrs_buf[kind_len..], TCA_OPTIONS as u16);
    options.write_attr(TCA_BPF_FD as u16, prog_fd)?;
    options.write_attr_bytes(TCA_BPF_NAME as u16, prog_name)?;
    options.write_attr(TCA_BPF_FLAGS as u16, TCA_BPF_FLAG_ACT_DIRECT)?;
    let options_len = options.finish()?;

    req.header.nlmsg_len += align_to(kind_len + options_len, NLA_ALIGNTO as usize) as u32;
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

    let mut req = unsafe { mem::zeroed::<TcRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<tcmsg>();
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
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO | request_flags) as u16,
        nlmsg_type: RTM_NEWTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_handle = handle; // auto-assigned, if zero
    req.tc_info.tcm_ifindex = if_index;
    req.tc_info.tcm_parent = attach_type.tc_parent();
    req.tc_info.tcm_info = tc_handler_make(
        u32::from(priority) << 16,
        u32::from(htons(ETH_P_ALL as u16)),
    );

    write_tc_attach_attrs(
        &mut req,
        nlmsg_len,
        prog_fd.as_raw_fd(),
        prog_name.to_bytes_with_nul(),
    )
    .map_err(|e| NetlinkError(NetlinkErrorInternal::IoError(e)))?;
    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;

    // find the RTM_NEWTFILTER reply and read the tcm_info and tcm_handle fields
    // which we'll need to detach
    let tc_msg: tcmsg = match sock
        .recv()?
        .iter()
        .find(|reply| reply.header.nlmsg_type == RTM_NEWTFILTER)
    {
        Some(reply) => unsafe { ptr::read_unaligned(reply.data.as_ptr().cast()) },
        None => {
            // if sock.recv() succeeds we should never get here unless there's a
            // bug in the kernel
            return Err(NetlinkError(NetlinkErrorInternal::IoError(
                io::Error::other("no RTM_NEWTFILTER reply received, this is a bug."),
            )));
        }
    };

    let priority = ((tc_msg.tcm_info & TC_H_MAJ_MASK) >> 16) as u16;
    Ok((priority, tc_msg.tcm_handle))
}

pub(crate) unsafe fn netlink_qdisc_detach(
    if_index: i32,
    attach_type: TcAttachType,
    priority: u16,
    handle: u32,
) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    let mut req = unsafe { mem::zeroed::<TcRequest>() };

    req.header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>() + size_of::<tcmsg>()) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_DELTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_handle = handle; // auto-assigned, if zero
    req.tc_info.tcm_info = tc_handler_make(
        u32::from(priority) << 16,
        u32::from(htons(ETH_P_ALL as u16)),
    );
    req.tc_info.tcm_parent = attach_type.tc_parent();
    req.tc_info.tcm_ifindex = if_index;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;

    sock.recv()?;

    Ok(())
}

// Returns a vector of tuple (priority, handle) for filters matching the provided parameters
pub(crate) unsafe fn netlink_find_filter_with_name(
    if_index: i32,
    attach_type: TcAttachType,
    name: &CStr,
) -> Result<Vec<(u16, u32)>, NetlinkError> {
    let mut req = unsafe { mem::zeroed::<TcRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<tcmsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_type: RTM_GETTFILTER,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_DUMP) as u16,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_handle = 0; // auto-assigned, if zero
    req.tc_info.tcm_ifindex = if_index;
    req.tc_info.tcm_parent = attach_type.tc_parent();

    let sock = NetlinkSocket::open()?;
    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;

    let mut filter_info = Vec::new();
    for msg in sock.recv()? {
        if msg.header.nlmsg_type != RTM_NEWTFILTER {
            continue;
        }

        let tc_msg: tcmsg = unsafe { ptr::read_unaligned(msg.data.as_ptr().cast()) };
        let priority = (tc_msg.tcm_info >> 16) as u16;
        let attrs = parse_attrs(&msg.data[size_of::<tcmsg>()..])
            .map_err(|e| NetlinkError(NetlinkErrorInternal::NlAttrError(e)))?;

        if let Some(opts) = attrs.get(&(TCA_OPTIONS as u16)) {
            let opts = parse_attrs(opts.data)
                .map_err(|e| NetlinkError(NetlinkErrorInternal::NlAttrError(e)))?;
            if let Some(f_name) = opts.get(&(TCA_BPF_NAME as u16)) {
                if let Ok(f_name) = CStr::from_bytes_with_nul(f_name.data) {
                    if name == f_name {
                        filter_info.push((priority, tc_msg.tcm_handle));
                    }
                }
            }
        }
    }

    Ok(filter_info)
}

#[doc(hidden)]
pub unsafe fn netlink_set_link_up(if_index: i32) -> Result<(), NetlinkError> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = unsafe { mem::zeroed::<Request>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;
    req.if_info.ifi_flags = IFF_UP as u32;
    req.if_info.ifi_change = IFF_UP as u32;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

    Ok(())
}

#[derive(Copy, Clone)]
#[repr(C)]
struct Request {
    header: nlmsghdr,
    if_info: ifinfomsg,
    attrs: [u8; 64],
}

unsafe impl Pod for Request {}

#[derive(Copy, Clone)]
#[repr(C)]
struct TcRequest {
    header: nlmsghdr,
    tc_info: tcmsg,
    // Must fit all netlink attributes written by write_tc_attach_attrs.
    attrs: [u8; tc_request_attrs_size()],
}

unsafe impl Pod for TcRequest {}

struct NetlinkSocket {
    sock: crate::MockableFd,
    _nl_pid: u32,
}

impl NetlinkSocket {
    fn open() -> Result<Self, NetlinkErrorInternal> {
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
        let mut addr_len = size_of::<sockaddr_nl>() as u32;
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

    fn send(&self, msg: &[u8]) -> Result<(), NetlinkErrorInternal> {
        if unsafe { send(self.sock.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) } < 0 {
            return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn recv(&self) -> Result<Vec<NetlinkMessage>, NetlinkErrorInternal> {
        let mut buf = [0u8; 4096];
        let mut messages = Vec::new();
        let mut multipart = true;
        'out: while multipart {
            multipart = false;
            // Safety: libc wrapper
            let len = unsafe { recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if len < 0 {
                return Err(NetlinkErrorInternal::IoError(io::Error::last_os_error()));
            }
            if len == 0 {
                break;
            }

            let len = len as usize;
            let mut offset = 0;
            while offset < len {
                let message = NetlinkMessage::read(&buf[offset..])?;
                offset += align_to(message.header.nlmsg_len as usize, NLMSG_ALIGNTO as usize);
                multipart = message.header.nlmsg_flags & NLM_F_MULTI as u16 != 0;
                match i32::from(message.header.nlmsg_type) {
                    NLMSG_ERROR => {
                        let err = message.error.unwrap();
                        if err.error == 0 {
                            // this is an ACK
                            continue;
                        }
                        let attrs = parse_attrs(&message.data)?;
                        let err_msg = attrs.get(&(NLMSGERR_ATTR_MSG as u16)).and_then(|msg| {
                            CStr::from_bytes_with_nul(msg.data)
                                .ok()
                                .map(|s| s.to_string_lossy().into_owned())
                        });
                        let e = match err_msg {
                            Some(err_msg) => NetlinkErrorInternal::Error {
                                message: err_msg,
                                source: io::Error::from_raw_os_error(-err.error),
                            },
                            None => NetlinkErrorInternal::IoError(io::Error::from_raw_os_error(
                                -err.error,
                            )),
                        };
                        return Err(e);
                    }
                    NLMSG_DONE => break 'out,
                    _ => messages.push(message),
                }
            }
        }

        Ok(messages)
    }
}

struct NetlinkMessage {
    header: nlmsghdr,
    data: Vec<u8>,
    error: Option<nlmsgerr>,
}

impl NetlinkMessage {
    fn read(buf: &[u8]) -> Result<Self, io::Error> {
        if size_of::<nlmsghdr>() > buf.len() {
            return Err(io::Error::other("buffer smaller than nlmsghdr"));
        }

        // Safety: nlmsghdr is POD so read is safe
        let header: nlmsghdr = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
        let msg_len = header.nlmsg_len as usize;
        if msg_len < size_of::<nlmsghdr>() || msg_len > buf.len() {
            return Err(io::Error::other("invalid nlmsg_len"));
        }

        let data_offset = align_to(size_of::<nlmsghdr>(), NLMSG_ALIGNTO as usize);
        if data_offset >= buf.len() {
            return Err(io::Error::other("need more data"));
        }

        let (rest, error) = if header.nlmsg_type == NLMSG_ERROR as u16 {
            if data_offset + size_of::<nlmsgerr>() > buf.len() {
                return Err(io::Error::other(
                    "NLMSG_ERROR but not enough space for nlmsgerr",
                ));
            }
            (
                &buf[data_offset + size_of::<nlmsgerr>()..msg_len],
                // Safety: nlmsgerr is POD so read is safe
                Some(unsafe { ptr::read_unaligned(buf[data_offset..].as_ptr().cast()) }),
            )
        } else {
            (&buf[data_offset..msg_len], None)
        };

        Ok(Self {
            header,
            data: rest.to_vec(),
            error,
        })
    }
}

const fn align_to(v: usize, align: usize) -> usize {
    v.next_multiple_of(align)
}

const fn htons(u: u16) -> u16 {
    u.to_be()
}

struct NestedAttrs<'a> {
    buf: &'a mut [u8],
    top_attr_type: u16,
    offset: usize,
}

impl<'a> NestedAttrs<'a> {
    const fn new(buf: &'a mut [u8], top_attr_type: u16) -> Self {
        Self {
            buf,
            top_attr_type,
            offset: NLA_HDR_LEN,
        }
    }

    fn write_attr<T: Pod>(&mut self, attr_type: u16, value: T) -> Result<usize, io::Error> {
        let size = write_attr(self.buf, self.offset, attr_type, value)?;
        self.offset += size;
        Ok(size)
    }

    fn write_attr_bytes(&mut self, attr_type: u16, value: &[u8]) -> Result<usize, io::Error> {
        let size = write_attr_bytes(self.buf, self.offset, attr_type, value)?;
        self.offset += size;
        Ok(size)
    }

    fn finish(self) -> Result<usize, io::Error> {
        let nla_len = self.offset;
        let attr = nlattr {
            nla_type: NLA_F_NESTED as u16 | self.top_attr_type,
            nla_len: nla_len as u16,
        };

        write_attr_header(self.buf, 0, attr)?;
        Ok(nla_len)
    }
}

fn write_attr<T: Pod>(
    buf: &mut [u8],
    offset: usize,
    attr_type: u16,
    value: T,
) -> Result<usize, io::Error> {
    let value = bytes_of(&value);
    write_attr_bytes(buf, offset, attr_type, value)
}

fn write_attr_bytes(
    buf: &mut [u8],
    offset: usize,
    attr_type: u16,
    value: &[u8],
) -> Result<usize, io::Error> {
    let attr = nlattr {
        nla_type: attr_type,
        nla_len: ((NLA_HDR_LEN + value.len()) as u16),
    };

    write_attr_header(buf, offset, attr)?;
    let value_len = write_bytes(buf, offset + NLA_HDR_LEN, value)?;

    Ok(NLA_HDR_LEN + value_len)
}

unsafe impl Pod for nlattr {}

fn write_attr_header(buf: &mut [u8], offset: usize, attr: nlattr) -> Result<usize, io::Error> {
    let attr = bytes_of(&attr);
    write_bytes(buf, offset, attr)?;
    Ok(NLA_HDR_LEN)
}

fn write_bytes(buf: &mut [u8], offset: usize, value: &[u8]) -> Result<usize, io::Error> {
    let align_len = align_to(value.len(), NLA_ALIGNTO as usize);
    if offset + align_len > buf.len() {
        return Err(io::Error::other("no space left"));
    }

    buf[offset..offset + value.len()].copy_from_slice(value);

    Ok(align_len)
}

struct NlAttrsIterator<'a> {
    attrs: &'a [u8],
    offset: usize,
}

impl<'a> NlAttrsIterator<'a> {
    const fn new(attrs: &'a [u8]) -> Self {
        Self { attrs, offset: 0 }
    }
}

impl<'a> Iterator for NlAttrsIterator<'a> {
    type Item = Result<NlAttr<'a>, NlAttrError>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = &self.attrs[self.offset..];
        if buf.is_empty() {
            return None;
        }

        if NLA_HDR_LEN > buf.len() {
            self.offset = buf.len();
            return Some(Err(NlAttrError::InvalidBufferLength {
                size: buf.len(),
                expected: NLA_HDR_LEN,
            }));
        }

        let attr: nlattr = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
        let len = attr.nla_len as usize;
        let align_len = align_to(len, NLA_ALIGNTO as usize);
        if len < NLA_HDR_LEN {
            return Some(Err(NlAttrError::InvalidHeaderLength(len)));
        }
        if align_len > buf.len() {
            return Some(Err(NlAttrError::InvalidBufferLength {
                size: buf.len(),
                expected: align_len,
            }));
        }

        let data = &buf[NLA_HDR_LEN..len];

        self.offset += align_len;
        Some(Ok(NlAttr { header: attr, data }))
    }
}

fn parse_attrs(buf: &[u8]) -> Result<HashMap<u16, NlAttr<'_>>, NlAttrError> {
    let mut attrs = HashMap::new();
    for attr in NlAttrsIterator::new(buf) {
        let attr = attr?;
        attrs.insert(attr.header.nla_type & NLA_TYPE_MASK as u16, attr);
    }
    Ok(attrs)
}

#[derive(Clone)]
struct NlAttr<'a> {
    header: nlattr,
    data: &'a [u8],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum NlAttrError {
    #[error("invalid buffer size `{size}`, expected `{expected}`")]
    InvalidBufferLength { size: usize, expected: usize },

    #[error("invalid nlattr header length `{0}`")]
    InvalidHeaderLength(usize),
}

unsafe fn request_attributes<T>(req: &mut T, msg_len: usize) -> &mut [u8] {
    let req: *mut _ = req;
    let req: *mut u8 = req.cast();
    let attrs_addr = unsafe { req.add(msg_len) };
    let align_offset = attrs_addr.align_offset(NLMSG_ALIGNTO as usize);
    let attrs_addr = unsafe { attrs_addr.add(align_offset) };
    let len = size_of::<T>() - msg_len - align_offset;
    unsafe { slice::from_raw_parts_mut(attrs_addr, len) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_nested_attrs() {
        let mut buf = [0; 64];

        // write IFLA_XDP with 2 nested attrs
        let mut attrs = NestedAttrs::new(&mut buf, IFLA_XDP);
        attrs.write_attr(IFLA_XDP_FD as u16, 42u32).unwrap();
        attrs
            .write_attr(IFLA_XDP_EXPECTED_FD as u16, 24u32)
            .unwrap();
        let len = attrs.finish().unwrap() as u16;

        // 3 nlattr headers (IFLA_XDP, IFLA_XDP_FD and IFLA_XDP_EXPECTED_FD) + the fd
        let nla_len = (NLA_HDR_LEN * 3 + size_of::<u32>() * 2) as u16;
        assert_eq!(len, nla_len);

        // read IFLA_XDP
        let attr: nlattr = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
        assert_eq!(attr.nla_type, NLA_F_NESTED as u16 | IFLA_XDP);
        assert_eq!(attr.nla_len, nla_len);

        // read IFLA_XDP_FD + fd
        let attr: nlattr = unsafe { ptr::read_unaligned(buf[NLA_HDR_LEN..].as_ptr().cast()) };
        assert_eq!(attr.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.nla_len, (NLA_HDR_LEN + size_of::<u32>()) as u16);
        let fd: u32 = unsafe { ptr::read_unaligned(buf[NLA_HDR_LEN * 2..].as_ptr().cast()) };
        assert_eq!(fd, 42);

        // read IFLA_XDP_EXPECTED_FD + fd
        let attr: nlattr = unsafe {
            ptr::read_unaligned(buf[NLA_HDR_LEN * 2 + size_of::<u32>()..].as_ptr().cast())
        };
        assert_eq!(attr.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(attr.nla_len, (NLA_HDR_LEN + size_of::<u32>()) as u16);
        let fd: u32 = unsafe {
            ptr::read_unaligned(buf[NLA_HDR_LEN * 3 + size_of::<u32>()..].as_ptr().cast())
        };
        assert_eq!(fd, 24);
    }

    #[test]
    fn test_nlattr_iterator_empty() {
        let mut iter = NlAttrsIterator::new(&[]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlattr_iterator_one() {
        let mut buf = [0; NLA_HDR_LEN + size_of::<u32>()];

        write_attr(&mut buf, 0, IFLA_XDP_FD as u16, 42u32).unwrap();

        let mut iter = NlAttrsIterator::new(&buf);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.data.len(), size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlattr_iterator_many() {
        let mut buf = [0; (NLA_HDR_LEN + size_of::<u32>()) * 2];

        write_attr(&mut buf, 0, IFLA_XDP_FD as u16, 42u32).unwrap();
        write_attr(
            &mut buf,
            NLA_HDR_LEN + size_of::<u32>(),
            IFLA_XDP_EXPECTED_FD as u16,
            12u32,
        )
        .unwrap();

        let mut iter = NlAttrsIterator::new(&buf);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.data.len(), size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(attr.data.len(), size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 12);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlattr_iterator_nested() {
        let mut buf = [0; 1024];

        let mut options = NestedAttrs::new(&mut buf, TCA_OPTIONS as u16);
        options.write_attr(TCA_BPF_FD as u16, 42).unwrap();

        let name = CString::new("foo").unwrap();
        options
            .write_attr_bytes(TCA_BPF_NAME as u16, name.to_bytes_with_nul())
            .unwrap();
        options.finish().unwrap();

        let mut iter = NlAttrsIterator::new(&buf);
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
    }

    fn tc_request(name: &[u8]) -> io::Result<()> {
        let mut req = unsafe { mem::zeroed::<TcRequest>() };
        let nlmsg_len = size_of::<nlmsghdr>() + size_of::<tcmsg>();
        req.header.nlmsg_len = nlmsg_len as u32;

        write_tc_attach_attrs(&mut req, nlmsg_len, 0, name)
    }

    /// Verify that [`TcRequest`] fits all the attributes [`write_tc_attach_attrs`]
    /// writes, even with the kernel's maximum TC name length (`CLS_BPF_NAME_LEN`).
    ///
    /// Before the buffer was enlarged, serializing the netlink attributes for
    /// long names failed with "no space left".
    #[test]
    fn tc_request_fits_max_length_name() {
        assert_matches!(tc_request(&[b'a'; CLS_BPF_NAME_LEN]), Ok(()));
    }

    /// Verify that a name exceeding `CLS_BPF_NAME_LEN` is rejected.
    #[test]
    fn tc_request_rejects_oversized_name() {
        // One byte over the kernel's maximum — the attribute buffer is sized
        // exactly for CLS_BPF_NAME_LEN, so this should fail with "no space left".
        assert_matches!(
            tc_request(&[b'a'; CLS_BPF_NAME_LEN + 1]),
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::Other);
                assert_eq!(err.to_string(), "no space left");
            }
        );
    }
}
