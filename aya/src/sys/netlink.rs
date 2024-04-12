use std::{
    collections::HashMap,
    ffi::CStr,
    io, mem,
    net::Ipv4Addr,
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
    ptr, slice,
};

use libc::{
    getsockname, nlattr, nlmsgerr, nlmsghdr, recv, send, setsockopt, sockaddr_nl, socket, AF_INET,
    AF_NETLINK, AF_UNSPEC, ETH_P_ALL, IFA_F_PERMANENT, IFA_LOCAL, IFF_UP, IFLA_IFNAME,
    IFLA_INFO_DATA, IFLA_INFO_KIND, IFLA_LINKINFO, IFLA_XDP, NETLINK_EXT_ACK, NETLINK_ROUTE,
    NLA_ALIGNTO, NLA_F_NESTED, NLA_TYPE_MASK, NLMSG_DONE, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_DUMP, NLM_F_ECHO, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REQUEST, RTM_DELLINK, RTM_DELTFILTER,
    RTM_GETTFILTER, RTM_NEWADDR, RTM_NEWLINK, RTM_NEWQDISC, RTM_NEWTFILTER, RTM_SETLINK,
    RT_SCOPE_UNIVERSE, SOCK_RAW, SOL_NETLINK,
};
use thiserror::Error;

use crate::{
    generated::{
        ifaddrmsg, ifinfomsg, tcmsg, IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS,
        NLMSG_ALIGNTO, TCA_BPF_FD, TCA_BPF_FLAGS, TCA_BPF_FLAG_ACT_DIRECT, TCA_BPF_NAME, TCA_KIND,
        TCA_OPTIONS, TC_H_CLSACT, TC_H_INGRESS, TC_H_MAJ_MASK, TC_H_UNSPEC, VETH_INFO_PEER,
        XDP_FLAGS_REPLACE,
    },
    programs::TcAttachType,
    util::tc_handler_make,
};

const NLA_HDR_LEN: usize = align_to(mem::size_of::<nlattr>(), NLA_ALIGNTO as usize);

// Safety: marking this as unsafe overall because of all the pointer math required to comply with
// netlink alignments
pub(crate) unsafe fn netlink_set_xdp_fd(
    if_index: i32,
    fd: Option<BorrowedFd<'_>>,
    old_fd: Option<BorrowedFd<'_>>,
    flags: u32,
) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = mem::zeroed::<Request>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>();
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
    let attrs_buf = request_attributes(&mut req, nlmsg_len);
    let mut attrs = NestedAttrs::new(attrs_buf, IFLA_XDP);
    attrs.write_attr(
        IFLA_XDP_FD as u16,
        fd.map(|fd| fd.as_raw_fd()).unwrap_or(-1),
    )?;

    if flags > 0 {
        attrs.write_attr(IFLA_XDP_FLAGS as u16, flags)?;
    }

    if flags & XDP_FLAGS_REPLACE != 0 {
        attrs.write_attr(
            IFLA_XDP_EXPECTED_FD as u16,
            old_fd.map(|fd| fd.as_raw_fd()).unwrap(),
        )?;
    }

    let nla_len = attrs.finish()?;
    req.header.nlmsg_len += align_to(nla_len, NLA_ALIGNTO as usize) as u32;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;

    sock.recv()?;

    Ok(())
}

pub(crate) unsafe fn netlink_qdisc_add_clsact(if_index: i32) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    let mut req = mem::zeroed::<TcRequest>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>();
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
    let attrs_buf = request_attributes(&mut req, nlmsg_len);
    let attr_len = write_attr_bytes(attrs_buf, 0, TCA_KIND as u16, b"clsact\0")?;
    req.header.nlmsg_len += align_to(attr_len, NLA_ALIGNTO as usize) as u32;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

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
) -> Result<(u16, u32), io::Error> {
    let sock = NetlinkSocket::open()?;
    let mut req = mem::zeroed::<TcRequest>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>();
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
    req.tc_info.tcm_parent = attach_type.parent();
    req.tc_info.tcm_info = tc_handler_make((priority as u32) << 16, htons(ETH_P_ALL as u16) as u32);

    let attrs_buf = request_attributes(&mut req, nlmsg_len);

    // add TCA_KIND
    let kind_len = write_attr_bytes(attrs_buf, 0, TCA_KIND as u16, b"bpf\0")?;

    // add TCA_OPTIONS which includes TCA_BPF_FD, TCA_BPF_NAME and TCA_BPF_FLAGS
    let mut options = NestedAttrs::new(&mut attrs_buf[kind_len..], TCA_OPTIONS as u16);
    options.write_attr(TCA_BPF_FD as u16, prog_fd)?;
    options.write_attr_bytes(TCA_BPF_NAME as u16, prog_name.to_bytes_with_nul())?;
    let flags: u32 = TCA_BPF_FLAG_ACT_DIRECT;
    options.write_attr(TCA_BPF_FLAGS as u16, flags)?;
    let options_len = options.finish()?;

    req.header.nlmsg_len += align_to(kind_len + options_len, NLA_ALIGNTO as usize) as u32;
    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;

    // find the RTM_NEWTFILTER reply and read the tcm_info and tcm_handle fields
    // which we'll need to detach
    let tc_msg = match sock
        .recv()?
        .iter()
        .find(|reply| reply.header.nlmsg_type == RTM_NEWTFILTER)
    {
        Some(reply) => ptr::read_unaligned(reply.data.as_ptr() as *const tcmsg),
        None => {
            // if sock.recv() succeeds we should never get here unless there's a
            // bug in the kernel
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "no RTM_NEWTFILTER reply received, this is a bug.",
            ));
        }
    };

    let priority = ((tc_msg.tcm_info & TC_H_MAJ_MASK) >> 16) as u16;
    Ok((priority, tc_msg.tcm_handle))
}

pub(crate) unsafe fn netlink_qdisc_detach(
    if_index: i32,
    attach_type: &TcAttachType,
    priority: u16,
    handle: u32,
) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;
    let mut req = mem::zeroed::<TcRequest>();

    req.header = nlmsghdr {
        nlmsg_len: (mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>()) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_DELTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };

    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_handle = handle; // auto-assigned, if zero
    req.tc_info.tcm_info = tc_handler_make((priority as u32) << 16, htons(ETH_P_ALL as u16) as u32);
    req.tc_info.tcm_parent = attach_type.parent();
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
) -> Result<Vec<(u16, u32)>, io::Error> {
    let mut req = mem::zeroed::<TcRequest>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>();
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
    req.tc_info.tcm_parent = attach_type.parent();

    let sock = NetlinkSocket::open()?;
    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;

    let mut filter_info = Vec::new();
    for msg in sock.recv()? {
        if msg.header.nlmsg_type != RTM_NEWTFILTER {
            continue;
        }

        let tc_msg = ptr::read_unaligned(msg.data.as_ptr() as *const tcmsg);
        let priority = (tc_msg.tcm_info >> 16) as u16;
        let attrs = parse_attrs(&msg.data[mem::size_of::<tcmsg>()..])?;

        if let Some(opts) = attrs.get(&(TCA_OPTIONS as u16)) {
            let opts = parse_attrs(opts.data)?;
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
pub unsafe fn netlink_add_veth_pair(name1: &CStr, name2: &CStr) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = mem::zeroed::<Request>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
        nlmsg_type: RTM_NEWLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = 0;
    req.if_info.ifi_flags = 0;
    req.if_info.ifi_change = 0;

    let attrs_buf = request_attributes(&mut req, nlmsg_len);

    // add IFLA_IFNAME
    let ifname_len = write_attr_bytes(attrs_buf, 0, IFLA_IFNAME, name1.to_bytes_with_nul())?;

    // add IFLA_LINKINFO which includes IFLA_INFO_KIND and IFLA_INFO_DATA
    let mut linkinfo = NestedAttrs::new(&mut attrs_buf[ifname_len..], IFLA_LINKINFO);
    linkinfo.write_attr_bytes(IFLA_INFO_KIND, b"veth")?;

    linkinfo.write_nested_attrs(IFLA_INFO_DATA, |info_data| {
        info_data.write_nested_attrs(VETH_INFO_PEER as u16, |info_peer| {
            // Safety: ifinfomsg is POD so this is safe
            let mut peer_if_info = mem::zeroed::<ifinfomsg>();
            peer_if_info.ifi_family = AF_UNSPEC as u8;
            peer_if_info.ifi_index = 0;
            peer_if_info.ifi_flags = 0;
            peer_if_info.ifi_change = 0;

            info_peer.write_bytes(bytes_of(&peer_if_info))?;

            // add IFLA_IFNAME
            info_peer.write_attr_bytes(IFLA_IFNAME, name2.to_bytes_with_nul())?;

            Ok(())
        })?;
        Ok(())
    })?;

    let linkinfo_len = linkinfo.finish()?;

    req.header.nlmsg_len += align_to(ifname_len + linkinfo_len, NLA_ALIGNTO as usize) as u32;
    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

    Ok(())
}

#[doc(hidden)]
pub unsafe fn netlink_set_link_up(if_index: i32) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = mem::zeroed::<Request>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>();
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

#[doc(hidden)]
pub unsafe fn netlink_set_link_down(if_index: i32) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = mem::zeroed::<Request>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;
    req.if_info.ifi_flags = 0;
    req.if_info.ifi_change = IFF_UP as u32;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

    Ok(())
}

#[doc(hidden)]
pub unsafe fn netlink_delete_link(if_index: i32) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    // Safety: Request is POD so this is safe
    let mut req = mem::zeroed::<Request>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_DELLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;
    req.if_info.ifi_flags = 0;
    req.if_info.ifi_change = 0;

    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

    Ok(())
}

#[doc(hidden)]
pub unsafe fn netlink_add_ip_addr(
    if_index: u32,
    ipv4_addr: Ipv4Addr,
    ipv4_prefix: u8,
) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    // Safety: AddrRequest is POD so this is safe
    let mut req = mem::zeroed::<AddrRequest>();

    let nlmsg_len = mem::size_of::<nlmsghdr>() + mem::size_of::<ifaddrmsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_addr.ifa_family = AF_INET as u8;
    req.if_addr.ifa_prefixlen = ipv4_prefix;
    req.if_addr.ifa_flags = IFA_F_PERMANENT as u8;
    req.if_addr.ifa_scope = RT_SCOPE_UNIVERSE;
    req.if_addr.ifa_index = if_index;

    let attrs_buf = request_attributes(&mut req, nlmsg_len);

    // add IFA_LOCAL
    let local_len = write_attr_bytes(attrs_buf, 0, IFA_LOCAL, &ipv4_addr.octets())?;

    req.header.nlmsg_len += align_to(local_len, NLA_ALIGNTO as usize) as u32;
    sock.send(&bytes_of(&req)[..req.header.nlmsg_len as usize])?;
    sock.recv()?;

    Ok(())
}

#[repr(C)]
struct Request {
    header: nlmsghdr,
    if_info: ifinfomsg,
    attrs: [u8; 128],
}

#[repr(C)]
struct TcRequest {
    header: nlmsghdr,
    tc_info: tcmsg,
    attrs: [u8; 64],
}

#[repr(C)]
struct AddrRequest {
    header: nlmsghdr,
    if_addr: ifaddrmsg,
    attrs: [u8; 64],
}

struct NetlinkSocket {
    sock: OwnedFd,
    _nl_pid: u32,
}

impl NetlinkSocket {
    fn open() -> Result<Self, io::Error> {
        // Safety: libc wrapper
        let sock = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `socket` returns a file descriptor.
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };

        let enable = 1i32;
        // Safety: libc wrapper
        unsafe {
            setsockopt(
                sock.as_raw_fd(),
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                &enable as *const _ as *const _,
                mem::size_of::<i32>() as u32,
            )
        };

        // Safety: sockaddr_nl is POD so this is safe
        let mut addr = unsafe { mem::zeroed::<sockaddr_nl>() };
        addr.nl_family = AF_NETLINK as u16;
        let mut addr_len = mem::size_of::<sockaddr_nl>() as u32;
        // Safety: libc wrapper
        if unsafe {
            getsockname(
                sock.as_raw_fd(),
                &mut addr as *mut _ as *mut _,
                &mut addr_len as *mut _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            sock,
            _nl_pid: addr.nl_pid,
        })
    }

    fn send(&self, msg: &[u8]) -> Result<(), io::Error> {
        if unsafe {
            send(
                self.sock.as_raw_fd(),
                msg.as_ptr() as *const _,
                msg.len(),
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self) -> Result<Vec<NetlinkMessage>, io::Error> {
        let mut buf = [0u8; 4096];
        let mut messages = Vec::new();
        let mut multipart = true;
        'out: while multipart {
            multipart = false;
            // Safety: libc wrapper
            let len = unsafe {
                recv(
                    self.sock.as_raw_fd(),
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    0,
                )
            };
            if len < 0 {
                return Err(io::Error::last_os_error());
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
                match message.header.nlmsg_type as i32 {
                    NLMSG_ERROR => {
                        let err = message.error.unwrap();
                        if err.error == 0 {
                            // this is an ACK
                            continue;
                        }
                        return Err(io::Error::from_raw_os_error(-err.error));
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
        if mem::size_of::<nlmsghdr>() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "buffer smaller than nlmsghdr",
            ));
        }

        // Safety: nlmsghdr is POD so read is safe
        let header = unsafe { ptr::read_unaligned(buf.as_ptr() as *const nlmsghdr) };
        let msg_len = header.nlmsg_len as usize;
        if msg_len < mem::size_of::<nlmsghdr>() || msg_len > buf.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid nlmsg_len"));
        }

        let data_offset = align_to(mem::size_of::<nlmsghdr>(), NLMSG_ALIGNTO as usize);
        if data_offset >= buf.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "need more data"));
        }

        let (data, error) = if header.nlmsg_type == NLMSG_ERROR as u16 {
            if data_offset + mem::size_of::<nlmsgerr>() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "NLMSG_ERROR but not enough space for nlmsgerr",
                ));
            }
            (
                Vec::new(),
                // Safety: nlmsgerr is POD so read is safe
                Some(unsafe {
                    ptr::read_unaligned(buf[data_offset..].as_ptr() as *const nlmsgerr)
                }),
            )
        } else {
            (buf[data_offset..msg_len].to_vec(), None)
        };

        Ok(Self {
            header,
            data,
            error,
        })
    }
}

const fn align_to(v: usize, align: usize) -> usize {
    (v + (align - 1)) & !(align - 1)
}

fn htons(u: u16) -> u16 {
    u.to_be()
}

struct NestedAttrs<'a> {
    buf: &'a mut [u8],
    top_attr_type: u16,
    offset: usize,
}

impl<'a> NestedAttrs<'a> {
    fn new(buf: &'a mut [u8], top_attr_type: u16) -> Self {
        Self {
            buf,
            top_attr_type,
            offset: NLA_HDR_LEN,
        }
    }

    fn write_attr<T>(&mut self, attr_type: u16, value: T) -> Result<usize, io::Error> {
        let size = write_attr(self.buf, self.offset, attr_type, value)?;
        self.offset += size;
        Ok(size)
    }

    fn write_attr_bytes(&mut self, attr_type: u16, value: &[u8]) -> Result<usize, io::Error> {
        let size = write_attr_bytes(self.buf, self.offset, attr_type, value)?;
        self.offset += size;
        Ok(size)
    }

    fn write_bytes(&mut self, value: &[u8]) -> Result<usize, io::Error> {
        let size = write_bytes(self.buf, self.offset, value)?;
        self.offset += size;
        Ok(size)
    }

    fn write_nested_attrs<F>(&mut self, attr_type: u16, f: F) -> Result<usize, io::Error>
    where
        F: FnOnce(&mut NestedAttrs<'_>) -> Result<(), io::Error>,
    {
        let mut nested_attrs = NestedAttrs::new(&mut self.buf[self.offset..], attr_type);
        f(&mut nested_attrs)?;
        let size = nested_attrs.finish()?;
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

fn write_attr<T>(
    buf: &mut [u8],
    offset: usize,
    attr_type: u16,
    value: T,
) -> Result<usize, io::Error> {
    let value =
        unsafe { slice::from_raw_parts(&value as *const _ as *const _, mem::size_of::<T>()) };
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

fn write_attr_header(buf: &mut [u8], offset: usize, attr: nlattr) -> Result<usize, io::Error> {
    let attr =
        unsafe { slice::from_raw_parts(&attr as *const _ as *const _, mem::size_of::<nlattr>()) };

    write_bytes(buf, offset, attr)?;
    Ok(NLA_HDR_LEN)
}

fn write_bytes(buf: &mut [u8], offset: usize, value: &[u8]) -> Result<usize, io::Error> {
    let align_len = align_to(value.len(), NLA_ALIGNTO as usize);
    if offset + align_len > buf.len() {
        return Err(io::Error::new(io::ErrorKind::Other, "no space left"));
    }

    buf[offset..offset + value.len()].copy_from_slice(value);

    Ok(align_len)
}

struct NlAttrsIterator<'a> {
    attrs: &'a [u8],
    offset: usize,
}

impl<'a> NlAttrsIterator<'a> {
    fn new(attrs: &'a [u8]) -> Self {
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

        let attr = unsafe { ptr::read_unaligned(buf.as_ptr() as *const nlattr) };
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
enum NlAttrError {
    #[error("invalid buffer size `{size}`, expected `{expected}`")]
    InvalidBufferLength { size: usize, expected: usize },

    #[error("invalid nlattr header length `{0}`")]
    InvalidHeaderLength(usize),
}

impl From<NlAttrError> for io::Error {
    fn from(e: NlAttrError) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

unsafe fn request_attributes<T>(req: &mut T, msg_len: usize) -> &mut [u8] {
    let attrs_addr = align_to(req as *mut _ as usize + msg_len, NLMSG_ALIGNTO as usize);
    let attrs_end = req as *mut _ as usize + mem::size_of::<T>();
    slice::from_raw_parts_mut(attrs_addr as *mut u8, attrs_end - attrs_addr)
}

fn bytes_of<T>(val: &T) -> &[u8] {
    let size = mem::size_of::<T>();
    unsafe { slice::from_raw_parts(slice::from_ref(val).as_ptr().cast(), size) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

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
        let nla_len = (NLA_HDR_LEN * 3 + mem::size_of::<u32>() * 2) as u16;
        assert_eq!(len, nla_len);

        // read IFLA_XDP
        let attr = unsafe { ptr::read_unaligned(buf.as_ptr() as *const nlattr) };
        assert_eq!(attr.nla_type, NLA_F_NESTED as u16 | IFLA_XDP);
        assert_eq!(attr.nla_len, nla_len);

        // read IFLA_XDP_FD + fd
        let attr = unsafe { ptr::read_unaligned(buf[NLA_HDR_LEN..].as_ptr() as *const nlattr) };
        assert_eq!(attr.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.nla_len, (NLA_HDR_LEN + mem::size_of::<u32>()) as u16);
        let fd = unsafe { ptr::read_unaligned(buf[NLA_HDR_LEN * 2..].as_ptr() as *const u32) };
        assert_eq!(fd, 42);

        // read IFLA_XDP_EXPECTED_FD + fd
        let attr = unsafe {
            ptr::read_unaligned(
                buf[NLA_HDR_LEN * 2 + mem::size_of::<u32>()..].as_ptr() as *const nlattr
            )
        };
        assert_eq!(attr.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(attr.nla_len, (NLA_HDR_LEN + mem::size_of::<u32>()) as u16);
        let fd = unsafe {
            ptr::read_unaligned(
                buf[NLA_HDR_LEN * 3 + mem::size_of::<u32>()..].as_ptr() as *const u32
            )
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
        let mut buf = [0; NLA_HDR_LEN + mem::size_of::<u32>()];

        write_attr(&mut buf, 0, IFLA_XDP_FD as u16, 42u32).unwrap();

        let mut iter = NlAttrsIterator::new(&buf);
        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.data.len(), mem::size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nlattr_iterator_many() {
        let mut buf = [0; (NLA_HDR_LEN + mem::size_of::<u32>()) * 2];

        write_attr(&mut buf, 0, IFLA_XDP_FD as u16, 42u32).unwrap();
        write_attr(
            &mut buf,
            NLA_HDR_LEN + mem::size_of::<u32>(),
            IFLA_XDP_EXPECTED_FD as u16,
            12u32,
        )
        .unwrap();

        let mut iter = NlAttrsIterator::new(&buf);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_FD as u16);
        assert_eq!(attr.data.len(), mem::size_of::<u32>());
        assert_eq!(u32::from_ne_bytes(attr.data.try_into().unwrap()), 42);

        let attr = iter.next().unwrap().unwrap();
        assert_eq!(attr.header.nla_type, IFLA_XDP_EXPECTED_FD as u16);
        assert_eq!(attr.data.len(), mem::size_of::<u32>());
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
}
