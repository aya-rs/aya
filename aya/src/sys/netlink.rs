use std::{ffi::CStr, io, mem, os::unix::io::RawFd, ptr, slice};

use libc::{
    c_int, close, getsockname, nlattr, nlmsgerr, nlmsghdr, recv, send, setsockopt, sockaddr_nl,
    socket, AF_NETLINK, AF_UNSPEC, ETH_P_ALL, IFLA_XDP, NETLINK_ROUTE, NLA_ALIGNTO, NLA_F_NESTED,
    NLMSG_DONE, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE, NLM_F_ECHO, NLM_F_EXCL, NLM_F_MULTI,
    NLM_F_REQUEST, RTM_DELTFILTER, RTM_NEWQDISC, RTM_NEWTFILTER, RTM_SETLINK, SOCK_RAW,
    SOL_NETLINK,
};

use crate::{
    generated::{
        ifinfomsg, tcmsg, IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS, NLMSG_ALIGNTO,
        TCA_BPF_FD, TCA_BPF_FLAGS, TCA_BPF_FLAG_ACT_DIRECT, TCA_BPF_NAME, TCA_KIND, TCA_OPTIONS,
        TC_H_CLSACT, TC_H_INGRESS, TC_H_MAJ_MASK, TC_H_UNSPEC, XDP_FLAGS_REPLACE,
    },
    programs::TcAttachType,
    util::tc_handler_make,
};

const NLA_HDR_LEN: usize = align_to(mem::size_of::<nlattr>(), NLA_ALIGNTO as usize);
const NETLINK_EXT_ACK: c_int = 11;

// Safety: marking this as unsafe overall because of all the pointer math required to comply with
// netlink alignments
pub(crate) unsafe fn netlink_set_xdp_fd(
    if_index: i32,
    fd: RawFd,
    old_fd: Option<RawFd>,
    flags: u32,
) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    let seq = 1;
    // Safety: Request is POD so this is safe
    let mut req = mem::zeroed::<Request>();

    req.header = nlmsghdr {
        nlmsg_len: (mem::size_of::<nlmsghdr>() + mem::size_of::<ifinfomsg>()) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: seq,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;

    let attrs_buf = {
        let attrs_addr = align_to(
            &req as *const _ as usize + req.header.nlmsg_len as usize,
            NLMSG_ALIGNTO as usize,
        );
        let attrs_end = &req as *const _ as usize + mem::size_of::<Request>();
        slice::from_raw_parts_mut(attrs_addr as *mut u8, attrs_end - attrs_addr)
    };

    // write the attrs
    let mut attrs = NestedAttrs::new(attrs_buf, IFLA_XDP);
    attrs.write_attr(IFLA_XDP_FD as u16, fd)?;

    if flags > 0 {
        attrs.write_attr(IFLA_XDP_FLAGS as u16, flags)?;
    }

    if flags & XDP_FLAGS_REPLACE != 0 {
        attrs.write_attr(IFLA_XDP_EXPECTED_FD as u16, old_fd.unwrap())?;
    }

    let nla_len = attrs.finish()?;
    req.header.nlmsg_len += align_to(nla_len, NLA_ALIGNTO as usize) as u32;

    if send(
        sock.sock,
        &req as *const _ as *const _,
        req.header.nlmsg_len as usize,
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }

    sock.recv()?;

    Ok(())
}

pub(crate) unsafe fn netlink_qdisc_add_clsact(if_index: i32) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;

    let seq = 1;
    let mut req = mem::zeroed::<QdiscRequest>();

    // prepare the TC rquest
    req.header = nlmsghdr {
        nlmsg_len: (mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>()) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
        nlmsg_type: RTM_NEWQDISC,
        nlmsg_pid: 0,
        nlmsg_seq: seq,
    };
    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_ifindex = if_index;
    req.tc_info.tcm_handle = tc_handler_make(TC_H_CLSACT, TC_H_UNSPEC);
    req.tc_info.tcm_parent = tc_handler_make(TC_H_CLSACT, TC_H_INGRESS);
    req.tc_info.tcm_info = 0;

    // add the TCA_KIND attribute
    let attrs_buf = {
        let attrs_addr = align_to(
            &req as *const _ as usize + req.header.nlmsg_len as usize,
            NLMSG_ALIGNTO as usize,
        );
        let attrs_end = &req as *const _ as usize + mem::size_of::<QdiscRequest>();
        slice::from_raw_parts_mut(attrs_addr as *mut u8, attrs_end - attrs_addr)
    };
    let attr_len = write_attr_bytes(attrs_buf, 0, TCA_KIND as u16, b"clsact\0")?;
    req.header.nlmsg_len += align_to(attr_len as usize, NLA_ALIGNTO as usize) as u32;

    if send(
        sock.sock,
        &req as *const _ as *const _,
        req.header.nlmsg_len as usize,
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    sock.recv()?;

    Ok(())
}

pub(crate) unsafe fn netlink_qdisc_attach(
    if_index: i32,
    attach_type: &TcAttachType,
    prog_fd: RawFd,
    prog_name: &CStr,
) -> Result<u32, io::Error> {
    let sock = NetlinkSocket::open()?;
    let seq = 1;
    let priority = 0;
    let mut req = mem::zeroed::<QdiscRequest>();

    req.header = nlmsghdr {
        nlmsg_len: (mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>()) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE | NLM_F_ECHO) as u16,
        nlmsg_type: RTM_NEWTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: seq,
    };
    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_handle = 0; // auto-assigned, if not provided
    req.tc_info.tcm_ifindex = if_index;
    req.tc_info.tcm_parent = attach_type.parent();

    req.tc_info.tcm_info = tc_handler_make(priority << 16, htons(ETH_P_ALL as u16) as u32);

    let attrs_buf = {
        let attrs_addr = align_to(
            &req as *const _ as usize + req.header.nlmsg_len as usize,
            NLMSG_ALIGNTO as usize,
        );
        let attrs_end = &req as *const _ as usize + mem::size_of::<QdiscRequest>();
        slice::from_raw_parts_mut(attrs_addr as *mut u8, attrs_end - attrs_addr)
    };

    // add TCA_KIND
    let kind_len = write_attr_bytes(attrs_buf, 0, TCA_KIND as u16, b"bpf\0")?;

    // add TCA_OPTIONS which includes TCA_BPF_FD, TCA_BPF_NAME and TCA_BPF_FLAGS
    let mut options = NestedAttrs::new(&mut attrs_buf[kind_len..], TCA_OPTIONS as u16);
    options.write_attr(TCA_BPF_FD as u16, prog_fd)?;
    options.write_attr_bytes(TCA_BPF_NAME as u16, prog_name.to_bytes_with_nul())?;
    let flags: u32 = TCA_BPF_FLAG_ACT_DIRECT;
    options.write_attr(TCA_BPF_FLAGS as u16, flags)?;
    let options_len = options.finish()?;

    req.header.nlmsg_len += align_to(kind_len + options_len as usize, NLA_ALIGNTO as usize) as u32;

    if send(
        sock.sock,
        &req as *const _ as *const _,
        req.header.nlmsg_len as usize,
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }

    // find the RTM_NEWTFILTER reply and read the tcm_info field which we'll
    // need to detach
    let tc_info = match sock
        .recv()?
        .iter()
        .find(|reply| reply.header.nlmsg_type == RTM_NEWTFILTER)
    {
        Some(reply) => {
            let msg = ptr::read_unaligned(reply.data.as_ptr() as *const tcmsg);
            msg.tcm_info
        }
        None => {
            // if sock.recv() succeeds we should never get here unless there's a
            // bug in the kernel
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "no RTM_NEWTFILTER reply received, this is a bug.",
            ));
        }
    };

    let priority = ((tc_info & TC_H_MAJ_MASK) >> 16) as u32;
    Ok(priority)
}

pub(crate) unsafe fn netlink_qdisc_detach(
    if_index: i32,
    attach_type: &TcAttachType,
    priority: u32,
) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open()?;
    let seq = 1;
    let mut req = mem::zeroed::<QdiscRequest>();

    req.header = nlmsghdr {
        nlmsg_len: (mem::size_of::<nlmsghdr>() + mem::size_of::<tcmsg>()) as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_DELTFILTER,
        nlmsg_pid: 0,
        nlmsg_seq: seq,
    };

    req.tc_info.tcm_family = AF_UNSPEC as u8;
    req.tc_info.tcm_handle = 0; // auto-assigned, if not provided
    req.tc_info.tcm_info = tc_handler_make(priority << 16, htons(ETH_P_ALL as u16) as u32);
    req.tc_info.tcm_parent = attach_type.parent();
    req.tc_info.tcm_ifindex = if_index;

    if send(
        sock.sock,
        &req as *const _ as *const _,
        req.header.nlmsg_len as usize,
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }

    sock.recv()?;

    Ok(())
}

#[repr(C)]
struct Request {
    header: nlmsghdr,
    if_info: ifinfomsg,
    attrs: [u8; 64],
}

#[repr(C)]
struct QdiscRequest {
    header: nlmsghdr,
    tc_info: tcmsg,
    attrs: [u8; 64],
}

struct NetlinkSocket {
    sock: RawFd,
    _nl_pid: u32,
}

impl NetlinkSocket {
    fn open() -> Result<NetlinkSocket, io::Error> {
        // Safety: libc wrapper
        let sock = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        let enable = 1i32;
        // Safety: libc wrapper
        unsafe {
            setsockopt(
                sock,
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
        if unsafe { getsockname(sock, &mut addr as *mut _ as *mut _, &mut addr_len as *mut _) } < 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(NetlinkSocket {
            sock,
            _nl_pid: addr.nl_pid,
        })
    }

    fn recv(&self) -> Result<Vec<NetlinkMessage>, io::Error> {
        let mut buf = [0u8; 4096];
        let mut messages = Vec::new();
        let mut multipart = true;
        while multipart {
            multipart = false;
            // Safety: libc wrapper
            let len = unsafe { recv(self.sock, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
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
                    NLMSG_DONE => break,
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
    fn read(buf: &[u8]) -> Result<NetlinkMessage, io::Error> {
        if mem::size_of::<nlmsghdr>() > buf.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "need more data"));
        }

        // Safety: nlmsghdr is POD so read is safe
        let header = unsafe { ptr::read_unaligned(buf.as_ptr() as *const nlmsghdr) };
        let data_offset = align_to(mem::size_of::<nlmsghdr>(), NLMSG_ALIGNTO as usize);
        if data_offset >= buf.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "need more data"));
        }

        let (data, error) = if header.nlmsg_type == NLMSG_ERROR as u16 {
            if data_offset + mem::size_of::<nlmsgerr>() > buf.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "need more data"));
            }
            (
                Vec::new(),
                // Safety: nlmsgerr is POD so read is safe
                Some(unsafe {
                    ptr::read_unaligned(buf[data_offset..].as_ptr() as *const nlmsgerr)
                }),
            )
        } else {
            (buf[data_offset..].to_vec(), None)
        };

        Ok(NetlinkMessage {
            header,
            data,
            error,
        })
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        // Safety: libc wrapper
        unsafe { close(self.sock) };
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
    fn new(buf: &mut [u8], top_attr_type: u16) -> NestedAttrs<'_> {
        NestedAttrs {
            buf,
            top_attr_type,
            offset: NLA_HDR_LEN,
        }
    }

    fn write_attr<T>(&mut self, attr_type: u16, value: T) -> Result<usize, io::Error> {
        let size = write_attr(&mut self.buf, self.offset, attr_type, value)?;
        self.offset += size;
        Ok(size)
    }

    fn write_attr_bytes(&mut self, attr_type: u16, value: &[u8]) -> Result<usize, io::Error> {
        let size = write_attr_bytes(&mut self.buf, self.offset, attr_type, value)?;
        self.offset += size;
        Ok(size)
    }

    fn finish(self) -> Result<usize, io::Error> {
        let nla_len = self.offset;
        let attr = nlattr {
            nla_type: NLA_F_NESTED as u16 | self.top_attr_type as u16,
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
        nla_type: attr_type as u16,
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
    if offset + value.len() > buf.len() {
        return Err(io::Error::new(io::ErrorKind::Other, "no space left"));
    }

    buf[offset..offset + value.len()].copy_from_slice(value);

    Ok(value.len())
}

#[cfg(test)]
mod tests {
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
}
