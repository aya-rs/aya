use std::{io, mem, os::unix::io::RawFd, ptr};

use libc::{
    c_int, close, getsockname, nlattr, nlmsgerr, nlmsghdr, recv, send, setsockopt, sockaddr_nl,
    socket, AF_NETLINK, AF_UNSPEC, IFLA_XDP, NETLINK_ROUTE, NLA_ALIGNTO, NLA_F_NESTED, NLMSG_DONE,
    NLMSG_ERROR, NLM_F_ACK, NLM_F_MULTI, NLM_F_REQUEST, RTM_SETLINK, SOCK_RAW, SOL_NETLINK,
};

use crate::generated::{
    _bindgen_ty_79::{IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS},
    ifinfomsg, NLMSG_ALIGNTO, XDP_FLAGS_REPLACE,
};

const NETLINK_EXT_ACK: c_int = 11;

// Safety: marking this as unsafe overall because of all the pointer math required to comply with
// netlink alignments
pub(crate) unsafe fn netlink_set_xdp_fd(
    if_index: i32,
    fd: RawFd,
    old_fd: Option<RawFd>,
    flags: u32,
) -> Result<(), io::Error> {
    let sock = NetlinkSocket::open().unwrap();

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

    let attrs_addr = &req as *const _ as usize + req.header.nlmsg_len as usize;
    let attrs_addr = align_to(attrs_addr, NLMSG_ALIGNTO as usize);
    let nla_hdr_len = align_to(mem::size_of::<nlattr>(), NLA_ALIGNTO as usize);

    // length of the root attribute
    let mut nla_len = nla_hdr_len as u16;

    // set the program fd
    let mut offset = attrs_addr + nla_len as usize;
    let attr = nlattr {
        nla_type: IFLA_XDP_FD as u16,
        // header len + fd
        nla_len: (nla_hdr_len + mem::size_of::<RawFd>()) as u16,
    };
    // write the header
    ptr::write(offset as *mut nlattr, attr);
    offset += nla_hdr_len;
    // write the fd
    ptr::write(offset as *mut RawFd, fd);
    offset += 4;
    nla_len += attr.nla_len;

    if flags > 0 {
        // set the flags
        let attr = nlattr {
            nla_type: IFLA_XDP_FLAGS as u16,
            // header len + flags
            nla_len: (nla_hdr_len + mem::size_of::<u32>()) as u16,
        };
        // write the header
        ptr::write(offset as *mut nlattr, attr);
        offset += nla_hdr_len;
        // write the flags
        ptr::write(offset as *mut u32, flags);
        offset += 4;
        nla_len += attr.nla_len;
    }

    if flags & XDP_FLAGS_REPLACE != 0 {
        // set the expected fd
        let attr = nlattr {
            nla_type: IFLA_XDP_EXPECTED_FD as u16,
            // header len + fd
            nla_len: (nla_hdr_len + mem::size_of::<RawFd>()) as u16,
        };
        // write the header
        ptr::write(offset as *mut nlattr, attr);
        offset += nla_hdr_len;
        // write the old fd
        ptr::write(offset as *mut RawFd, old_fd.unwrap());
        // offset += 4;
        nla_len += attr.nla_len;
    }

    // now write the root header
    let attr = nlattr {
        nla_type: NLA_F_NESTED as u16 | IFLA_XDP as u16,
        nla_len,
    };
    offset = attrs_addr;
    ptr::write(offset as *mut nlattr, attr);

    req.header.nlmsg_len += align_to(nla_len as usize, NLA_ALIGNTO as usize) as u32;

    if send(
        sock.sock,
        &req as *const _ as *const _,
        req.header.nlmsg_len as usize,
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error())?;
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

struct NetlinkSocket {
    sock: RawFd,
    _nl_pid: u32,
}

impl NetlinkSocket {
    fn open() -> Result<NetlinkSocket, io::Error> {
        // Safety: libc wrapper
        let sock = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if sock < 0 {
            return Err(io::Error::last_os_error())?;
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
            return Err(io::Error::last_os_error())?;
        }

        Ok(NetlinkSocket {
            sock,
            _nl_pid: addr.nl_pid,
        })
    }

    fn recv(&self) -> Result<(), io::Error> {
        let mut buf = [0u8; 4096];

        let mut multipart = true;
        while multipart {
            multipart = false;
            // Safety: libc wrapper
            let len = unsafe { recv(self.sock, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if len < 0 {
                return Err(io::Error::last_os_error())?;
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
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

struct NetlinkMessage {
    header: nlmsghdr,
    _data: Vec<u8>,
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
            _data: data,
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

fn align_to(v: usize, align: usize) -> usize {
    (v + (align - 1)) & !(align - 1)
}
