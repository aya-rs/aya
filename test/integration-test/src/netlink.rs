//! Minimal netlink helpers for integration-test network setup.
//!
//! These live here (rather than in the `aya` crate) to avoid adding test-only
//! public API surface to the production library.

use std::{
    collections::HashMap,
    ffi::CStr,
    io, mem,
    net::Ipv4Addr,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
    ptr, slice,
};

use libc::{
    AF_INET, AF_NETLINK, AF_UNSPEC, IFA_ADDRESS, IFA_LOCAL, IFF_UP, IFLA_ADDRESS, IFLA_IFNAME,
    IFLA_INFO_DATA, IFLA_INFO_KIND, IFLA_LINKINFO, IFLA_NET_NS_FD, NDA_DST, NDA_LLADDR,
    NETLINK_ROUTE, NLA_ALIGNTO, NLA_F_NESTED, NLA_TYPE_MASK, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NTF_SELF, NUD_PERMANENT, RTM_GETLINK, RTM_NEWADDR,
    RTM_NEWLINK, RTM_NEWNEIGH, RTM_SETLINK, SOCK_RAW, SOL_NETLINK, nlattr, nlmsgerr, nlmsghdr,
};

/// `NLMSG_ALIGNTO` from the kernel; value is always 4.
const NLMSG_ALIGNTO: usize = 4;
const NLA_HDR_LEN: usize = align_to(size_of::<nlattr>(), NLA_ALIGNTO as usize);
/// `VETH_INFO_PEER` from `linux/veth.h`; not exported by libc.
const VETH_INFO_PEER: u16 = 1;

/// `struct ifinfomsg` from `linux/if_link.h`.
#[derive(Copy, Clone)]
#[repr(C)]
struct Ifinfomsg {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// `struct ifaddrmsg` from `linux/if_addr.h`.
#[derive(Copy, Clone)]
#[repr(C)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// `struct ndmsg` from `linux/neighbour.h`.
#[derive(Copy, Clone)]
#[repr(C)]
struct Ndmsg {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct LinkRequest {
    header: nlmsghdr,
    if_info: Ifinfomsg,
    attrs: [u8; 64],
}

#[derive(Copy, Clone)]
#[repr(C)]
struct VethRequest {
    header: nlmsghdr,
    if_info: Ifinfomsg,
    attrs: [u8; 128],
}

#[derive(Copy, Clone)]
#[repr(C)]
struct AddrRequest {
    header: nlmsghdr,
    addr_info: Ifaddrmsg,
    attrs: [u8; 24],
}

#[derive(Copy, Clone)]
#[repr(C)]
struct NeighRequest {
    header: nlmsghdr,
    neigh_info: Ndmsg,
    attrs: [u8; 24],
}

const fn align_to(v: usize, align: usize) -> usize {
    v.next_multiple_of(align)
}

/// Reinterpret a `#[repr(C)]` struct as a byte slice.
///
/// # Safety
///
/// `T` must be `#[repr(C)]` with no padding that could leak uninitialised bytes
/// into the returned slice.  All request structs in this module satisfy this
/// because they are either fully initialised or their padding bytes are
/// explicitly zeroed via `mem::zeroed()`.
unsafe fn bytes_of<T>(val: &T) -> &[u8] {
    unsafe { slice::from_raw_parts(ptr::from_ref(val).cast(), size_of::<T>()) }
}

/// Return a mutable slice over the attribute area of a request struct.
///
/// # Safety
///
/// `msg_len` must be the offset of the attribute area within `T`.
unsafe fn request_attributes<T>(req: &mut T, msg_len: usize) -> &mut [u8] {
    let req: *mut u8 = ptr::from_mut(req).cast();
    let attrs_addr = unsafe { req.add(msg_len) };
    let align_offset = attrs_addr.align_offset(NLMSG_ALIGNTO);
    let attrs_addr = unsafe { attrs_addr.add(align_offset) };
    let len = size_of::<T>() - msg_len - align_offset;
    unsafe { slice::from_raw_parts_mut(attrs_addr, len) }
}

fn write_attr_bytes(
    buf: &mut [u8],
    offset: usize,
    attr_type: u16,
    value: &[u8],
) -> Result<usize, io::Error> {
    let attr = nlattr {
        nla_type: attr_type,
        nla_len: (NLA_HDR_LEN + value.len()) as u16,
    };
    write_attr_header(buf, offset, attr)?;
    let value_len = write_bytes(buf, offset + NLA_HDR_LEN, value)?;
    Ok(NLA_HDR_LEN + value_len)
}

fn write_attr_header(buf: &mut [u8], offset: usize, attr: nlattr) -> Result<usize, io::Error> {
    let attr = unsafe { bytes_of(&attr) };
    write_bytes(buf, offset, attr)?;
    Ok(NLA_HDR_LEN)
}

fn write_bytes(buf: &mut [u8], offset: usize, value: &[u8]) -> Result<usize, io::Error> {
    let align_len = align_to(value.len(), NLA_ALIGNTO as usize);
    if offset + align_len > buf.len() {
        return Err(io::Error::other(
            "no space left in netlink attribute buffer",
        ));
    }
    buf[offset..offset + value.len()].copy_from_slice(value);
    Ok(align_len)
}

struct NetlinkSocket {
    sock: OwnedFd,
}

impl NetlinkSocket {
    fn open() -> io::Result<Self> {
        let sock = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };

        let enable = 1_i32;
        unsafe {
            if libc::setsockopt(
                sock.as_raw_fd(),
                SOL_NETLINK,
                libc::NETLINK_EXT_ACK,
                ptr::from_ref(&enable).cast(),
                size_of_val(&enable) as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::setsockopt(
                sock.as_raw_fd(),
                SOL_NETLINK,
                libc::NETLINK_CAP_ACK,
                ptr::from_ref(&enable).cast(),
                size_of_val(&enable) as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self { sock })
    }

    /// Send a request and collect the response messages.
    fn execute(&self, msg: &[u8]) -> io::Result<Vec<NetlinkMessage>> {
        if unsafe { libc::send(self.sock.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.recv()
    }

    fn recv(&self) -> io::Result<Vec<NetlinkMessage>> {
        let mut buf = [0u8; 4096];
        let mut messages = Vec::new();
        let mut multipart = true;
        'out: while multipart {
            multipart = false;
            let len =
                unsafe { libc::recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
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
                offset += align_to(message.header.nlmsg_len as usize, NLMSG_ALIGNTO);
                multipart = (message.header.nlmsg_flags & (libc::NLM_F_MULTI as u16)) != 0;
                match i32::from(message.header.nlmsg_type) {
                    NLMSG_ERROR => {
                        let err = message.error.unwrap();
                        if err.error == 0 {
                            // ACK
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
    fn read(buf: &[u8]) -> io::Result<Self> {
        if size_of::<nlmsghdr>() > buf.len() {
            return Err(io::Error::other("buffer smaller than nlmsghdr"));
        }
        let header: nlmsghdr = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
        let msg_len = header.nlmsg_len as usize;
        if msg_len < size_of::<nlmsghdr>() || msg_len > buf.len() {
            return Err(io::Error::other("invalid nlmsg_len"));
        }
        let data_offset = align_to(size_of::<nlmsghdr>(), NLMSG_ALIGNTO);
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

fn parse_attrs(buf: &[u8]) -> HashMap<u16, &[u8]> {
    let mut attrs = HashMap::new();
    let mut offset = 0;
    while offset < buf.len() {
        let remaining = &buf[offset..];
        if NLA_HDR_LEN > remaining.len() {
            break;
        }
        let attr: nlattr = unsafe { ptr::read_unaligned(remaining.as_ptr().cast()) };
        let len = attr.nla_len as usize;
        if len < NLA_HDR_LEN {
            break;
        }
        let align_len = align_to(len, NLA_ALIGNTO as usize);
        if align_len > remaining.len() {
            break;
        }
        attrs.insert(
            attr.nla_type & (NLA_TYPE_MASK as u16),
            &remaining[NLA_HDR_LEN..len],
        );
        offset += align_len;
    }
    attrs
}

/// Set a network interface up (IFF_UP).
pub(crate) fn set_link_up(if_index: i32) -> io::Result<()> {
    let sock = NetlinkSocket::open()?;
    let mut req = unsafe { mem::zeroed::<LinkRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<Ifinfomsg>();
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

    sock.execute(unsafe { &bytes_of(&req)[..req.header.nlmsg_len as usize] })?;
    Ok(())
}

/// Create a veth pair.
pub(crate) fn create_veth_pair(if_name: &CStr, peer_name: &CStr) -> io::Result<()> {
    let sock = NetlinkSocket::open()?;
    let mut req = unsafe { mem::zeroed::<VethRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<Ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL) as u16,
        nlmsg_type: RTM_NEWLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;

    let attrs_buf = unsafe { request_attributes(&mut req, nlmsg_len) };
    let attr_len = write_veth_attrs(attrs_buf, if_name, peer_name)?;
    req.header.nlmsg_len += align_to(attr_len, NLA_ALIGNTO as usize) as u32;

    sock.execute(unsafe { &bytes_of(&req)[..req.header.nlmsg_len as usize] })?;
    Ok(())
}

fn write_veth_attrs(buf: &mut [u8], if_name: &CStr, peer_name: &CStr) -> Result<usize, io::Error> {
    let mut offset = 0usize;

    // IFLA_IFNAME for the first interface.
    offset += write_attr_bytes(buf, offset, IFLA_IFNAME, if_name.to_bytes_with_nul())?;

    // IFLA_LINKINFO (nested): contains IFLA_INFO_KIND + IFLA_INFO_DATA.
    let linkinfo_start = offset;
    offset += NLA_HDR_LEN; // reserve; back-filled below

    // IFLA_INFO_KIND = "veth"
    offset += write_attr_bytes(buf, offset, IFLA_INFO_KIND, c"veth".to_bytes_with_nul())?;

    // IFLA_INFO_DATA (nested): contains VETH_INFO_PEER.
    let info_data_start = offset;
    offset += NLA_HDR_LEN;

    // VETH_INFO_PEER (nested): contains an Ifinfomsg + IFLA_IFNAME.
    let peer_start = offset;
    offset += NLA_HDR_LEN;

    // Embedded Ifinfomsg for the peer (all zeros from mem::zeroed).
    let ifinfo_size = align_to(size_of::<Ifinfomsg>(), NLA_ALIGNTO as usize);
    if offset + ifinfo_size > buf.len() {
        return Err(io::Error::other(
            "no space left in netlink attribute buffer",
        ));
    }
    offset += ifinfo_size;

    // IFLA_IFNAME for the peer.
    offset += write_attr_bytes(buf, offset, IFLA_IFNAME, peer_name.to_bytes_with_nul())?;

    // Back-fill headers.
    write_attr_header(
        buf,
        peer_start,
        nlattr {
            nla_type: (NLA_F_NESTED as u16) | VETH_INFO_PEER,
            nla_len: (offset - peer_start) as u16,
        },
    )?;
    write_attr_header(
        buf,
        info_data_start,
        nlattr {
            nla_type: (NLA_F_NESTED as u16) | IFLA_INFO_DATA,
            nla_len: (offset - info_data_start) as u16,
        },
    )?;
    write_attr_header(
        buf,
        linkinfo_start,
        nlattr {
            nla_type: (NLA_F_NESTED as u16) | IFLA_LINKINFO,
            nla_len: (offset - linkinfo_start) as u16,
        },
    )?;

    Ok(offset)
}

/// Move a network interface to another network namespace.
pub(crate) fn set_link_ns(if_index: i32, netns_fd: RawFd) -> io::Result<()> {
    let sock = NetlinkSocket::open()?;
    let mut req = unsafe { mem::zeroed::<LinkRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<Ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_type: RTM_SETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;

    let attrs_buf = unsafe { request_attributes(&mut req, nlmsg_len) };
    let attr_len = write_attr_bytes(attrs_buf, 0, IFLA_NET_NS_FD, unsafe { bytes_of(&netns_fd) })?;
    req.header.nlmsg_len += align_to(attr_len, NLA_ALIGNTO as usize) as u32;

    sock.execute(unsafe { &bytes_of(&req)[..req.header.nlmsg_len as usize] })?;
    Ok(())
}

/// Add an IPv4 address to a network interface.
pub(crate) fn add_addr_v4(if_index: i32, addr: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    let sock = NetlinkSocket::open()?;
    let mut req = unsafe { mem::zeroed::<AddrRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<Ifaddrmsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL) as u16,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.addr_info = Ifaddrmsg {
        ifa_family: AF_INET as u8,
        ifa_prefixlen: prefix_len,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: if_index as u32,
    };

    let attrs_buf = unsafe { request_attributes(&mut req, nlmsg_len) };
    let addr_bytes = addr.octets();
    let mut offset = 0;
    offset += write_attr_bytes(attrs_buf, offset, IFA_LOCAL, &addr_bytes)?;
    offset += write_attr_bytes(attrs_buf, offset, IFA_ADDRESS, &addr_bytes)?;
    req.header.nlmsg_len += align_to(offset, NLA_ALIGNTO as usize) as u32;

    sock.execute(unsafe { &bytes_of(&req)[..req.header.nlmsg_len as usize] })?;
    Ok(())
}

/// Read the MAC address (IFLA_ADDRESS) of a network interface.
pub(crate) fn get_link_mac(if_index: i32) -> io::Result<[u8; 6]> {
    let sock = NetlinkSocket::open()?;
    let mut req = unsafe { mem::zeroed::<LinkRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<Ifinfomsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: NLM_F_REQUEST as u16,
        nlmsg_type: RTM_GETLINK,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.if_info.ifi_family = AF_UNSPEC as u8;
    req.if_info.ifi_index = if_index;

    for msg in sock.execute(unsafe { &bytes_of(&req)[..req.header.nlmsg_len as usize] })? {
        if msg.header.nlmsg_type != RTM_NEWLINK {
            continue;
        }
        let attrs = parse_attrs(&msg.data[size_of::<Ifinfomsg>()..]);
        if let Some(data) = attrs.get(&IFLA_ADDRESS) {
            if let Ok(mac) = <[u8; 6]>::try_from(*data) {
                return Ok(mac);
            }
        }
    }

    Err(io::Error::other(
        "IFLA_ADDRESS not found in RTM_GETLINK response",
    ))
}

/// Add a static neighbor (ARP) entry.
pub(crate) fn add_neigh_v4(if_index: i32, dst_addr: Ipv4Addr, lladdr: &[u8; 6]) -> io::Result<()> {
    let sock = NetlinkSocket::open()?;
    let mut req = unsafe { mem::zeroed::<NeighRequest>() };

    let nlmsg_len = size_of::<nlmsghdr>() + size_of::<Ndmsg>();
    req.header = nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL) as u16,
        nlmsg_type: RTM_NEWNEIGH,
        nlmsg_pid: 0,
        nlmsg_seq: 1,
    };
    req.neigh_info = Ndmsg {
        ndm_family: AF_INET as u8,
        ndm_pad1: 0,
        ndm_pad2: 0,
        ndm_ifindex: if_index,
        ndm_state: NUD_PERMANENT,
        ndm_flags: NTF_SELF,
        ndm_type: 0,
    };

    let attrs_buf = unsafe { request_attributes(&mut req, nlmsg_len) };
    let mut offset = 0;
    offset += write_attr_bytes(attrs_buf, offset, NDA_DST, &dst_addr.octets())?;
    offset += write_attr_bytes(attrs_buf, offset, NDA_LLADDR, lladdr)?;
    req.header.nlmsg_len += align_to(offset, NLA_ALIGNTO as usize) as u32;

    sock.execute(unsafe { &bytes_of(&req)[..req.header.nlmsg_len as usize] })?;
    Ok(())
}
