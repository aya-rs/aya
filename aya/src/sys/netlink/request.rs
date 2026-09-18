//! Typed requests for the netlink operations used by Aya.
//!
//! Constructors select the family header and attribute layout together. Requests
//! own integer payloads and borrow strings; all headers and payloads stay alive
//! until writev returns.

use std::ffi::CStr;

use aya_obj::generated::{self, ifinfomsg, tcmsg};
use libc::{NLA_ALIGNTO, NLA_F_NESTED, nlattr, nlmsghdr};

use super::{NetlinkErrorInternal, NetlinkSocket};
use crate::{Pod, util::bytes_of};

pub(super) struct Link<X> {
    family_header: ifinfomsg,
    xdp: X,
}

impl Link<()> {
    pub(super) const fn new(family_header: ifinfomsg) -> Self {
        Self {
            family_header,
            xdp: (),
        }
    }

    pub(super) const fn xdp<E>(self, xdp: Xdp<E>) -> Link<Xdp<E>> {
        let Self {
            family_header,
            xdp: (),
        } = self;
        Link { family_header, xdp }
    }

    #[cfg(feature = "test-helpers")]
    pub(super) fn send(
        &self,
        sock: &NetlinkSocket,
        flags: u16,
    ) -> Result<(), NetlinkErrorInternal> {
        let Self {
            family_header,
            xdp: (),
        } = self;
        send_without_attrs(sock, libc::RTM_SETLINK, flags, family_header)
    }
}

impl<E: Optional<i32>> Link<Xdp<E>> {
    pub(super) fn send(
        &self,
        sock: &NetlinkSocket,
        flags: u16,
    ) -> Result<(), NetlinkErrorInternal> {
        let Self { family_header, xdp } = self;
        xdp.send(sock, flags, family_header)
    }
}

// Payload types follow the kernel's attribute policies:
// https://github.com/torvalds/linux/blob/v6.18/net/core/rtnetlink.c#L2298-L2305
pub(super) struct Xdp<E> {
    fd: i32,
    flags: u32,
    expected_fd: E,
}

impl Xdp<()> {
    pub(super) const fn new(fd: i32, flags: u32) -> Self {
        Self {
            fd,
            flags,
            expected_fd: (),
        }
    }

    pub(super) const fn expected_fd(self, expected_fd: Option<i32>) -> Xdp<Option<i32>> {
        let Self {
            fd,
            flags,
            expected_fd: (),
        } = self;
        Xdp {
            fd,
            flags,
            expected_fd,
        }
    }
}

impl<E: Optional<i32>> Xdp<E> {
    fn send(
        &self,
        sock: &NetlinkSocket,
        flags: u16,
        family_header: &ifinfomsg,
    ) -> Result<(), NetlinkErrorInternal> {
        let Self {
            fd,
            flags: xdp_flags,
            expected_fd,
        } = self;
        let attrs = [
            attr(generated::IFLA_XDP_FD as u16, Some(bytes_of(fd))),
            attr(generated::IFLA_XDP_FLAGS as u16, Some(bytes_of(xdp_flags))),
            attr(
                generated::IFLA_XDP_EXPECTED_FD as u16,
                expected_fd.as_ref().map(bytes_of),
            ),
        ];
        let children = attrs.each_ref().map(attr_bufs);
        let nested = attr_header(libc::IFLA_XDP | NLA_F_NESTED as u16, bufs_len(&children));
        let [fd, xdp_flags, expected_fd] = children;
        let attrs = [[bytes_of(&nested), &[], &[]], fd, xdp_flags, expected_fd];
        let (header, family_header) = message(libc::RTM_SETLINK, flags, family_header, &attrs);
        let [nested, fd, xdp_flags, expected_fd] = attrs;
        sock.send([
            [
                bytes_of(&header),
                family_header,
                padding(family_header.len()),
            ],
            nested,
            fd,
            xdp_flags,
            expected_fd,
        ])
    }
}

pub(super) struct Tc<'a, C> {
    family_header: tcmsg,
    operation: TcOperation<'a, C>,
}

enum TcOperation<'a, C> {
    DeleteFilter,
    GetFilter,
    Clsact,
    Bpf(Bpf<'a, C>),
}

impl<'a> Tc<'a, ()> {
    pub(super) const fn add_clsact(family_header: tcmsg) -> Self {
        Self {
            family_header,
            operation: TcOperation::Clsact,
        }
    }

    pub(super) const fn new_filter<C>(family_header: tcmsg, bpf: Bpf<'a, C>) -> Tc<'a, C> {
        Tc {
            family_header,
            operation: TcOperation::Bpf(bpf),
        }
    }

    pub(super) const fn delete_filter(family_header: tcmsg) -> Self {
        Self {
            family_header,
            operation: TcOperation::DeleteFilter,
        }
    }

    pub(super) const fn get_filter(family_header: tcmsg) -> Self {
        Self {
            family_header,
            operation: TcOperation::GetFilter,
        }
    }
}

impl<C: Optional<u32>> Tc<'_, C> {
    pub(super) fn send(
        &self,
        sock: &NetlinkSocket,
        flags: u16,
    ) -> Result<(), NetlinkErrorInternal> {
        let Self {
            family_header,
            operation,
        } = self;
        match operation {
            TcOperation::DeleteFilter => {
                send_without_attrs(sock, libc::RTM_DELTFILTER, flags, family_header)
            }
            TcOperation::GetFilter => {
                send_without_attrs(sock, libc::RTM_GETTFILTER, flags, family_header)
            }
            TcOperation::Clsact => {
                let attr = attr(
                    generated::TCA_KIND as u16,
                    Some(c"clsact".to_bytes_with_nul()),
                );
                let attrs = [attr_bufs(&attr)];
                let (header, family_header) =
                    message(libc::RTM_NEWQDISC, flags, family_header, &attrs);
                let [kind] = attrs;
                sock.send([
                    [
                        bytes_of(&header),
                        family_header,
                        padding(family_header.len()),
                    ],
                    kind,
                ])
            }
            TcOperation::Bpf(bpf) => bpf.send(sock, flags, family_header),
        }
    }
}

// https://github.com/torvalds/linux/blob/v6.18/net/sched/cls_bpf.c#L54-L64
pub(super) struct Bpf<'a, C> {
    fd: u32,
    name: &'a CStr,
    flags: u32,
    classid: C,
}

impl<'a> Bpf<'a, ()> {
    pub(super) const fn new(fd: u32, name: &'a CStr, flags: u32) -> Self {
        Self {
            fd,
            name,
            flags,
            classid: (),
        }
    }

    pub(super) const fn classid(self, classid: Option<u32>) -> Bpf<'a, Option<u32>> {
        let Self {
            fd,
            name,
            flags,
            classid: (),
        } = self;
        Bpf {
            fd,
            name,
            flags,
            classid,
        }
    }
}

impl<C: Optional<u32>> Bpf<'_, C> {
    fn send(
        &self,
        sock: &NetlinkSocket,
        flags: u16,
        family_header: &tcmsg,
    ) -> Result<(), NetlinkErrorInternal> {
        let Self {
            fd,
            name,
            flags: bpf_flags,
            classid,
        } = self;
        let attrs = [
            attr(
                generated::TCA_BPF_CLASSID as u16,
                classid.as_ref().map(bytes_of),
            ),
            attr(generated::TCA_BPF_FD as u16, Some(bytes_of(fd))),
            attr(
                generated::TCA_BPF_NAME as u16,
                Some(name.to_bytes_with_nul()),
            ),
            attr(generated::TCA_BPF_FLAGS as u16, Some(bytes_of(bpf_flags))),
        ];
        let children = attrs.each_ref().map(attr_bufs);
        let nested = attr_header(
            generated::TCA_OPTIONS as u16 | NLA_F_NESTED as u16,
            bufs_len(&children),
        );
        let kind = attr(generated::TCA_KIND as u16, Some(c"bpf".to_bytes_with_nul()));
        let [classid, fd, name, bpf_flags] = children;
        let attrs = [
            attr_bufs(&kind),
            [bytes_of(&nested), &[], &[]],
            classid,
            fd,
            name,
            bpf_flags,
        ];
        let (header, family_header) = message(libc::RTM_NEWTFILTER, flags, family_header, &attrs);
        let [kind, nested, classid, fd, name, bpf_flags] = attrs;
        sock.send([
            [
                bytes_of(&header),
                family_header,
                padding(family_header.len()),
            ],
            kind,
            nested,
            classid,
            fd,
            name,
            bpf_flags,
        ])
    }
}

// An optional starts as (), and its setter changes that field to Option<T>.
// Both states can be encoded, but even setting None consumes the setter.
pub(super) trait Optional<T> {
    fn as_ref(&self) -> Option<&T>;
}

impl<T> Optional<T> for () {
    fn as_ref(&self) -> Option<&T> {
        None
    }
}

impl<T> Optional<T> for Option<T> {
    fn as_ref(&self) -> Option<&T> {
        Self::as_ref(self)
    }
}

fn send_without_attrs<B: Pod>(
    sock: &NetlinkSocket,
    kind: u16,
    flags: u16,
    family_header: &B,
) -> Result<(), NetlinkErrorInternal> {
    let (header, family_header) = message(kind, flags, family_header, &[]);
    sock.send([[
        bytes_of(&header),
        family_header,
        padding(family_header.len()),
    ]])
}

fn message<'a, B: Pod>(
    kind: u16,
    flags: u16,
    family_header: &'a B,
    attrs: &[[&[u8]; 3]],
) -> (nlmsghdr, &'a [u8]) {
    let family_header = bytes_of(family_header);
    let header = nlmsghdr {
        nlmsg_len: (size_of::<nlmsghdr>()
            + family_header.len().next_multiple_of(NLA_ALIGNTO as usize)
            + bufs_len(attrs)) as u32,
        nlmsg_type: kind,
        nlmsg_flags: flags,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    (header, family_header)
}

fn bufs_len(bufs: &[[&[u8]; 3]]) -> usize {
    bufs.iter().flatten().map(|buf| buf.len()).sum()
}

const fn attr(kind: u16, bytes: Option<&[u8]>) -> (Option<nlattr>, &[u8]) {
    match bytes {
        Some(bytes) => (Some(attr_header(kind, bytes.len())), bytes),
        None => (None, &[]),
    }
}

fn attr_bufs<'a>((header, bytes): &'a (Option<nlattr>, &[u8])) -> [&'a [u8]; 3] {
    [
        header.as_ref().map_or(&[], bytes_of),
        bytes,
        padding(bytes.len()),
    ]
}

const fn attr_header(kind: u16, payload_len: usize) -> nlattr {
    nlattr {
        nla_type: kind,
        // nla_len excludes padding after this attribute's payload.
        nla_len: (size_of::<nlattr>() + payload_len) as u16,
    }
}

fn padding(len: usize) -> &'static [u8] {
    const ZEROES: [u8; NLA_ALIGNTO as usize - 1] = [0; _];
    &ZEROES[..len.next_multiple_of(NLA_ALIGNTO as usize) - len]
}
