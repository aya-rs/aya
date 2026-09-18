//! The message bodies, attribute values and nesting supported by our requests.
//!
//! Keep tag constructors private so callers cannot pair arbitrary wire IDs and
//! Rust types. Required attributes and value-dependent rules belong to the
//! operation-specific helpers in the parent module.

use std::{ffi::CStr, marker::PhantomData};

use aya_obj::generated::{self, ifinfomsg, tcmsg};
use libc::{NLA_ALIGNTO, nlattr};

use crate::{Pod, util::bytes_of};

pub(super) enum Link {}
pub(super) enum Xdp {}
pub(super) enum Tc {}
pub(super) enum Bpf {}

pub(super) struct MessageKind<Body, Family>(u16, PhantomData<(Body, Family)>);

impl<Body, Family> MessageKind<Body, Family> {
    pub(super) const fn with_body(self, body: &Body) -> (u16, PhantomData<Family>, &Body) {
        let Self(kind, _marker) = self;
        (kind, PhantomData, body)
    }
}

pub(super) struct AttrKind<Family, V: ?Sized>(u16, PhantomData<(Family, V)>);

impl<Family, V: ?Sized> AttrKind<Family, V> {
    pub(super) const fn with_value(
        self,
        _family: PhantomData<Family>,
        value: Option<&V>,
    ) -> (u16, Option<&V>) {
        let Self(kind, _marker) = self;
        (kind, value)
    }
}

pub(super) struct NestedKind<Parent, Child>(u16, PhantomData<(Parent, Child)>);

impl<Parent, Child> NestedKind<Parent, Child> {
    pub(super) const fn enter(self, _parent: PhantomData<Parent>) -> (u16, PhantomData<Child>) {
        let Self(kind, _marker) = self;
        (kind, PhantomData)
    }
}

pub(super) const RTM_SETLINK: MessageKind<ifinfomsg, Link> =
    MessageKind(libc::RTM_SETLINK, PhantomData);
pub(super) const RTM_NEWQDISC: MessageKind<tcmsg, Tc> =
    MessageKind(libc::RTM_NEWQDISC, PhantomData);
pub(super) const RTM_NEWTFILTER: MessageKind<tcmsg, Tc> =
    MessageKind(libc::RTM_NEWTFILTER, PhantomData);
pub(super) const RTM_DELTFILTER: MessageKind<tcmsg, Tc> =
    MessageKind(libc::RTM_DELTFILTER, PhantomData);
pub(super) const RTM_GETTFILTER: MessageKind<tcmsg, Tc> =
    MessageKind(libc::RTM_GETTFILTER, PhantomData);

// Payload types follow the kernel's attribute policies:
// https://github.com/torvalds/linux/blob/v6.18/net/core/rtnetlink.c#L2298-L2305
pub(super) const IFLA_XDP: NestedKind<Link, Xdp> = NestedKind(libc::IFLA_XDP, PhantomData);
pub(super) const IFLA_XDP_FD: AttrKind<Xdp, i32> =
    AttrKind(generated::IFLA_XDP_FD as u16, PhantomData);
pub(super) const IFLA_XDP_EXPECTED_FD: AttrKind<Xdp, i32> =
    AttrKind(generated::IFLA_XDP_EXPECTED_FD as u16, PhantomData);
pub(super) const IFLA_XDP_FLAGS: AttrKind<Xdp, u32> =
    AttrKind(generated::IFLA_XDP_FLAGS as u16, PhantomData);

pub(super) const TCA_KIND: AttrKind<Tc, CStr> = AttrKind(generated::TCA_KIND as u16, PhantomData);
pub(super) const TCA_OPTIONS: NestedKind<Tc, Bpf> =
    NestedKind(generated::TCA_OPTIONS as u16, PhantomData);
// https://github.com/torvalds/linux/blob/v6.18/net/sched/cls_bpf.c#L54-L64
pub(super) const TCA_BPF_CLASSID: AttrKind<Bpf, u32> =
    AttrKind(generated::TCA_BPF_CLASSID as u16, PhantomData);
pub(super) const TCA_BPF_FD: AttrKind<Bpf, u32> =
    AttrKind(generated::TCA_BPF_FD as u16, PhantomData);
pub(super) const TCA_BPF_NAME: AttrKind<Bpf, CStr> =
    AttrKind(generated::TCA_BPF_NAME as u16, PhantomData);
pub(super) const TCA_BPF_FLAGS: AttrKind<Bpf, u32> =
    AttrKind(generated::TCA_BPF_FLAGS as u16, PhantomData);

pub(super) trait AttrValue {
    fn as_bytes(&self) -> &[u8];
}

impl<T: Pod> AttrValue for T {
    fn as_bytes(&self) -> &[u8] {
        bytes_of(self)
    }
}

impl AttrValue for CStr {
    fn as_bytes(&self) -> &[u8] {
        self.to_bytes_with_nul()
    }
}

// Collect borrowed slices into a fixed-size array for writev. `match` keeps
// temporaries inside payload expressions alive until the send completes.
//
// @parts carries the attribute family, [collected slices], [remaining input],
// and [what to do when done]. Nested attributes collect children in their own
// family, then resume their parent.
macro_rules! send_netlink {
    ($sock:expr, $kind:expr, $flags:expr, $body:expr, [$($parts:tt)*]) => {
        match (&$sock, $kind, $flags, &$body) {
            (sock, kind, flags, body) => {
                let (kind, _family, body) = kind.with_body(body);
                let body = bytes_of(body);
                let flags = flags as u16;
                send_netlink!(@parts _family [body, padding(body.len()),] [$($parts)*] [send(sock, kind, flags)])
            }
        }
    };
    (@parts $family:ident [$($buf:expr,)*] [] [send($sock:ident, $kind:ident, $flags:ident)]) => {{
        let bufs: [&[u8]; _] = [$($buf,)*];
        let header = nlmsghdr {
            nlmsg_len: (size_of::<nlmsghdr>() + bufs.iter().map(|buf| buf.len()).sum::<usize>()) as u32,
            nlmsg_type: $kind,
            nlmsg_flags: $flags,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        $sock.send([bytes_of(&header), $($buf,)*])
    }};
    (@parts $family:ident [$($buf:expr,)*] [] [nested($kind:ident, $parent_family:ident) [$($parent:expr,)*] [$($rest:tt)*] $resume:tt]) => {{
        let bufs: [&[u8]; _] = [$($buf,)*];
        // The enclosing attribute's payload includes its children's padding.
        let header = attr_header($kind | NLA_F_NESTED as u16, bufs.iter().map(|buf| buf.len()).sum());
        send_netlink!(@parts $parent_family [$($parent,)* bytes_of(&header), $($buf,)*] [$($rest)*] $resume)
    }};
    (@parts $family:ident $bufs:tt [nested_attr($kind:expr, [$($children:tt)*]), $($rest:tt)*] $resume:tt) => {{
        let (kind, _family) = $kind.enter($family);
        send_netlink!(@parts _family [] [$($children)*] [nested(kind, $family) $bufs [$($rest)*] $resume])
    }};
    (@parts $family:ident [$($buf:expr,)*] [attr($kind:expr, $value:expr), $($rest:tt)*] $resume:tt) => {
        match ($kind, $value) {
            (kind, value) => {
                // Accept &V or Option<&V>, where the tag determines V.
                let (kind, value) = kind.with_value($family, value.into());
                let bytes = value.map(AttrValue::as_bytes);
                let header = bytes.map(|bytes| attr_header(kind, bytes.len()));
                // None contributes empty slices, preserving the array's length.
                send_netlink!(@parts $family [
                    $($buf,)*
                    header.as_ref().map_or(&[], bytes_of),
                    bytes.unwrap_or_default(),
                    padding(bytes.map_or(0, <[u8]>::len)),
                ] [$($rest)*] $resume)
            }
        }
    };
}

pub(super) use send_netlink;

pub(super) const fn attr_header(kind: u16, payload_len: usize) -> nlattr {
    nlattr {
        nla_type: kind,
        // nla_len excludes padding after this attribute's payload.
        nla_len: (size_of::<nlattr>() + payload_len) as u16,
    }
}

pub(super) fn padding(len: usize) -> &'static [u8] {
    const ZEROES: [u8; NLA_ALIGNTO as usize - 1] = [0; _];
    &ZEROES[..len.next_multiple_of(NLA_ALIGNTO as usize) - len]
}
