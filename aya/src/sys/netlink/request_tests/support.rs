// These adapters supply only the signatures needed by compile-fail tests.
// The socket-pair test exercises real serialization and writev.
use aya::Pod;
use libc::{NLA_F_NESTED, nlmsghdr};
use request::{AttrValue, attr_header, padding, send_netlink};
use util::bytes_of;

#[cfg(any(doctest, rust_analyzer))]
use crate as aya;

#[path = "../request.rs"]
mod request;

mod util {
    pub(super) fn bytes_of<T: super::Pod>(_value: &T) -> &[u8] {
        unreachable!()
    }
}

struct Socket;
impl Socket {
    fn send<const N: usize>(&self, _bufs: [&[u8]; N]) {
        unreachable!()
    }
}
