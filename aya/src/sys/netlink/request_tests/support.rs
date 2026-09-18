// These adapters supply only the signatures needed by compile-fail tests.
// The socket-pair test exercises real serialization and writev.
use aya::Pod;

#[cfg(any(doctest, rust_analyzer))]
use crate as aya;

#[path = "../request.rs"]
mod request;

mod util {
    pub(super) const fn bytes_of<T: super::Pod>(_value: &T) -> &[u8] {
        unreachable!()
    }
}

type NetlinkErrorInternal = std::io::Error;

struct NetlinkSocket;
impl NetlinkSocket {
    fn send<const N: usize>(&self, _bufs: [[&[u8]; 3]; N]) -> Result<(), NetlinkErrorInternal> {
        unreachable!()
    }
}
