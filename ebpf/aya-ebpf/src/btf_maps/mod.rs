use core::marker::PhantomData;

pub mod array;
pub mod ring_buf;
pub mod sk_storage;

pub use array::Array;
pub use ring_buf::RingBuf;
pub use sk_storage::SkStorage;

/// A marker used to remove names of annotated types in LLVM debug info and
/// therefore also in BTF.
#[repr(transparent)]
pub(crate) struct AyaBtfMapMarker(PhantomData<()>);

impl AyaBtfMapMarker {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}
