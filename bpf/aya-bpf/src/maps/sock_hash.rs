use core::{marker::PhantomData, mem};

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKHASH, bpf_sock_ops},
    helpers::{bpf_msg_redirect_hash, bpf_sock_hash_update},
    maps::PinningType,
    programs::SkMsgContext,
    BpfContext,
};

#[repr(transparent)]
pub struct SockHash<K> {
    def: bpf_map_def,
    _k: PhantomData<K>,
}

impl<K> SockHash<K> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> SockHash<K> {
        SockHash {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKHASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
            _k: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> SockHash<K> {
        SockHash {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKHASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
            _k: PhantomData,
        }
    }

    pub unsafe fn update(
        &mut self,
        key: &mut K,
        sk_ops: *mut bpf_sock_ops,
        flags: u64,
    ) -> Result<(), i64> {
        let ret = bpf_sock_hash_update(
            sk_ops,
            &mut self.def as *mut _ as *mut _,
            key as *mut _ as *mut c_void,
            flags,
        );
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    pub unsafe fn redirect(&mut self, ctx: &SkMsgContext, key: &mut K, flags: u64) -> i64 {
        bpf_msg_redirect_hash(
            ctx.as_ptr() as *mut _,
            &mut self.def as *mut _ as *mut _,
            key as *mut _ as *mut _,
            flags,
        )
    }
}
