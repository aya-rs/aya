use core::mem;

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKMAP, bpf_sock_ops},
    helpers::{bpf_msg_redirect_map, bpf_sock_map_update},
    maps::PinningType,
    programs::SkMsgContext,
    BpfContext,
};

#[repr(transparent)]
pub struct SockMap {
    def: bpf_map_def,
}

impl SockMap {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> SockMap {
        SockMap {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> SockMap {
        SockMap {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
        }
    }

    pub unsafe fn update(
        &mut self,
        mut index: u32,
        sk_ops: *mut bpf_sock_ops,
        flags: u64,
    ) -> Result<(), i64> {
        let ret = bpf_sock_map_update(
            sk_ops,
            &mut self.def as *mut _ as *mut _,
            &mut index as *mut _ as *mut c_void,
            flags,
        );
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    pub unsafe fn redirect(&mut self, ctx: &SkMsgContext, index: u32, flags: u64) -> i64 {
        bpf_msg_redirect_map(
            ctx.as_ptr() as *mut _,
            &mut self.def as *mut _ as *mut _,
            index,
            flags,
        )
    }
}
