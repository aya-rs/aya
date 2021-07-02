use core::mem;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_STACK_TRACE},
    helpers::{bpf_get_stackid},
    BpfContext,
};

#[repr(transparent)]
pub struct StackTrace {
	def: bpf_map_def,
}

const PERF_MAX_STACK_DEPTH: u32 = 127;

impl StackTrace {
	pub const fn with_max_entries(max_entries: u32, flags: u32) -> StackTrace {
		StackTrace {
			def: bpf_map_def {
				type_: BPF_MAP_TYPE_STACK_TRACE,
				key_size: mem::size_of::<u32>() as u32,
				value_size: mem::size_of::<u64>() as u32 * PERF_MAX_STACK_DEPTH,
				max_entries,
				map_flags: flags,
				id: 0,
				pinning: 0,
			},
		}
	}

	pub unsafe fn get_stackid<C: BpfContext>(&mut self, ctx: &C, flags: u64) -> Result<i64, i64> {
		let ret = bpf_get_stackid(
			ctx.as_ptr(),
			&mut self.def as *mut _ as *mut _,
			flags,
		);
		if ret < 0 {
			Err(ret)
		} else {
			Ok(ret)
		}
	}
}