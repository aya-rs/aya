#![no_std]

pub const XDP_DISPATCHER_VERSION: u8 = 2;
pub const XDP_DISPATCHER_MAGIC: u8 = 236;
pub const XDP_DISPATCHER_RETVAL: u32 = 31;
pub const MAX_DISPATCHER_ACTIONS: usize = 10;

#[cfg_attr(not(target_arch = "bpf"), derive(bytemuck::Pod, bytemuck::Zeroable))]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct XdpDispatcherConfig {
    pub magic: u8,
    pub dispatcher_version: u8,
    pub num_progs_enabled: u8,
    pub is_xdp_frags: u8,
    pub chain_call_actions: [u32; MAX_DISPATCHER_ACTIONS],
    pub run_prios: [u32; MAX_DISPATCHER_ACTIONS],
    pub program_flags: [u32; MAX_DISPATCHER_ACTIONS],
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for XdpDispatcherConfig {}
