#![no_std]

#[repr(C)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
