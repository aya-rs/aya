#[derive(Copy, Clone)]
#[repr(C)]
pub struct XdpData {
    pub packet_count : u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for XdpData {}