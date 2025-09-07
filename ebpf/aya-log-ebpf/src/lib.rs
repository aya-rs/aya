#![no_std]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]

pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

#[doc(hidden)]
pub mod macro_support {
    #[cfg(target_arch = "bpf")]
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::{PerCpuArray, RingBuf};
    use aya_log_common::LogValueLength;
    pub use aya_log_common::{
        DefaultFormatter, DisplayHint, IpFormatter, Level, LowerHexFormatter, LowerMacFormatter,
        UpperHexFormatter, UpperMacFormatter, WriteToBuf, write_record_header,
    };

    const LOG_BUF_CAPACITY: LogValueLength = 8192;

    #[repr(C)]
    pub struct LogBuf {
        pub buf: [u8; LOG_BUF_CAPACITY as usize],
    }

    // This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
    // meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
    // because the integration-test crate depends on this crate transitively. See comment in
    // test/integration-test/Cargo.toml.
    #[cfg_attr(target_arch = "bpf", map)]
    pub static AYA_LOG_BUF: PerCpuArray<LogBuf> = PerCpuArray::with_max_entries(1, 0);

    // This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
    // meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
    // because the integration-test crate depends on this crate transitively. See comment in
    // test/integration-test/Cargo.toml.
    #[cfg_attr(target_arch = "bpf", map)]
    pub static AYA_LOGS: RingBuf = RingBuf::with_byte_size((LOG_BUF_CAPACITY as u32) << 4, 0);

    /// Global log level controlling which log statements are active.
    ///
    /// Userspace may patch this symbol before load via `EbpfLoader::set_global`.
    #[unsafe(no_mangle)]
    pub static AYA_LOG_LEVEL: u8 = 0xff;

    /// Returns `true` if the provided level is enabled according to [`AYA_LOG_LEVEL`].
    #[inline(always)]
    pub fn level_enabled(level: Level) -> bool {
        let current_level = unsafe { core::ptr::read_volatile(&AYA_LOG_LEVEL) };
        level as u8 <= current_level
    }
}
