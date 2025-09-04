#![no_std]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]

pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

#[doc(hidden)]
pub mod macro_support {
    #[cfg(target_arch = "bpf")]
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::{PerCpuArray, RingBuf};
    use aya_log_common::LogValueLength;
    #[cfg(target_arch = "bpf")]
    use core::ptr::read_volatile;
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

    /// Global log level mask controlling which log statements are active.
    /// Bits correspond to variants of `Level` (1-based discriminant) shifted into a mask.
    /// By default all bits set (enable all levels). Userspace may patch this symbol before load
    /// via `EbpfLoader::set_log_level_mask` (to be implemented) using global data patching.
    /// When a bit is unset, verifier will see the guarded block as unreachable and prune it.
    #[no_mangle]
    pub static mut AYA_LOG_LEVEL_MASK: u32 = 0xFFFF_FFFF;

    /// Returns `true` if the provided level is enabled according to `AYA_LOG_LEVEL_MASK`.
    #[inline(always)]
    pub fn level_enabled(lvl: Level) -> bool {
        // SAFETY: Mask lives in .rodata for BPF (declared mutable for patching), we only read it.
        let mask = unsafe { read_volatile(&AYA_LOG_LEVEL_MASK) };
        let bit: u32 = 1u32 << (lvl as u32 - 1);
        (mask & bit) != 0
    }
}
