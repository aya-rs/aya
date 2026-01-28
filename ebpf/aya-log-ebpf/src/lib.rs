#![cfg_attr(
    target_arch = "bpf",
    expect(unused_crate_dependencies, reason = "compiler_builtins")
)]
#![no_std]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]

pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

#[doc(hidden)]
pub mod macro_support {
    #[cfg(target_arch = "bpf")]
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::RingBuf;
    pub use aya_log_common::{
        Argument, DefaultFormatter, DisplayHint, Field, Header, IpFormatter, Level, LogValueLength,
        LowerHexFormatter, LowerMacFormatter, PointerFormatter, UpperHexFormatter,
        UpperMacFormatter,
    };

    // This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
    // meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
    // because the integration-test crate depends on this crate transitively. See comment in
    // test/integration-test/Cargo.toml.
    #[cfg_attr(target_arch = "bpf", map)]
    // This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
    // meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
    // because the integration-test crate depends on this crate transitively. See comment in
    // test/integration-test/Cargo.toml.
    #[cfg_attr(target_arch = "bpf", map)]
    pub static AYA_LOGS: RingBuf = RingBuf::with_byte_size(1 << 17 /* 128 KiB */, 0);

    /// Global log level controlling which log statements are active.
    ///
    /// Userspace may patch this symbol before load via `EbpfLoader::override_global`.
    #[unsafe(no_mangle)]
    pub static AYA_LOG_LEVEL: u8 = 0xff;

    /// Returns `true` if the provided level is enabled according to [`AYA_LOG_LEVEL`].
    #[inline(always)]
    pub fn level_enabled(level: Level) -> bool {
        let current_level = unsafe { core::ptr::read_volatile(&raw const AYA_LOG_LEVEL) };
        level as u8 <= current_level
    }
}
