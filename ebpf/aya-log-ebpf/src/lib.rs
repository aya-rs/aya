#![no_std]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]

pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

#[doc(hidden)]
pub mod macro_support {
    #[cfg(target_arch = "bpf")]
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::RingBuf;
    pub use aya_log_common::{
        Argument, DefaultFormatter, DisplayHint, Field, Header, IpFormatter, Level,
        LowerHexFormatter, LowerMacFormatter, UpperHexFormatter, UpperMacFormatter,
    };

    // This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
    // meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
    // because the integration-test crate depends on this crate transitively. See comment in
    // test/integration-test/Cargo.toml.
    #[cfg_attr(target_arch = "bpf", map)]
    pub static AYA_LOGS: RingBuf = RingBuf::with_byte_size(1 << 17 /* 128 KiB */, 0);
}
