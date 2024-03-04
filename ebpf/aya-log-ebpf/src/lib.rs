#![no_std]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]

#[cfg(target_arch = "bpf")]
use aya_ebpf::macros::map;
use aya_ebpf::maps::{PerCpuArray, PerfEventByteArray};
pub use aya_log_common::{write_record_header, Level, WriteToBuf, LOG_BUF_CAPACITY};
pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

#[doc(hidden)]
#[repr(C)]
pub struct LogBuf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[doc(hidden)]
// This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
// meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
// because the integration-test crate depends on this crate transitively. See comment in
// test/integration-test/Cargo.toml.
#[cfg_attr(target_arch = "bpf", map)]
pub static mut AYA_LOG_BUF: PerCpuArray<LogBuf> = PerCpuArray::with_max_entries(1, 0);

#[doc(hidden)]
// This cfg_attr prevents compilation failures on macOS where the generated section name doesn't
// meet mach-o's requirements. We wouldn't ordinarily build this crate for macOS, but we do so
// because the integration-test crate depends on this crate transitively. See comment in
// test/integration-test/Cargo.toml.
#[cfg_attr(target_arch = "bpf", map)]
pub static mut AYA_LOGS: PerfEventByteArray = PerfEventByteArray::new(0);

#[doc(hidden)]
pub mod macro_support {
    pub use aya_log_common::{
        DefaultFormatter, DisplayHint, IpFormatter, Level, LowerHexFormatter, LowerMacFormatter,
        UpperHexFormatter, UpperMacFormatter, LOG_BUF_CAPACITY,
    };
    pub use aya_log_ebpf_macros::log;
}
