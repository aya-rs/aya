#![no_std]
use aya_bpf::{
    macros::map,
    maps::{PerCpuArray, PerfEventByteArray},
};
pub use aya_log_common::{write_record_header, Level, WriteToBuf, LOG_BUF_CAPACITY};
pub use aya_log_ebpf_macros::{debug, error, info, log, trace, warn};

#[doc(hidden)]
#[repr(C)]
pub struct LogBuf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[doc(hidden)]
#[map]
pub static mut AYA_LOG_BUF: PerCpuArray<LogBuf> = PerCpuArray::with_max_entries(1, 0);

#[doc(hidden)]
#[map]
pub static mut AYA_LOGS: PerfEventByteArray = PerfEventByteArray::new(0);

#[doc(hidden)]
pub mod macro_support {
    pub use aya_log_common::{
        check_impl_default, check_impl_ip, check_impl_lower_hex, check_impl_lower_mac,
        check_impl_upper_hex, check_impl_upper_mac, DefaultFormatter, DisplayHint, IpFormatter,
        Level, LowerHexFormatter, LowerMacFormatter, UpperHexFormatter, UpperMacFormatter,
        LOG_BUF_CAPACITY,
    };
    pub use aya_log_ebpf_macros::log;
}
