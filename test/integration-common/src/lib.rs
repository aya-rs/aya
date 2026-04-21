#![no_std]

pub mod array {
    pub const GET_INDEX: u32 = 0;
    pub const GET_PTR_INDEX: u32 = 1;
    pub const GET_PTR_MUT_INDEX: u32 = 2;
    pub const NUM_SLOTS: u32 = 3;
    /// Arbitrary number of slots exercised by the array tests.
    pub const ARRAY_LEN: u32 = 4;
}

pub mod prog_array {
    /// Slot written by the uprobe after `tail_call` falls through.
    pub const RESULT_INDEX: u32 = 0;

    /// Slot written by the tail-call target to prove the target ran.
    pub const SUCCESS_INDEX: u32 = 1;

    /// Arbitrary non-zero sentinel written by the uprobe to prove control
    /// returned from a failed `tail_call`.
    pub const FAILURE_SENTINEL: u32 = 42;

    /// Arbitrary non-zero sentinel written by the tail-call target program.
    pub const SUCCESS_SENTINEL: u32 = 43;
}

pub mod bloom_filter {
    pub const INSERT_INDEX: u32 = 0;
    pub const CONTAINS_PRESENT_INDEX: u32 = 1;
    pub const CONTAINS_ABSENT_INDEX: u32 = 2;
}

pub mod bpf_probe_read {
    pub const RESULT_BUF_LEN: usize = 1024;

    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct TestResult {
        pub buf: [u8; RESULT_BUF_LEN],
        pub len: Option<Result<usize, i32>>,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
}

pub mod log {
    pub const BUF_LEN: usize = 1024;

    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct Buffer {
        pub buf: [u8; BUF_LEN], // 64 KiB, one more than LogValueLength::MAX.
        pub len: usize,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for Buffer {}
}

pub mod raw_tracepoint {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SysEnterEvent {
        pub common_type: u16,
        pub common_flags: u8,
        _padding: u8, // Padding must be explicit to ensure zero-initialization.
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for SysEnterEvent {}
}

pub mod ring_buf {
    // This structure's definition is duplicated in the probe.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
    pub struct Registers {
        pub dropped: u64,
        pub rejected: u64,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for Registers {}
}

pub mod strncmp {
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct TestResult(pub core::cmp::Ordering);

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
}

pub mod linear_data_structures {
    pub const PEEK_INDEX: u32 = 0;
    pub const POP_INDEX: u32 = 1;
}

pub mod printk {
    pub const C_MARKER: &core::ffi::CStr = c"PRINTK_TEST";
    pub const MARKER: &str = {
        match C_MARKER.to_str() {
            Ok(marker) => marker,
            Err(_) => panic!("C_MARKER.to_str()"),
        }
    };
    pub const TEST_CHAR: char = '\u{3042}'; // i.e. 'あ'
    pub const TEST_U8: u8 = 42;
    pub const TEST_U16: u16 = 0x1234;
    pub const TEST_U32: u32 = 0xDEAD_BEEF;
    pub const TEST_U64: u64 = 0x0123_4567_89AB_CDEF;
    pub const TEST_USIZE: usize = usize::MAX;
    pub const TEST_I8: i8 = -127;
    pub const TEST_I16: i16 = -32768;
    pub const TEST_I32: i32 = -0x0808_CAFE;
    pub const TEST_I64: i64 = -0x0123_4567_89AB_CDEF;
    pub const TEST_ISIZE: isize = isize::MIN;
}

pub mod sk_storage {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(C)]
    pub enum Ip {
        V4(u32),
        V6([u32; 4]),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(C)]
    pub struct Value {
        pub user_family: u32,
        pub user_ip: Ip,
        pub user_port: u32,
        pub family: u32,
        pub type_: u32,
        pub protocol: u32,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for Value {}
}

pub mod lpm_trie {
    pub const LPM_MATCH_SLOT: u32 = 0;
    pub const NO_MATCH_SLOT: u32 = 1;
    pub const REMOVE_SLOT: u32 = 2;
    pub const NUM_SLOTS: u32 = 3;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct TestResult {
        pub value: u32,
        /// Distinguishes a recorded result from a zero-initialised slot.
        pub ran: bool,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
}

pub mod sk_reuseport {
    pub const SELECT_HITS_INDEX: u32 = 0;
    pub const MIGRATE_HITS_INDEX: u32 = 1;
    pub const CLEAR_FALLBACK_HITS_INDEX: u32 = 2;
    pub const SELECT_SOCKET_INDEX: u32 = 0;
    pub const MIGRATE_SOCKET_INDEX: u32 = 2;
}

pub mod stack_trace {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct TestResult {
        pub stack_id: u32,

        /// Distinguishes a recorded result from a zero-initialised slot.
        pub ran: bool,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
}
