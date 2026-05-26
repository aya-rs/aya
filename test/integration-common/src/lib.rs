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

pub mod fexit {
    pub const TEST_RAN: u32 = 1;

    pub const NO_ERROR: i32 = 0;
    pub const RETVAL_MISMATCH: i32 = 1;
    pub const ARG_MISMATCH: i32 = 2;

    pub const TEST1_INDEX: u32 = 0;
    pub const TEST2_INDEX: u32 = 1;
    pub const TEST3_INDEX: u32 = 2;
    pub const TEST4_INDEX: u32 = 3;
    pub const TEST5_INDEX: u32 = 4;
    pub const TEST6_INDEX: u32 = 5;
    pub const TEST7_INDEX: u32 = 6;
    pub const TEST8_INDEX: u32 = 7;
    pub const TEST9_INDEX: u32 = 8;
    pub const TEST10_INDEX: u32 = 9;

    pub const TEST_COUNT: u32 = 10;

    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    pub struct TestResult {
        /// Distinguishes a recorded result from a zero-initialised slot. Use a
        /// `u32` flag instead of `bool` so this `Pod` type has no implicit
        /// padding.
        pub ran: u32,
        pub error: i32,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
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

pub mod cgroup_array {
    /// Index holding a cgroup the task is under (expect `1`).
    pub const UNDER_INDEX: u32 = 0;
    /// Index holding a cgroup the task is not under (expect `0`).
    pub const NOT_UNDER_INDEX: u32 = 1;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct TestResult {
        /// `current_task_under_cgroup` for `UNDER_INDEX`: 1 under, 0 not, negative errno.
        pub under: i64,
        /// `current_task_under_cgroup` for `NOT_UNDER_INDEX`.
        pub not_under: i64,
        /// Distinguishes a recorded result from a zero-initialised slot.
        pub ran: bool,
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
        pub regs_addr: u64,
        pub syscall_id: i64,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for SysEnterEvent {}

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TaskRenameEvent {
        pub task_addr: u64,
        pub comm_addr: u64,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TaskRenameEvent {}
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

pub mod btf_map_of_maps {
    /// Capacity of each inner array shared between userspace and the eBPF probes.
    pub const INNER_MAX_ENTRIES: u32 = 10;

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(C)]
    pub struct TestResult {
        pub value: u32,
        pub ran: u32,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
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
    pub const PATH_HITS_MAX_ENTRIES: u32 = 3;
    pub const SELECT_SOCKET_INDEX: u32 = 0;
    pub const MIGRATE_SOCKET_INDEX: u32 = 2;
}

pub mod socket_filter {
    pub const PASS_HITS_INDEX: u32 = 0;
    pub const TRIM_HITS_INDEX: u32 = 1;

    pub const REUSEPORT_SELECT_FIRST_HITS_INDEX: u32 = 2;
    pub const REUSEPORT_SELECT_SECOND_HITS_INDEX: u32 = 3;
    pub const PATH_HITS_MAX_ENTRIES: u32 = 4;

    pub const TRIM_DELTA_BYTES: u32 = 4;
    pub const REUSEPORT_FIRST_LISTENER_INDEX: i64 = 0;
    pub const REUSEPORT_SECOND_LISTENER_INDEX: i64 = 1;
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

pub mod test_run {
    pub const XDP_MODIFY_VAL: u8 = 0xAA;
    pub const IF_INDEX: u32 = 1;
    pub const XDP_MODIFY_LEN: usize = 16;
}
