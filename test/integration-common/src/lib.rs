#![no_std]

pub mod bpf_probe_read {
    pub const RESULT_BUF_LEN: usize = 1024;

    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct TestResult {
        pub buf: [u8; RESULT_BUF_LEN],
        pub len: Option<Result<usize, i64>>,
    }

    #[cfg(feature = "user")]
    unsafe impl aya::Pod for TestResult {}
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

    impl core::ops::Add for Registers {
        type Output = Self;
        fn add(self, rhs: Self) -> Self::Output {
            Self {
                dropped: self.dropped + rhs.dropped,
                rejected: self.rejected + rhs.rejected,
            }
        }
    }

    impl<'a> core::iter::Sum<&'a Registers> for Registers {
        fn sum<I: Iterator<Item = &'a Registers>>(iter: I) -> Self {
            iter.fold(Default::default(), |a, b| a + *b)
        }
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

pub mod stack_queue {
    pub const PEEK_INDEX: u32 = 0;
    pub const POP_INDEX: u32 = 1;
}
