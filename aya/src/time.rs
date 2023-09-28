//! Utilities for working with time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A timestamp relative to the system boot time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SinceBoot(Duration);

impl SinceBoot {
    /// The current SinceBoot.
    ///
    /// Note that these calls will be monotonic.
    pub fn now() -> Self {
        Self(get_time(libc::CLOCK_BOOTTIME))
    }

    /// Converts the timestamp to a `SystemTime`.
    ///
    /// Note that this will not be robust to changes in the system clock, and thus these
    /// times should not be used for comparisons.
    pub fn into_system(self) -> SystemTime {
        let Self(since_boot) = self;
        boot_time() + since_boot
    }

    pub(crate) fn from_nanos(nanos: u64) -> Self {
        Self(Duration::from_nanos(nanos))
    }
}

fn boot_time() -> SystemTime {
    let since_boot = get_time(libc::CLOCK_BOOTTIME);
    let since_epoch = get_time(libc::CLOCK_REALTIME);
    UNIX_EPOCH + since_epoch - since_boot
}

fn get_time(clock_id: libc::clockid_t) -> Duration {
    let mut time = unsafe { std::mem::zeroed::<libc::timespec>() };
    assert_eq!(
        unsafe { libc::clock_gettime(clock_id, &mut time) },
        0,
        "clock_gettime({}, _)",
        clock_id
    );
    let libc::timespec { tv_sec, tv_nsec } = time;
    Duration::new(tv_sec as u64, tv_nsec as u32)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_since_boot_now_into_system_near_system_time() {
        let since_boot = SinceBoot::now().into_system();
        let system_time = SystemTime::now();
        let delta = system_time
            .duration_since(since_boot)
            .unwrap_or_else(|err| err.duration());
        const MAX_DELTA: Duration = Duration::from_micros(10);
        assert!(
            delta <= MAX_DELTA,
            "delta {delta:?} > {MAX_DELTA:?}: since_boot: {:?}, system_time: {:?}",
            since_boot,
            system_time
        );
    }
}
