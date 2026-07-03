use std::process;

use aya::{
    EbpfLoader,
    maps::{Array, MapData},
    programs::KProbe,
};
use integration_common::syscall_args::{RAN, RESULT_INDEX, TestResult};

// The number of attempts we make to capture our own `kill(2)` call. The kprobe
// is global, so concurrent `kill` invocations from other processes can
// overwrite the shared result slot. Each attempt resets the slot to zero,
// recomputes `pid`, and triggers another `kill(pid, 0)` call.
const ATTEMPTS: usize = 16;

// Returns the syscall wrapper symbol used by the host architecture, or `None`
// if the architecture does not implement `CONFIG_ARCH_HAS_SYSCALL_WRAPPER`.
fn kill_syscall_wrapper() -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Some("__x64_sys_kill")
    } else if cfg!(target_arch = "aarch64") {
        Some("__arm64_sys_kill")
    } else {
        None
    }
}

#[test_log::test]
fn syscall_arg_kill() {
    let Some(wrapper) = kill_syscall_wrapper() else {
        eprintln!(
            "skipping test - syscall wrappers unavailable on {}",
            std::env::consts::ARCH
        );
        return;
    };

    let mut bpf = EbpfLoader::new().load(crate::SYSCALL_ARGS).unwrap();

    let mut results: Array<MapData, TestResult> =
        Array::try_from(bpf.take_map("RESULTS").unwrap()).unwrap();

    let prog: &mut KProbe = bpf
        .program_mut("syscall_args_kill")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(wrapper, 0).unwrap();

    // Try several times in case other processes' `kill` calls overwrite the
    // shared result slot between our reset and our read.
    for _ in 0..ATTEMPTS {
        let pid = process::id() as i32;
        let sig = 0i32;

        // Reset the result slot before triggering the kprobe.
        results.set(RESULT_INDEX, TestResult::default(), 0).unwrap();

        // Trigger the syscall. `kill(pid, 0)` performs a permission check
        // without actually delivering a signal, but still calls the syscall
        // wrapper and so fires the kprobe.
        let rc = unsafe { libc::kill(pid, sig) };
        assert_eq!(rc, 0, "kill({pid}, {sig}) failed");

        let result = results.get(&RESULT_INDEX, 0).unwrap();
        if result.ran != RAN || result.pid != pid || result.sig != sig {
            // Probably overwritten by another process' `kill` call. Retry.
            continue;
        }

        return;
    }

    panic!("did not observe our own kill(pid, 0) after {ATTEMPTS} attempts");
}
