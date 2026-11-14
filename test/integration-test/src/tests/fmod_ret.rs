use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    maps::Array,
    programs::{FExit, FModRet, ProgramError, TestRun as _},
    sys::SyscallError,
    util::KernelVersion,
};
use integration_common::fmod_ret::{
    ARGUMENT_INDEX, FEXIT_RAN_INDEX, INCOMING_RETURN_INDEX, INITIAL_SIDE_EFFECT,
    LONG_MODIFIER_RAN_INDEX, MODIFIER_RAN_INDEX, NOT_RUN, ORIGINAL_RETURN, ORIGINAL_SIDE_EFFECT,
    OVERRIDE_ERROR, PASS_THROUGH, RETURN_VALUE_INDEX, RETURNED_VALUE_INDEX, SENDER_TGID_INDEX,
    SIDE_EFFECT_INDEX, TARGET_ARGUMENT, TEST_RAN,
};

#[test]
fn fmod_ret_overrides_or_runs_the_target_and_preserves_fexit() {
    let version = KernelVersion::current().unwrap();
    if version < KernelVersion::new(5, 17, 0) {
        eprintln!("skipping fmod_ret test on {version:?}: context return helper requires 5.17");
        return;
    }
    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf = Ebpf::load(crate::FMOD_RET).unwrap();
    let mut control: Array<_, i32> = bpf.take_map("CONTROL").unwrap().try_into().unwrap();
    let mut results: Array<_, i32> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();
    let modifier: &mut FModRet = bpf
        .program_mut("modify_return")
        .unwrap()
        .try_into()
        .unwrap();
    let config = procfs::kernel_config().unwrap();
    let result = modifier.load("bpf_modify_return_test", &btf);
    // Linux 6.2 registers this target in a BTF fmodret ID set independently of error injection.
    if version < KernelVersion::new(6, 2, 0)
        && !matches!(
            config.get("CONFIG_FUNCTION_ERROR_INJECTION"),
            Some(procfs::ConfigSetting::Yes)
        )
    {
        assert_matches!(result, Err(ProgramError::LoadError { io_error, .. }) => {
            assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
        });
        return;
    }
    result.unwrap();
    let observer: &mut FExit = bpf
        .program_mut("observe_return")
        .unwrap()
        .try_into()
        .unwrap();
    observer.load("bpf_modify_return_test", &btf).unwrap();
    let attach_supported = cfg_select! {
        target_arch = "aarch64" => version >= KernelVersion::new(6, 4, 0),
        _ => true,
    };
    let result = observer.attach();
    if attach_supported {
        result.unwrap();
    } else {
        assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
            assert_eq!(call, "bpf_raw_tracepoint_open");
            assert_eq!(io_error.raw_os_error(), Some(524));
        });
    }
    let modifier: &mut FModRet = bpf
        .program_mut("modify_return")
        .unwrap()
        .try_into()
        .unwrap();
    let result = modifier.attach();
    if !attach_supported {
        assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
            assert_eq!(call, "bpf_raw_tracepoint_open");
            assert_eq!(io_error.raw_os_error(), Some(524));
        });
        eprintln!("asserted fexit and fmod_ret attach errno 524 on {version:?}");
        return;
    }
    result.unwrap();

    for (override_value, expected_result, expected_argument) in [
        (OVERRIDE_ERROR, OVERRIDE_ERROR, INITIAL_SIDE_EFFECT),
        (PASS_THROUGH, ORIGINAL_RETURN, ORIGINAL_SIDE_EFFECT),
    ] {
        control.set(RETURN_VALUE_INDEX, &override_value, 0).unwrap();
        for index in 0..results.len() {
            results.set(index, &NOT_RUN, 0).unwrap();
        }
        modifier.test_run(()).unwrap();
        assert_eq!(
            results.get(&MODIFIER_RAN_INDEX, 0).unwrap(),
            TEST_RAN,
            "modifier did not run"
        );
        assert_eq!(results.get(&ARGUMENT_INDEX, 0).unwrap(), TARGET_ARGUMENT);
        assert_eq!(
            results.get(&INCOMING_RETURN_INDEX, 0).unwrap(),
            PASS_THROUGH,
            "incoming modifier result"
        );
        assert_eq!(
            results.get(&FEXIT_RAN_INDEX, 0).unwrap(),
            TEST_RAN,
            "fexit did not run"
        );
        assert_eq!(
            results.get(&RETURNED_VALUE_INDEX, 0).unwrap(),
            expected_result
        );
        assert_eq!(
            results.get(&SIDE_EFFECT_INDEX, 0).unwrap(),
            expected_argument,
            "target side effect"
        );
    }
}

#[test]
fn fmod_ret_sign_extends_errno_for_long_syscall_targets() {
    let target = cfg_select! {
        target_arch = "x86_64" => Some(("__x64_sys_getpgid", KernelVersion::new(5, 7, 0))),
        target_arch = "aarch64" => Some(("__arm64_sys_getpgid", KernelVersion::new(6, 0, 0))),
        _ => None,
    };
    let Some((target, minimum)) = target else {
        eprintln!("skipping long syscall modifier on an unsupported architecture");
        return;
    };
    let version = KernelVersion::current().unwrap();
    if version < minimum {
        eprintln!(
            "skipping long syscall modifier on {version:?}: target loading requires {minimum:?}"
        );
        return;
    }
    // SAFETY: getpgid with pid zero queries this process and takes no pointers.
    let original = unsafe { libc::syscall(libc::SYS_getpgid, 0) };
    assert!(original >= 0);
    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf = Ebpf::load(crate::FMOD_RET).unwrap();
    let mut control: Array<_, i32> = bpf.take_map("CONTROL").unwrap().try_into().unwrap();
    let results: Array<_, i32> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();
    // The fixture compares root-namespace TGIDs, so this test requires the root PID namespace.
    control
        .set(
            SENDER_TGID_INDEX,
            &i32::try_from(std::process::id()).unwrap(),
            0,
        )
        .unwrap();
    control.set(RETURN_VALUE_INDEX, &OVERRIDE_ERROR, 0).unwrap();
    let modifier: &mut FModRet = bpf
        .program_mut("modify_long_return")
        .unwrap()
        .try_into()
        .unwrap();
    let config = procfs::kernel_config().unwrap();
    let result = modifier.load(target, &btf);
    // Syscall wrappers enter the error-injection list only with this option enabled.
    // https://github.com/torvalds/linux/blob/7d0a66e4b/include/asm-generic/error-injection.h
    if !matches!(
        config.get("CONFIG_FUNCTION_ERROR_INJECTION"),
        Some(procfs::ConfigSetting::Yes)
    ) {
        assert_matches!(result, Err(ProgramError::LoadError { io_error, .. }) => {
            assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
        });
        return;
    }
    result.unwrap();
    let result = modifier.attach();
    let attach_supported = cfg_select! {
        target_arch = "aarch64" => version >= KernelVersion::new(6, 4, 0),
        _ => true,
    };
    if !attach_supported {
        assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
            assert_eq!(call, "bpf_raw_tracepoint_open");
            assert_eq!(io_error.raw_os_error(), Some(524));
        });
        eprintln!("asserted long-return fmod_ret attach errno 524 on {version:?}");
        return;
    }
    result.unwrap();
    // SAFETY: the same scalar-only query now exercises the PID-scoped modifier.
    let overridden = unsafe { libc::syscall(libc::SYS_getpgid, 0) };
    let error = std::io::Error::last_os_error();
    assert_eq!(overridden, libc::c_long::from(OVERRIDE_ERROR));
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(results.get(&LONG_MODIFIER_RAN_INDEX, 0).unwrap(), TEST_RAN);
    control.set(RETURN_VALUE_INDEX, &PASS_THROUGH, 0).unwrap();
    // SAFETY: zero allows the same pointer-free syscall to execute normally.
    assert_eq!(unsafe { libc::syscall(libc::SYS_getpgid, 0) }, original);
}
