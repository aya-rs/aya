use std::ffi::c_longlong;

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfError, EbpfLoader, KConfig, maps::Array, programs::UProbe, util::KernelVersion,
};
use aya_obj::btf::BtfError;
use integration_common::kconfig::{
    BPF_JIT_INDEX, CONFIG_BPF_INDEX, DEFAULT_HOSTNAME_INDEX, DEFAULT_HOSTNAME_LEN,
    DEFAULT_HUNG_TASK_TIMEOUT_INDEX, FIRST_STRING_INDEX, FIRST_STRING_LEN, PANIC_TIMEOUT_INDEX,
    SECOND_STRING_INDEX, SECOND_STRING_LEN,
};

const OPTIONAL_INDEX: u32 = SECOND_STRING_INDEX + SECOND_STRING_LEN as u32;
const UNKNOWN_LINUX_INDEX: u32 = OPTIONAL_INDEX + 1;
const CHAR_VALUE_INDEX: u32 = UNKNOWN_LINUX_INDEX + 1;
const BOOL_VALUE_INDEX: u32 = CHAR_VALUE_INDEX + 1;
const TRISTATE_ENUM_INDEX: u32 = BOOL_VALUE_INDEX + 1;
const TRUNCATED_STRING_INDEX: u32 = TRISTATE_ENUM_INDEX + 1;
const TRUNCATED_STRING_LEN: usize = 4;
const OPTIONAL_STRING_INDEX: u32 = TRUNCATED_STRING_INDEX + TRUNCATED_STRING_LEN as u32;
const OPTIONAL_STRING_LEN: usize = 1;

fn ensure_kconfig_support() -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 9, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, kconfig support for BPF requires 5.9.0"
        );
        return false;
    }
    true
}

fn load_with_kconfig(bytes: &[u8], config: &[u8]) -> Result<Ebpf, EbpfError> {
    EbpfLoader::new()
        .kconfig(Some(KConfig::parse(config).unwrap()))
        .load(bytes)
}

fn read_u8_string<const LEN: usize>(
    results: &Array<aya::maps::MapData, c_longlong>,
    base: u32,
) -> [u8; LEN] {
    let mut value = [0u8; LEN];
    for (i, byte) in value.iter_mut().enumerate() {
        *byte = results
            .get(&u32::try_from(i).unwrap().wrapping_add(base), 0)
            .unwrap() as u8;
    }
    value
}

fn nul_terminated_string<const LEN: usize>(value: &[u8]) -> [u8; LEN] {
    let mut result = [0u8; LEN];
    assert!(value.len() < LEN);
    result[..value.len()].copy_from_slice(value);
    result
}

#[test_log::test]
fn kconfig() {
    if !ensure_kconfig_support() {
        return;
    }
    let mut bpf = load_with_kconfig(crate::KCONFIG, KCONFIG_TEST_CONFIG).unwrap();

    let prog: &mut UProbe = bpf.program_mut("test_kconfig").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("trigger_kconfig", "/proc/self/exe", None)
        .unwrap();

    trigger_kconfig();

    let results: Array<_, c_longlong> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();

    assert_eq!(results.get(&CONFIG_BPF_INDEX, 0).unwrap(), 1);
    assert_eq!(results.get(&PANIC_TIMEOUT_INDEX, 0).unwrap(), -1);
    assert_eq!(
        results.get(&DEFAULT_HUNG_TASK_TIMEOUT_INDEX, 0).unwrap(),
        120
    );
    assert_eq!(results.get(&BPF_JIT_INDEX, 0).unwrap(), 1);
    assert_eq!(
        read_u8_string::<DEFAULT_HOSTNAME_LEN>(&results, DEFAULT_HOSTNAME_INDEX),
        nul_terminated_string(b"(none)")
    );
    assert_eq!(results.get(&OPTIONAL_INDEX, 0).unwrap(), 0);
    assert_eq!(results.get(&UNKNOWN_LINUX_INDEX, 0).unwrap(), 0);
    assert_eq!(
        results.get(&CHAR_VALUE_INDEX, 0).unwrap(),
        c_longlong::from(b'm')
    );
    assert_eq!(results.get(&BOOL_VALUE_INDEX, 0).unwrap(), 1);
    assert_eq!(results.get(&TRISTATE_ENUM_INDEX, 0).unwrap(), 2);
    assert_eq!(
        read_u8_string::<TRUNCATED_STRING_LEN>(&results, TRUNCATED_STRING_INDEX),
        *b"abc\0"
    );
    assert_eq!(
        read_u8_string::<OPTIONAL_STRING_LEN>(&results, OPTIONAL_STRING_INDEX),
        *b"\0"
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig() {
    core::hint::black_box(trigger_kconfig);
}

const UNSIZED_KCONFIG_TEST_CONFIG: &[u8] = br#"
CONFIG_BPF=y
CONFIG_PANIC_TIMEOUT=0
CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120
CONFIG_BPF_JIT=y
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_CHAR_VALUE=m
CONFIG_BOOL_VALUE=y
CONFIG_TRISTATE_ENUM=m
CONFIG_TRUNCATED_STRING="abcdef"
CONFIG_FIRST_STRING="a"
CONFIG_SECOND_STRING="bcdef"
"#;

const KCONFIG_TEST_CONFIG: &[u8] = br#"
CONFIG_BPF=y
CONFIG_PANIC_TIMEOUT=-1
CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120
CONFIG_BPF_JIT=y
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_CHAR_VALUE=m
CONFIG_BOOL_VALUE=y
CONFIG_TRISTATE_ENUM=m
CONFIG_TRUNCATED_STRING="abcdef"
"#;

#[test_log::test]
fn kconfig_unsized_strings() {
    if !ensure_kconfig_support() {
        return;
    }

    let mut bpf = EbpfLoader::new()
        .kconfig(Some(KConfig::parse(UNSIZED_KCONFIG_TEST_CONFIG).unwrap()))
        .load(crate::KCONFIG)
        .unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_kconfig_unsized_strings")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_kconfig_unsized_strings", "/proc/self/exe", None)
        .unwrap();

    trigger_kconfig_unsized_strings();

    let results: Array<_, c_longlong> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();
    assert_eq!(
        read_u8_string::<FIRST_STRING_LEN>(&results, FIRST_STRING_INDEX),
        *b"a\0"
    );
    assert_eq!(
        read_u8_string::<SECOND_STRING_LEN>(&results, SECOND_STRING_INDEX),
        *b"bcdef\0"
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig_unsized_strings() {
    core::hint::black_box(trigger_kconfig_unsized_strings);
}

#[test_log::test]
fn kconfig_rejects_missing_strong_externs() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_MISSING_STRONG, b""),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolNotFound { symbol_name }))
            if symbol_name == "CONFIG_REQUIRED"
    );
}

#[test_log::test]
fn kconfig_rejects_unknown_weak_externs() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_UNKNOWN_WEAK, b""),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "UNKNOWN_OPTIONAL"
    );
}

#[test_log::test]
fn kconfig_rejects_out_of_range_unsigned_scalars() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_UNSIGNED_U8, b"CONFIG_TOO_LARGE=256\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_TOO_LARGE"
    );
}

#[test_log::test]
fn kconfig_rejects_out_of_range_positive_signed_scalars() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_SIGNED_I8, b"CONFIG_SIGNED_VALUE=128\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_SIGNED_VALUE"
    );
}

#[test_log::test]
fn kconfig_rejects_out_of_range_negative_signed_scalars() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_SIGNED_I8, b"CONFIG_SIGNED_VALUE=-129\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_SIGNED_VALUE"
    );
}

#[test_log::test]
fn kconfig_rejects_invalid_bool_scalars() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_INVALID_BOOL, b"CONFIG_BOOL_VALUE=m\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_BOOL_VALUE"
    );
}

#[test_log::test]
fn kconfig_rejects_unsupported_array_types() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(
            crate::KCONFIG_INVALID_ARRAY,
            b"CONFIG_UNSUPPORTED_ARRAY=1\n",
        ),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "CONFIG_UNSUPPORTED_ARRAY"
    );
}

#[test_log::test]
fn kconfig_rejects_non_tristate_enums() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_NON_TRISTATE_ENUM, b"CONFIG_NOT_TRISTATE=m\n"),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "CONFIG_NOT_TRISTATE"
    );
}
