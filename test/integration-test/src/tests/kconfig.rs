use std::ffi::c_longlong;

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfError, EbpfLoader, KConfig, KConfigMode,
    maps::Array,
    programs::{UProbe, uprobe::UProbeScope},
    util::KernelVersion,
};
use aya_obj::btf::BtfError;
const CONFIG_BPF_INDEX: u32 = 0;
const PANIC_TIMEOUT_INDEX: u32 = 1;
const DEFAULT_HUNG_TASK_TIMEOUT_INDEX: u32 = 2;
const BPF_JIT_INDEX: u32 = 3;
const DEFAULT_HOSTNAME_INDEX: u32 = 4;
const DEFAULT_HOSTNAME_LEN: usize = 64;
const OPTIONAL_INDEX: u32 = DEFAULT_HOSTNAME_INDEX + DEFAULT_HOSTNAME_LEN as u32;
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
        .kconfig(KConfigMode::Explicit(KConfig::parse(config).unwrap()))
        .load(bytes)
}

fn run_kconfig(config: &[u8]) -> Array<aya::maps::MapData, c_longlong> {
    let mut bpf = load_with_kconfig(crate::KCONFIG, config).unwrap();

    let prog: &mut UProbe = bpf.program_mut("test_kconfig").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(
        "trigger_kconfig",
        "/proc/self/exe",
        UProbeScope::CallingProcess,
    )
    .unwrap();

    trigger_kconfig();

    bpf.take_map("RESULTS").unwrap().try_into().unwrap()
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
    let results = run_kconfig(KCONFIG_TEST_CONFIG);

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

#[test_log::test]
fn kconfig_materializes_false_markers_and_numeric_scalars() {
    if !ensure_kconfig_support() {
        return;
    }
    let results = run_kconfig(KCONFIG_FALSE_AND_NUMERIC_SCALAR_CONFIG);

    assert_eq!(results.get(&CONFIG_BPF_INDEX, 0).unwrap(), 0);
    assert_eq!(results.get(&BPF_JIT_INDEX, 0).unwrap(), 0);
    assert_eq!(
        results.get(&CHAR_VALUE_INDEX, 0).unwrap(),
        c_longlong::from(b'A')
    );
    assert_eq!(results.get(&BOOL_VALUE_INDEX, 0).unwrap(), 1);
    assert_eq!(results.get(&TRISTATE_ENUM_INDEX, 0).unwrap(), 0);
    assert_eq!(
        read_u8_string::<DEFAULT_HOSTNAME_LEN>(&results, DEFAULT_HOSTNAME_INDEX),
        nul_terminated_string(b"host")
    );
    assert_eq!(
        read_u8_string::<TRUNCATED_STRING_LEN>(&results, TRUNCATED_STRING_INDEX),
        *b"ab\0\0"
    );
}

#[test_log::test]
fn kconfig_materializes_yes_tristate_enums() {
    if !ensure_kconfig_support() {
        return;
    }
    let results = run_kconfig(KCONFIG_YES_TRISTATE_CONFIG);

    assert_eq!(results.get(&TRISTATE_ENUM_INDEX, 0).unwrap(), 1);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig() {
    core::hint::black_box(trigger_kconfig);
}

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

const KCONFIG_FALSE_AND_NUMERIC_SCALAR_CONFIG: &[u8] = br#"
CONFIG_BPF=n
CONFIG_PANIC_TIMEOUT=0
CONFIG_BPF_JIT=0
CONFIG_DEFAULT_HOSTNAME="host"
CONFIG_CHAR_VALUE=65
CONFIG_BOOL_VALUE=1
CONFIG_TRISTATE_ENUM=n
CONFIG_TRUNCATED_STRING="ab"
"#;

const KCONFIG_YES_TRISTATE_CONFIG: &[u8] = br#"
CONFIG_BPF=y
CONFIG_PANIC_TIMEOUT=0
CONFIG_BPF_JIT=y
CONFIG_DEFAULT_HOSTNAME="host"
CONFIG_CHAR_VALUE=0
CONFIG_BOOL_VALUE=0
CONFIG_TRISTATE_ENUM=y
CONFIG_TRUNCATED_STRING="ab"
"#;

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
fn kconfig_rejects_out_of_range_numeric_bool_scalars() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_INVALID_BOOL, b"CONFIG_BOOL_VALUE=2\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_BOOL_VALUE"
    );
}

#[test_log::test]
fn kconfig_rejects_unsized_string_arrays() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(
            crate::KCONFIG_INVALID_ARRAY,
            b"CONFIG_UNSIZED_STRING=\"abc\"\n",
        ),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "CONFIG_UNSIZED_STRING"
    );
}

#[test_log::test]
fn kconfig_rejects_tristate_markers_for_wide_ints() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_INT_TRISTATE, b"CONFIG_INT_VALUE=m\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_INT_VALUE"
    );
}

#[test_log::test]
fn kconfig_rejects_tristate_markers_for_strings() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_STRING_TRISTATE, b"CONFIG_STRING_VALUE=m\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_STRING_VALUE"
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

#[test_log::test]
fn kconfig_rejects_out_of_range_tristate_enums() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_TRISTATE_ENUM, b"CONFIG_TRISTATE_ENUM=3\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_TRISTATE_ENUM"
    );
}

#[test_log::test]
fn kconfig_rejects_unknown_strong_linux_externs() {
    if !ensure_kconfig_support() {
        return;
    }

    assert_matches!(
        load_with_kconfig(crate::KCONFIG_UNKNOWN_LINUX_STRONG, b""),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "LINUX_HAS_FUTURE_FEATURE"
    );
}
