use assert_matches::assert_matches;

use aya::{
    Ebpf, EbpfError, EbpfLoader, KConfig,
    maps::{Array, MapData},
    programs::UProbe,
    util::KernelVersion,
};
use aya_obj::btf::BtfError;
use integration_common::kconfig::{
    BOOL_VALUE_INDEX, BPF_JIT_INDEX, BYTE_INDEX, CHAR_VALUE_INDEX, CONFIG_BPF_INDEX,
    DEFAULT_HOSTNAME_INDEX, DEFAULT_HOSTNAME_LEN, DEFAULT_HUNG_TASK_TIMEOUT_INDEX,
    FIRST_STRING_INDEX, FIRST_STRING_LEN, FUTURE_LINUX_INDEX, OPTIONAL_INDEX,
    OPTIONAL_STRING_INDEX, OPTIONAL_STRING_LEN, PADDED_INDEX, PANIC_TIMEOUT_INDEX,
    SECOND_STRING_INDEX, SECOND_STRING_LEN, TRIMMED_INDEX, TRISTATE_ENUM_INDEX,
    TRUNCATED_STRING_INDEX, TRUNCATED_STRING_LEN,
};

const REQUIRED_OPTIONAL_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_required_optional.bpf.o",
));
const OPTIONAL_WEAK_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_optional_weak.bpf.o",
));
const UNKNOWN_WEAK_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_unknown_weak.bpf.o",
));
const UNKNOWN_LINUX_WEAK_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_unknown_linux_weak.bpf.o",
));
const SCALARS_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_scalars.bpf.o",
));
const UNSUPPORTED_ARRAY_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_unsupported_array.bpf.o",
));
const NON_TRISTATE_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../aya-obj/tests/fixtures/kconfig_non_tristate.bpf.o",
));

const KCONFIG_SEMANTICS_CONFIG: &[u8] = br#"
CONFIG_BPF=y
CONFIG_PANIC_TIMEOUT=0
CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120
CONFIG_BPF_JIT=y
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_FIRST_STRING="a"
CONFIG_SECOND_STRING="bcdef"
CONFIG_BYTE=0xaa
CONFIG_TRIMMED=0x11223344
CONFIG_PADDED=0x6655
CONFIG_BOOL_VALUE=y
CONFIG_CHAR_VALUE=m
CONFIG_TRISTATE_ENUM=m
CONFIG_TRUNCATED_STRING="abcdef"
"#;

const SCALARS_BASE_CONFIG: &[u8] = b"
CONFIG_BYTE=0xaa
CONFIG_TRIMMED=0x11223344
CONFIG_PADDED=0x6655
CONFIG_TOO_LARGE=255
CONFIG_TOO_POSITIVE=127
CONFIG_TOO_NEGATIVE=-128
CONFIG_BOOL_VALUE=y
CONFIG_CHAR_VALUE=m
CONFIG_TRISTATE_ENUM=m
";

fn load_with_kconfig(data: &[u8], config_text: &[u8]) -> Result<Ebpf, EbpfError> {
    let kconfig = KConfig::parse(config_text).unwrap();
    EbpfLoader::new().kconfig(Some(kconfig)).load(data)
}

fn load_scalars_with(config_line: &[u8]) -> Result<Ebpf, EbpfError> {
    let mut config = Vec::from(SCALARS_BASE_CONFIG);
    config.extend_from_slice(config_line);
    load_with_kconfig(SCALARS_FIXTURE, &config)
}

fn attach_uprobe(bpf: &mut Ebpf, program_name: &str, fn_name: &str) {
    let prog: &mut UProbe = bpf.program_mut(program_name).unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(fn_name, "/proc/self/exe", None).unwrap();
}

fn read_u64(results: &Array<MapData, u64>, index: u32) -> u64 {
    results.get(&index, 0).unwrap()
}

fn read_bytes<const N: usize>(results: &Array<MapData, u64>, start: u32) -> [u8; N] {
    let mut result = [0u8; N];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = results
            .get(&u32::try_from(i).unwrap().wrapping_add(start), 0)
            .unwrap() as u8;
    }
    result
}

#[test_log::test]
fn kconfig() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 9, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, kconfig support for BPF requires 5.9.0"
        );
        return;
    }

    let kconfig = match KConfig::current() {
        Ok(kconfig) => kconfig,
        Err(err) => {
            eprintln!("skipping test because KConfig::current() failed: {err}");
            return;
        }
    };

    let mut bpf = EbpfLoader::new()
        .kconfig(Some(kconfig))
        .load(crate::KCONFIG_CURRENT)
        .unwrap();
    attach_uprobe(&mut bpf, "test_kconfig_current", "trigger_kconfig");
    trigger_kconfig();
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig() {
    core::hint::black_box(trigger_kconfig);
}

#[test_log::test]
fn kconfig_semantics() {
    let mut bpf = load_with_kconfig(crate::KCONFIG, KCONFIG_SEMANTICS_CONFIG).unwrap();

    attach_uprobe(&mut bpf, "test_kconfig", "trigger_kconfig_semantics_core");
    attach_uprobe(
        &mut bpf,
        "test_kconfig_unsized_strings",
        "trigger_kconfig_semantics_strings",
    );
    attach_uprobe(
        &mut bpf,
        "test_kconfig_semantics",
        "trigger_kconfig_semantics_more",
    );

    trigger_kconfig_semantics_core();
    trigger_kconfig_semantics_strings();
    trigger_kconfig_semantics_more();

    let results: Array<_, u64> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();

    assert_eq!(read_u64(&results, CONFIG_BPF_INDEX), 1);
    assert_eq!(read_u64(&results, PANIC_TIMEOUT_INDEX), 0);
    assert_eq!(read_u64(&results, DEFAULT_HUNG_TASK_TIMEOUT_INDEX), 120);
    assert_eq!(read_u64(&results, BPF_JIT_INDEX), 1);
    assert_eq!(
        read_bytes::<DEFAULT_HOSTNAME_LEN>(&results, DEFAULT_HOSTNAME_INDEX),
        {
            let mut expected = [0u8; DEFAULT_HOSTNAME_LEN];
            expected[..6].copy_from_slice(b"(none)");
            expected[6] = 0;
            expected
        }
    );
    assert_eq!(
        read_bytes::<FIRST_STRING_LEN>(&results, FIRST_STRING_INDEX),
        *b"a\0"
    );
    assert_eq!(
        read_bytes::<SECOND_STRING_LEN>(&results, SECOND_STRING_INDEX),
        *b"bcdef\0"
    );
    assert_eq!(read_u64(&results, OPTIONAL_INDEX), 0);
    assert_eq!(read_u64(&results, BYTE_INDEX), 0xaa);
    assert_eq!(read_u64(&results, TRIMMED_INDEX), 0x1122_3344);
    assert_eq!(read_u64(&results, PADDED_INDEX), 0x6655);
    assert_eq!(read_u64(&results, BOOL_VALUE_INDEX), 1);
    assert_eq!(read_u64(&results, CHAR_VALUE_INDEX), u64::from(b'm'));
    assert_eq!(read_u64(&results, TRISTATE_ENUM_INDEX), 2);
    assert_eq!(read_u64(&results, FUTURE_LINUX_INDEX), 0);
    assert_eq!(
        read_bytes::<TRUNCATED_STRING_LEN>(&results, TRUNCATED_STRING_INDEX),
        *b"abc\0"
    );
    assert_eq!(
        read_bytes::<OPTIONAL_STRING_LEN>(&results, OPTIONAL_STRING_INDEX),
        *b"\0"
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig_semantics_core() {
    core::hint::black_box(trigger_kconfig_semantics_core);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig_semantics_strings() {
    core::hint::black_box(trigger_kconfig_semantics_strings);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig_semantics_more() {
    core::hint::black_box(trigger_kconfig_semantics_more);
}

#[test_log::test]
fn kconfig_requires_strong_externs() {
    assert_matches!(
        load_with_kconfig(REQUIRED_OPTIONAL_FIXTURE, b""),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolNotFound { symbol_name }))
            if symbol_name == "CONFIG_REQUIRED"
    );
}

#[test_log::test]
fn kconfig_zero_fills_missing_weak_externs() {
    load_with_kconfig(OPTIONAL_WEAK_FIXTURE, b"CONFIG_REQUIRED=1\n").unwrap();
}

#[test_log::test]
fn kconfig_rejects_unknown_weak_externs() {
    assert_matches!(
        load_with_kconfig(UNKNOWN_WEAK_FIXTURE, b""),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "UNKNOWN_OPTIONAL"
    );
}

#[test_log::test]
fn kconfig_zero_fills_unknown_weak_linux_externs() {
    load_with_kconfig(UNKNOWN_LINUX_WEAK_FIXTURE, b"").unwrap();
}

#[test_log::test]
fn kconfig_rejects_unsupported_types() {
    assert_matches!(
        load_with_kconfig(UNSUPPORTED_ARRAY_FIXTURE, b"CONFIG_UNSUPPORTED_ARRAY=1\n"),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "CONFIG_UNSUPPORTED_ARRAY"
    );
}

#[test_log::test]
fn kconfig_rejects_non_tristate_enums() {
    assert_matches!(
        load_with_kconfig(NON_TRISTATE_FIXTURE, b"CONFIG_NOT_TRISTATE=1\n"),
        Err(EbpfError::BtfError(BtfError::InvalidExternalSymbol { symbol_name }))
            if symbol_name == "CONFIG_NOT_TRISTATE"
    );
}

#[test_log::test]
fn kconfig_rejects_invalid_bool_values() {
    assert_matches!(
        load_scalars_with(b"CONFIG_BOOL_VALUE=2\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_BOOL_VALUE"
    );
}

#[test_log::test]
fn kconfig_rejects_out_of_range_unsigned_values() {
    assert_matches!(
        load_scalars_with(b"CONFIG_TOO_LARGE=256\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_TOO_LARGE"
    );
}

#[test_log::test]
fn kconfig_rejects_out_of_range_signed_values() {
    assert_matches!(
        load_scalars_with(b"CONFIG_TOO_POSITIVE=128\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_TOO_POSITIVE"
    );

    assert_matches!(
        load_scalars_with(b"CONFIG_TOO_NEGATIVE=-129\n"),
        Err(EbpfError::BtfError(BtfError::ExternalSymbolValueOutOfRange { symbol_name }))
            if symbol_name == "CONFIG_TOO_NEGATIVE"
    );
}
