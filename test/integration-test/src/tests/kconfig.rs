use std::{
    ffi::c_longlong,
    fs,
    path::{Path, PathBuf},
};

use aya::{EbpfLoader, KConfig, maps::Array, programs::UProbe, util::KernelVersion};
use flate2::read::GzDecoder;
use integration_common::kconfig::{
    BPF_JIT_INDEX, CONFIG_BPF_INDEX, DEFAULT_HOSTNAME_INDEX, DEFAULT_HOSTNAME_LEN,
    DEFAULT_HUNG_TASK_TIMEOUT_INDEX, FIRST_STRING_INDEX, FIRST_STRING_LEN, PANIC_TIMEOUT_INDEX,
    SECOND_STRING_INDEX, SECOND_STRING_LEN,
};
use procfs::{ConfigSetting, KernelConfig, prelude::FromRead as _};

fn numeric_setting(
    config: &std::collections::HashMap<String, ConfigSetting>,
    name: &str,
) -> Option<c_longlong> {
    match config.get(name) {
        Some(ConfigSetting::Yes) => Some(1),
        Some(ConfigSetting::Module) => Some(2),
        Some(ConfigSetting::Value(value)) => {
            if let Some(value) = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
            {
                Some(c_longlong::from_str_radix(value, 16).unwrap())
            } else {
                Some(value.parse().unwrap())
            }
        }
        None => None,
    }
}

fn string_setting(
    config: &std::collections::HashMap<String, ConfigSetting>,
    name: &str,
) -> [u8; DEFAULT_HOSTNAME_LEN] {
    let mut result = [0u8; DEFAULT_HOSTNAME_LEN];
    let value = match config.get(name) {
        Some(ConfigSetting::Value(value)) => value,
        Some(ConfigSetting::Yes | ConfigSetting::Module) => panic!("{name} is not a string"),
        None => panic!("{name} not found in kernel config"),
    };
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{name} is not quoted: {value}"));
    let bytes = value.as_bytes();
    assert!(
        bytes.len() < DEFAULT_HOSTNAME_LEN,
        "{name} too long for test buffer"
    );
    result[..bytes.len()].copy_from_slice(bytes);
    result[bytes.len()] = 0;
    result
}

fn read_kernel_config_file(path: &Path, gzip: bool) -> procfs::ProcResult<KernelConfig> {
    if gzip {
        let file = fs::File::open(path)?;
        KernelConfig::from_read(GzDecoder::new(file))
    } else {
        KernelConfig::from_read(fs::File::open(path)?)
    }
}

fn current_kernel_config() -> procfs::ProcResult<std::collections::HashMap<String, ConfigSetting>> {
    let mut boot_config_name = std::ffi::OsString::from("config-");
    boot_config_name.push(kernel_release());
    let boot_config_path = PathBuf::from("/boot").join(boot_config_name);

    if boot_config_path.exists() {
        if let Ok(config) = read_kernel_config_file(&boot_config_path, false) {
            return Ok(config.0);
        }
    }

    let proc_config_path = Path::new("/proc/config.gz");
    if proc_config_path.exists() {
        return read_kernel_config_file(proc_config_path, true).map(|config| config.0);
    }

    Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
}

fn kernel_release() -> std::ffi::OsString {
    use std::{ffi::CStr, os::unix::ffi::OsStringExt as _};

    unsafe {
        let mut v = std::mem::zeroed::<libc::utsname>();
        assert_eq!(libc::uname(std::ptr::from_mut(&mut v)), 0);
        let release = CStr::from_ptr(v.release.as_ptr());
        std::ffi::OsString::from_vec(release.to_bytes().to_vec())
    }
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
    let kernel_config = match current_kernel_config() {
        Ok(kernel_config) => kernel_config,
        Err(err) => {
            eprintln!("skipping test because current kernel config could not be read: {err}");
            return;
        }
    };

    let mut bpf = EbpfLoader::new()
        .kconfig(Some(kconfig))
        .load(crate::KCONFIG)
        .unwrap();

    let prog: &mut UProbe = bpf.program_mut("test_kconfig").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("trigger_kconfig", "/proc/self/exe", None)
        .unwrap();

    trigger_kconfig();

    let results: Array<_, c_longlong> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();

    assert_eq!(
        results.get(&CONFIG_BPF_INDEX, 0).unwrap(),
        numeric_setting(&kernel_config, "CONFIG_BPF").unwrap()
    );
    assert_eq!(
        results.get(&PANIC_TIMEOUT_INDEX, 0).unwrap(),
        numeric_setting(&kernel_config, "CONFIG_PANIC_TIMEOUT").unwrap()
    );
    if let Some(default_hung_task_timeout) =
        numeric_setting(&kernel_config, "CONFIG_DEFAULT_HUNG_TASK_TIMEOUT")
    {
        assert_eq!(
            results.get(&DEFAULT_HUNG_TASK_TIMEOUT_INDEX, 0).unwrap(),
            default_hung_task_timeout
        );
    }
    assert_eq!(
        results.get(&BPF_JIT_INDEX, 0).unwrap(),
        numeric_setting(&kernel_config, "CONFIG_BPF_JIT").unwrap()
    );
    let mut default_hostname = [0u8; DEFAULT_HOSTNAME_LEN];
    for (i, byte) in default_hostname.iter_mut().enumerate() {
        *byte = results
            .get(
                &u32::try_from(i)
                    .unwrap()
                    .wrapping_add(DEFAULT_HOSTNAME_INDEX),
                0,
            )
            .unwrap() as u8;
    }
    assert_eq!(
        default_hostname,
        string_setting(&kernel_config, "CONFIG_DEFAULT_HOSTNAME")
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
CONFIG_FIRST_STRING="a"
CONFIG_SECOND_STRING="bcdef"
"#;

#[test_log::test]
fn kconfig_unsized_strings() {
    let kconfig = KConfig::parse(UNSIZED_KCONFIG_TEST_CONFIG).unwrap();

    let mut bpf = EbpfLoader::new()
        .kconfig(Some(kconfig))
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

    let mut first = [0u8; FIRST_STRING_LEN];
    for (i, byte) in first.iter_mut().enumerate() {
        *byte = results
            .get(
                &u32::try_from(i).unwrap().wrapping_add(FIRST_STRING_INDEX),
                0,
            )
            .unwrap() as u8;
    }
    assert_eq!(first, *b"a\0");

    let mut second = [0u8; SECOND_STRING_LEN];
    for (i, byte) in second.iter_mut().enumerate() {
        *byte = results
            .get(
                &u32::try_from(i).unwrap().wrapping_add(SECOND_STRING_INDEX),
                0,
            )
            .unwrap() as u8;
    }
    assert_eq!(second, *b"bcdef\0");
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_kconfig_unsized_strings() {
    core::hint::black_box(trigger_kconfig_unsized_strings);
}
