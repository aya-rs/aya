use std::{fmt, io, sync::OnceLock};

use crate::{
    programs::{ProgramType, is_syscall_wrapper_supported},
    sys::{
        BpfHelper, BtfFeature, is_bpf_global_data_supported, is_bpf_name_supported,
        is_btf_feature_supported, is_btf_supported, is_cpumap_prog_id_supported,
        is_devmap_prog_id_supported, is_helper_supported, is_perf_link_supported,
    },
};

struct FeatureProbe {
    probe_name: &'static str,
    probe: fn() -> io::Result<bool>,
    value: OnceLock<io::Result<bool>>,
}

impl FeatureProbe {
    const fn new(probe_name: &'static str, probe: fn() -> io::Result<bool>) -> Self {
        Self {
            probe_name,
            probe,
            value: OnceLock::new(),
        }
    }

    fn get(&self) -> bool {
        // Kernel capabilities are expected to remain stable for the lifetime of the
        // process. Cache probe errors to avoid retrying a failed probe, but treat them as
        // unsupported when returning the boolean result.
        self.value
            .get_or_init(|| {
                (self.probe)().inspect_err(|error| {
                    log::warn!("kernel feature probe `{}` failed: {error}", self.probe_name);
                })
            })
            .as_ref()
            .copied()
            .unwrap_or(false)
    }
}

macro_rules! feature_probe {
    ($probe:path) => {
        FeatureProbe::new(stringify!($probe), $probe)
    };
    ($probe:path, $arg:expr) => {
        FeatureProbe::new(
            concat!(stringify!($probe), "(", stringify!($arg), ")"),
            || $probe($arg),
        )
    };
}

impl fmt::Debug for FeatureProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value.get() {
            Some(value) => value.fmt(f),
            None => f.write_str("<not yet probed>"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Feature {
    BpfName,
    BpfProbeReadKernel,
    BpfPerfLink,
    BpfGlobalData,
    BpfCookie,
    CpuMapProgId,
    DevMapProgId,
    BpfSyscallWrapper,
    Btf,
}

/// Kernel feature support used internally by Aya.
///
/// The global [`FEATURES`] instance probes features on first use. Each feature is probed at most
/// once during the lifetime of the process, and probe failures are treated as unsupported.
#[derive(Debug)]
pub(crate) struct Features {
    bpf_name: FeatureProbe,
    bpf_probe_read_kernel: FeatureProbe,
    bpf_perf_link: FeatureProbe,
    bpf_global_data: FeatureProbe,
    bpf_cookie: FeatureProbe,
    cpumap_prog_id: FeatureProbe,
    devmap_prog_id: FeatureProbe,
    bpf_syscall_wrapper: FeatureProbe,
    btf: FeatureProbe,
    btf_capabilities: BtfFeatures,
}

impl Features {
    const fn new() -> Self {
        Self {
            bpf_name: feature_probe!(is_bpf_name_supported),
            bpf_probe_read_kernel: feature_probe!(probe_read_kernel_feature),
            bpf_perf_link: feature_probe!(is_perf_link_supported),
            bpf_global_data: feature_probe!(is_bpf_global_data_supported),
            bpf_cookie: feature_probe!(probe_bpf_cookie_feature),
            cpumap_prog_id: feature_probe!(is_cpumap_prog_id_supported),
            devmap_prog_id: feature_probe!(is_devmap_prog_id_supported),
            bpf_syscall_wrapper: FeatureProbe::new("is_syscall_wrapper_supported", || {
                Ok(is_syscall_wrapper_supported())
            }),
            btf: feature_probe!(is_btf_supported),
            btf_capabilities: BtfFeatures::new(),
        }
    }

    pub(crate) fn is_supported(&self, feature: Feature) -> bool {
        let Self {
            bpf_name,
            bpf_probe_read_kernel,
            bpf_perf_link,
            bpf_global_data,
            bpf_cookie,
            cpumap_prog_id,
            devmap_prog_id,
            bpf_syscall_wrapper,
            btf,
            btf_capabilities: _,
        } = self;
        let probe = match feature {
            Feature::BpfName => bpf_name,
            Feature::BpfProbeReadKernel => bpf_probe_read_kernel,
            Feature::BpfPerfLink => bpf_perf_link,
            Feature::BpfGlobalData => bpf_global_data,
            Feature::BpfCookie => bpf_cookie,
            Feature::CpuMapProgId => cpumap_prog_id,
            Feature::DevMapProgId => devmap_prog_id,
            Feature::BpfSyscallWrapper => bpf_syscall_wrapper,
            Feature::Btf => btf,
        };
        probe.get()
    }

    pub(crate) fn btf(&self) -> Option<&BtfFeatures> {
        self.is_supported(Feature::Btf)
            .then_some(&self.btf_capabilities)
    }
}

#[derive(Debug)]
pub(crate) struct BtfFeatures {
    func: FeatureProbe,
    func_global: FeatureProbe,
    datasec: FeatureProbe,
    datasec_zero: FeatureProbe,
    float: FeatureProbe,
    decl_tag: FeatureProbe,
    type_tag: FeatureProbe,
    enum64: FeatureProbe,
}

impl BtfFeatures {
    const fn new() -> Self {
        Self {
            func: feature_probe!(is_btf_feature_supported, BtfFeature::Func),
            func_global: feature_probe!(is_btf_feature_supported, BtfFeature::FuncGlobal),
            datasec: feature_probe!(is_btf_feature_supported, BtfFeature::DataSec),
            datasec_zero: feature_probe!(is_btf_feature_supported, BtfFeature::DataSecZero),
            float: feature_probe!(is_btf_feature_supported, BtfFeature::Float),
            decl_tag: feature_probe!(is_btf_feature_supported, BtfFeature::DeclTag),
            type_tag: feature_probe!(is_btf_feature_supported, BtfFeature::TypeTag),
            enum64: feature_probe!(is_btf_feature_supported, BtfFeature::Enum64),
        }
    }

    pub(crate) fn is_supported(&self, feature: BtfFeature) -> bool {
        let Self {
            func,
            func_global,
            datasec,
            datasec_zero,
            float,
            decl_tag,
            type_tag,
            enum64,
        } = self;
        let capability = match feature {
            BtfFeature::Func => func,
            BtfFeature::FuncGlobal => func_global,
            BtfFeature::DataSec => datasec,
            BtfFeature::DataSecZero => datasec_zero,
            BtfFeature::Float => float,
            BtfFeature::DeclTag => decl_tag,
            BtfFeature::TypeTag => type_tag,
            BtfFeature::Enum64 => enum64,
        };
        capability.get()
    }
}

pub(crate) static FEATURES: Features = Features::new();

fn probe_read_kernel_feature() -> io::Result<bool> {
    is_helper_supported(
        ProgramType::TracePoint,
        BpfHelper::BPF_FUNC_probe_read_kernel,
    )
    .map_err(io::Error::other)
}

fn probe_bpf_cookie_feature() -> io::Result<bool> {
    is_helper_supported(ProgramType::KProbe, BpfHelper::BPF_FUNC_get_attach_cookie)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::{io, sync::OnceLock};

    use super::FeatureProbe;

    #[test]
    fn feature_is_probed_on_demand_once() {
        // FeatureProbe stores a function pointer, so the probe cannot capture a local call marker.
        static PROBED: OnceLock<()> = OnceLock::new();

        let feature = FeatureProbe::new("test feature", || {
            PROBED.set(()).expect("feature probed more than once");
            Ok(true)
        });

        assert!(format!("{feature:?}").contains("<not yet probed>"));
        assert!(PROBED.get().is_none());

        assert!(feature.get());
        assert!(feature.get());
        assert!(PROBED.get().is_some());
    }

    #[test]
    fn feature_probe_errors_are_cached_and_treated_as_unsupported() {
        // FeatureProbe stores a function pointer, so the probe cannot capture a local call marker.
        static PROBED: OnceLock<()> = OnceLock::new();

        let feature = FeatureProbe::new("test feature", || {
            PROBED.set(()).expect("feature probed more than once");
            Err(io::Error::from_raw_os_error(libc::EIO))
        });

        assert!(!feature.get());
        assert!(!feature.get());
        assert!(PROBED.get().is_some());

        let error = io::Error::from_raw_os_error(libc::EIO);
        assert_eq!(format!("{feature:?}"), format!("Err({error:?})"));
    }
}
