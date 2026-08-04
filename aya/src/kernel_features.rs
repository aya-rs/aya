use std::{fmt, io, sync::OnceLock};

use crate::{
    programs::ProgramType,
    sys::{
        BpfHelper, BtfFeature, is_bpf_global_data_supported, is_bpf_name_supported,
        is_btf_feature_supported, is_btf_supported, is_cpumap_prog_id_supported,
        is_devmap_prog_id_supported, is_helper_supported, is_perf_link_supported,
    },
};

pub(crate) struct Feature {
    probe_name: &'static str,
    probe: fn() -> io::Result<bool>,
    value: OnceLock<io::Result<bool>>,
}

impl Feature {
    const fn new(probe_name: &'static str, probe: fn() -> io::Result<bool>) -> Self {
        Self {
            probe_name,
            probe,
            value: OnceLock::new(),
        }
    }

    pub(crate) fn get(&self) -> bool {
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

macro_rules! feature {
    ($probe:path) => {
        Feature::new(stringify!($probe), $probe)
    };
    ($probe:path, $arg:expr) => {
        Feature::new(
            concat!(stringify!($probe), "(", stringify!($arg), ")"),
            || $probe($arg),
        )
    };
}

impl fmt::Debug for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value.get() {
            Some(value) => value.fmt(f),
            None => f.write_str("<not yet probed>"),
        }
    }
}

/// Kernel feature support used internally by Aya.
///
/// The global [`FEATURES`] instance probes features on first use. Each feature is probed at most
/// once during the lifetime of the process, and probe failures are treated as unsupported.
#[derive(Debug)]
pub(crate) struct Features {
    pub(crate) bpf_name: Feature,
    pub(crate) bpf_probe_read_kernel: Feature,
    pub(crate) bpf_perf_link: Feature,
    pub(crate) bpf_global_data: Feature,
    pub(crate) bpf_cookie: Feature,
    pub(crate) cpumap_prog_id: Feature,
    pub(crate) devmap_prog_id: Feature,
    btf: Feature,
    btf_capabilities: BtfFeatures,
}

impl Features {
    const fn new() -> Self {
        Self {
            bpf_name: feature!(is_bpf_name_supported),
            bpf_probe_read_kernel: feature!(probe_read_kernel_feature),
            bpf_perf_link: feature!(is_perf_link_supported),
            bpf_global_data: feature!(is_bpf_global_data_supported),
            bpf_cookie: feature!(probe_bpf_cookie_feature),
            cpumap_prog_id: feature!(is_cpumap_prog_id_supported),
            devmap_prog_id: feature!(is_devmap_prog_id_supported),
            btf: feature!(is_btf_supported),
            btf_capabilities: BtfFeatures::new(),
        }
    }

    pub(crate) fn btf(&self) -> Option<&BtfFeatures> {
        self.btf.get().then_some(&self.btf_capabilities)
    }
}

#[derive(Debug)]
pub(crate) struct BtfFeatures {
    func: Feature,
    func_global: Feature,
    datasec: Feature,
    datasec_zero: Feature,
    float: Feature,
    decl_tag: Feature,
    type_tag: Feature,
    enum64: Feature,
}

impl BtfFeatures {
    const fn new() -> Self {
        Self {
            func: feature!(is_btf_feature_supported, BtfFeature::Func),
            func_global: feature!(is_btf_feature_supported, BtfFeature::FuncGlobal),
            datasec: feature!(is_btf_feature_supported, BtfFeature::DataSec),
            datasec_zero: feature!(is_btf_feature_supported, BtfFeature::DataSecZero),
            float: feature!(is_btf_feature_supported, BtfFeature::Float),
            decl_tag: feature!(is_btf_feature_supported, BtfFeature::DeclTag),
            type_tag: feature!(is_btf_feature_supported, BtfFeature::TypeTag),
            enum64: feature!(is_btf_feature_supported, BtfFeature::Enum64),
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

    use super::Feature;

    #[test]
    fn feature_is_probed_on_demand_once() {
        // Feature stores a function pointer, so the probe cannot capture a local call marker.
        static PROBED: OnceLock<()> = OnceLock::new();

        let feature = Feature::new("test feature", || {
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
        // Feature stores a function pointer, so the probe cannot capture a local call marker.
        static PROBED: OnceLock<()> = OnceLock::new();

        let feature = Feature::new("test feature", || {
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
