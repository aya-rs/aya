use std::{
    fmt, io,
    os::fd::{AsFd as _, BorrowedFd},
    sync::OnceLock,
};

use aya_obj::generated::bpf_map_type;

use crate::{
    programs::ProgramType,
    sys::{
        BpfHelper, BtfFeature, UProbeMultiFeature, probe_bpf_global_data, probe_bpf_name,
        probe_btf, probe_btf_feature, probe_helper, probe_perf_link, probe_prog_id,
        probe_uprobe_multi_link,
    },
    token::BpfToken,
};

/// A kernel feature probe, run with the BPF token of the [`Features`] instance, if any.
type Probe = fn(Option<BorrowedFd<'_>>) -> io::Result<bool>;

struct FeatureProbe {
    probe_name: &'static str,
    probe: Probe,
    value: OnceLock<io::Result<bool>>,
}

impl FeatureProbe {
    const fn new(probe_name: &'static str, probe: Probe) -> Self {
        Self {
            probe_name,
            probe,
            value: OnceLock::new(),
        }
    }

    fn get(&self, token_fd: Option<BorrowedFd<'_>>) -> bool {
        // Kernel capabilities are expected to remain stable for the lifetime of the
        // process. Cache probe errors to avoid retrying a failed probe, but treat them as
        // unsupported when returning the boolean result.
        self.value
            .get_or_init(|| {
                (self.probe)(token_fd).inspect_err(|error| {
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
            |token_fd| $probe($arg, token_fd),
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
    DevMapHashProgId,
    Btf,
    #[expect(dead_code, reason = "reserved for future USDT attach mode selection")]
    UProbeMultiLink,
}

/// Kernel feature support used internally by Aya.
///
/// The global [`FEATURES`] instance probes features on first use. Each feature is probed at most
/// once during the lifetime of the process, and probe failures are treated as unsupported.
///
/// An instance created with [`Features::with_token`] probes features through a BPF token
/// instead, which is required when the process lacks the necessary capabilities in the initial
/// user namespace.
#[derive(Debug)]
pub(crate) struct Features {
    token: Option<BpfToken>,
    bpf_name: FeatureProbe,
    bpf_probe_read_kernel: FeatureProbe,
    bpf_perf_link: FeatureProbe,
    bpf_global_data: FeatureProbe,
    bpf_cookie: FeatureProbe,
    cpumap_prog_id: FeatureProbe,
    devmap_prog_id: FeatureProbe,
    devmap_hash_prog_id: FeatureProbe,
    btf: FeatureProbe,
    uprobe_multi_link: FeatureProbe,
    btf_capabilities: BtfFeatures,
}

impl Features {
    const fn new(token: Option<BpfToken>) -> Self {
        Self {
            token,
            bpf_name: feature_probe!(probe_bpf_name),
            bpf_probe_read_kernel: feature_probe!(probe_read_kernel_feature),
            bpf_perf_link: feature_probe!(probe_perf_link),
            bpf_global_data: feature_probe!(probe_bpf_global_data),
            bpf_cookie: feature_probe!(probe_bpf_cookie_feature),
            cpumap_prog_id: feature_probe!(probe_prog_id, bpf_map_type::BPF_MAP_TYPE_CPUMAP),
            devmap_prog_id: feature_probe!(probe_prog_id, bpf_map_type::BPF_MAP_TYPE_DEVMAP),
            // Probed separately from `DEVMAP` because a token may only delegate one of them.
            devmap_hash_prog_id: feature_probe!(
                probe_prog_id,
                bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH
            ),
            btf: feature_probe!(probe_btf),
            uprobe_multi_link: feature_probe!(
                probe_uprobe_multi_link,
                UProbeMultiFeature::ProcessScopedPidFilter
            ),
            btf_capabilities: BtfFeatures::new(),
        }
    }

    /// Creates an instance that probes features through `token`.
    pub(crate) const fn with_token(token: BpfToken) -> Self {
        Self::new(Some(token))
    }

    fn token_fd(&self) -> Option<BorrowedFd<'_>> {
        self.token.as_ref().map(|token| token.as_fd())
    }

    pub(crate) fn is_supported(&self, feature: Feature) -> bool {
        let Self {
            token: _,
            bpf_name,
            bpf_probe_read_kernel,
            bpf_perf_link,
            bpf_global_data,
            bpf_cookie,
            cpumap_prog_id,
            devmap_prog_id,
            devmap_hash_prog_id,
            btf,
            uprobe_multi_link,
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
            Feature::DevMapHashProgId => devmap_hash_prog_id,
            Feature::Btf => btf,
            Feature::UProbeMultiLink => uprobe_multi_link,
        };
        probe.get(self.token_fd())
    }

    /// Returns a function that reports whether a BTF feature is supported, if BTF is.
    pub(crate) fn btf(&self) -> Option<impl Fn(BtfFeature) -> bool> {
        self.is_supported(Feature::Btf)
            .then_some(|feature| self.btf_capabilities.is_supported(feature, self.token_fd()))
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
            func: feature_probe!(probe_btf_feature, BtfFeature::Func),
            func_global: feature_probe!(probe_btf_feature, BtfFeature::FuncGlobal),
            datasec: feature_probe!(probe_btf_feature, BtfFeature::DataSec),
            datasec_zero: feature_probe!(probe_btf_feature, BtfFeature::DataSecZero),
            float: feature_probe!(probe_btf_feature, BtfFeature::Float),
            decl_tag: feature_probe!(probe_btf_feature, BtfFeature::DeclTag),
            type_tag: feature_probe!(probe_btf_feature, BtfFeature::TypeTag),
            enum64: feature_probe!(probe_btf_feature, BtfFeature::Enum64),
        }
    }

    fn is_supported(&self, feature: BtfFeature, token_fd: Option<BorrowedFd<'_>>) -> bool {
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
        capability.get(token_fd)
    }
}

pub(crate) static FEATURES: Features = Features::new(None);

fn probe_read_kernel_feature(token_fd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
    probe_helper(
        ProgramType::TracePoint,
        BpfHelper::BPF_FUNC_probe_read_kernel,
        token_fd,
    )
    .map_err(io::Error::other)
}

fn probe_bpf_cookie_feature(token_fd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
    probe_helper(
        ProgramType::KProbe,
        BpfHelper::BPF_FUNC_get_attach_cookie,
        token_fd,
    )
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

        let feature = FeatureProbe::new("test feature", |_token_fd| {
            PROBED.set(()).expect("feature probed more than once");
            Ok(true)
        });

        assert!(format!("{feature:?}").contains("<not yet probed>"));
        assert!(PROBED.get().is_none());

        assert!(feature.get(None));
        assert!(feature.get(None));
        assert!(PROBED.get().is_some());
    }

    #[test]
    fn feature_probe_errors_are_cached_and_treated_as_unsupported() {
        // FeatureProbe stores a function pointer, so the probe cannot capture a local call marker.
        static PROBED: OnceLock<()> = OnceLock::new();

        let feature = FeatureProbe::new("test feature", |_token_fd| {
            PROBED.set(()).expect("feature probed more than once");
            Err(io::Error::from_raw_os_error(libc::EIO))
        });

        assert!(!feature.get(None));
        assert!(!feature.get(None));
        assert!(PROBED.get().is_some());

        let error = io::Error::from_raw_os_error(libc::EIO);
        assert_eq!(format!("{feature:?}"), format!("Err({error:?})"));
    }
}
