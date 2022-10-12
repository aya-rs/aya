use core::ffi::c_void;

use aya_common::{
    UsdtArgType, UsdtSpec, USDT_MAX_ARG_COUNT, USDT_MAX_IP_COUNT, USDT_MAX_SPEC_COUNT,
};

use crate::{
    args::FromPtRegs,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_user},
    macros::map,
    maps::{Array, HashMap},
    BpfContext,
};

// aarch64 uses user_pt_regs instead of pt_regs
#[cfg(not(bpf_target_arch = "aarch64"))]
use crate::bindings::pt_regs;
#[cfg(bpf_target_arch = "aarch64")]
use crate::bindings::user_pt_regs as pt_regs;

#[map(name = "__bpf_usdt_specs")]
static USDT_SPECS: Array<UsdtSpec> = Array::with_max_entries(USDT_MAX_SPEC_COUNT, 0);

#[map(name = "__bpf_usdt_ip_to_spec_id")]
static USDT_IP_TO_SPEC_ID: HashMap<i64, u32> = HashMap::with_max_entries(USDT_MAX_IP_COUNT, 0);

pub struct UsdtContext {
    pub regs: *mut pt_regs,
}

/// Errors from Usdt map operations
#[derive(Debug, Clone)]
pub enum UsdtError {
    MaxArgCount,
    SpecIdNotFound,
    ValueError,
    IpNotFound,
}

impl UsdtContext {
    /// Creates a new Usdtcontext.
    pub fn new(ctx: *mut c_void) -> UsdtContext {
        UsdtContext {
            regs: ctx as *mut pt_regs,
        }
    }

    /// Access the register that holds the next instruction pointer.
    #[inline(always)]
    fn ip<T: FromPtRegs>(&self) -> Option<T> {
        T::from_ip(unsafe { &*self.regs })
    }

    /// Access the spec_id from the BPF Attach Cookie.
    #[cfg(feature = "cookie")]
    #[inline(always)]
    fn spec_id(&self) -> Result<u32, ()> {
        unsafe { Ok(aya_bpf_bindings::helpers::bpf_get_attach_cookie(self.as_ptr()) as u32) }
    }

    /// Access the spec_id using the `USDT_IP_TO_SPEC_ID` map
    #[cfg(not(feature = "cookie"))]
    #[inline(always)]
    fn spec_id(&self) -> Result<u32, UsdtError> {
        let ip: i64 = self.ip().ok_or(UsdtError::IpNotFound)?;
        let spec = unsafe {
            USDT_IP_TO_SPEC_ID
                .get(&ip)
                .ok_or(UsdtError::SpecIdNotFound)?
        };
        Ok(*spec)
    }

    /// Returns the value of the USDT argument `n` as a u64.
    ///
    /// This uses the USDT_SPEC_MAP to determine the correct specification to use in order
    /// to read the value of argument `n` from the eBPF Context.
    #[inline(always)]
    pub fn arg(&self, n: usize) -> Result<u64, UsdtError> {
        if n > USDT_MAX_ARG_COUNT {
            return Err(UsdtError::MaxArgCount);
        }
        let spec_id = self.spec_id()?;
        let spec = USDT_SPECS.get(spec_id).ok_or(UsdtError::SpecIdNotFound)?;

        if n > (spec.arg_count as usize) {
            return Err(UsdtError::MaxArgCount);
        }

        let arg_spec = &spec.args[n];
        let mut val = match arg_spec.arg_type {
            UsdtArgType::Const => arg_spec.val_off,
            UsdtArgType::Reg => unsafe {
                bpf_probe_read_kernel(self.as_ptr().offset(arg_spec.reg_off as isize) as *const _)
                    .map_err(|_| UsdtError::ValueError)?
            },
            UsdtArgType::RegDeref => unsafe {
                let ptr: u64 = bpf_probe_read_kernel(
                    self.as_ptr().offset(arg_spec.reg_off as isize) as *const _,
                )
                .map_err(|_| UsdtError::ValueError)?;
                let ptr = ptr as *const u64;
                bpf_probe_read_user::<u64>(ptr.offset(arg_spec.val_off as isize))
                    .map_err(|_| UsdtError::ValueError)?
                // TODO: libbpf applies a bitshift here if the arch is big endian
            },
        };

        // cast arg from 1, 2, or 4 bytes to final 8 byte size clearing
        // necessary upper arg_bitshift bits, with sign extension if argument
        // is signed
        val <<= arg_spec.arg_bitshift;
        if arg_spec.arg_signed {
            val = ((val as i64) >> arg_spec.arg_bitshift) as u64
        } else {
            val >>= arg_spec.arg_bitshift;
        }
        Ok(val)
    }
}

impl BpfContext for UsdtContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs as *mut c_void
    }
}
