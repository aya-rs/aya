//! This module contains kernel helper functions that may be exposed to specific BPF
//! program types. These helpers can be used to perform common tasks, query and operate on
//! data exposed by the kernel, and perform some operations that would normally be denied
//! by the BPF verifier.
//!
//! Here, we provide some higher-level wrappers around the underlying kernel helpers, but
//! also expose bindings to the underlying helpers as a fall-back in case of a missing
//! implementation.

use core::mem::{self, MaybeUninit};

pub use aya_bpf_bindings::helpers as gen;
#[doc(hidden)]
pub use gen::*;

use crate::cty::{c_char, c_long, c_void};

/// Read bytes stored at `src` and store them as a `T`.
///
/// Generally speaking, the more specific [`bpf_probe_read_user`] and
/// [`bpf_probe_read_kernel`] should be preferred over this function.
///
/// Returns a bitwise copy of `mem::size_of::<T>()` bytes stored at the user space address
/// `src`. See `bpf_probe_read_kernel` for  reading kernel space memory.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::{c_int, c_long}, helpers::bpf_probe_read};
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const c_int = 0 as _;
/// let my_int: c_int = unsafe { bpf_probe_read(kernel_ptr)? };
///
/// // Do something with my_int
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub unsafe fn bpf_probe_read<T>(src: *const T) -> Result<T, c_long> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    let ret = gen::bpf_probe_read(
        v.as_mut_ptr() as *mut c_void,
        mem::size_of::<T>() as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(v.assume_init())
    } else {
        Err(ret)
    }
}

/// Read bytes from the pointer `src` into the provided destination buffer.
///
/// Generally speaking, the more specific [`bpf_probe_read_user_buf`] and
/// [`bpf_probe_read_kernel_buf`] should be preferred over this function.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::{c_int, c_long}, helpers::bpf_probe_read_buf};
/// # fn try_test() -> Result<(), c_long> {
/// # let ptr: *const u8 = 0 as _;
/// let mut buf = [0u8; 16];
/// unsafe { bpf_probe_read_buf(ptr, &mut buf)? };
///
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub unsafe fn bpf_probe_read_buf(src: *const u8, dst: &mut [u8]) -> Result<(), c_long> {
    let ret = gen::bpf_probe_read(
        dst.as_mut_ptr() as *mut c_void,
        dst.len() as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Read bytes stored at the _user space_ pointer `src` and store them as a `T`.
///
/// Returns a bitwise copy of `mem::size_of::<T>()` bytes stored at the user space address
/// `src`. See `bpf_probe_read_kernel` for  reading kernel space memory.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::{c_int, c_long}, helpers::bpf_probe_read_user};
/// # fn try_test() -> Result<(), c_long> {
/// # let user_ptr: *const c_int = 0 as _;
/// let my_int: c_int = unsafe { bpf_probe_read_user(user_ptr)? };
///
/// // Do something with my_int
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub unsafe fn bpf_probe_read_user<T>(src: *const T) -> Result<T, c_long> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    let ret = gen::bpf_probe_read_user(
        v.as_mut_ptr() as *mut c_void,
        mem::size_of::<T>() as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(v.assume_init())
    } else {
        Err(ret)
    }
}

/// Read bytes from the _user space_ pointer `src` into the provided destination
/// buffer.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::{c_int, c_long}, helpers::bpf_probe_read_user_buf};
/// # fn try_test() -> Result<(), c_long> {
/// # let user_ptr: *const u8 = 0 as _;
/// let mut buf = [0u8; 16];
/// unsafe { bpf_probe_read_user_buf(user_ptr, &mut buf)? };
///
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub unsafe fn bpf_probe_read_user_buf(src: *const u8, dst: &mut [u8]) -> Result<(), c_long> {
    let ret = gen::bpf_probe_read_user(
        dst.as_mut_ptr() as *mut c_void,
        dst.len() as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Read bytes stored at the _kernel space_ pointer `src` and store them as a `T`.
///
/// Returns a bitwise copy of `mem::size_of::<T>()` bytes stored at the kernel space address
/// `src`. See `bpf_probe_read_user` for  reading user space memory.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::{c_int, c_long}, helpers::bpf_probe_read_kernel};
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const c_int = 0 as _;
/// let my_int: c_int = unsafe { bpf_probe_read_kernel(kernel_ptr)? };
///
/// // Do something with my_int
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub unsafe fn bpf_probe_read_kernel<T>(src: *const T) -> Result<T, c_long> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    let ret = gen::bpf_probe_read_kernel(
        v.as_mut_ptr() as *mut c_void,
        mem::size_of::<T>() as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(v.assume_init())
    } else {
        Err(ret)
    }
}

/// Read bytes from the _kernel space_ pointer `src` into the provided destination
/// buffer.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::{c_int, c_long}, helpers::bpf_probe_read_kernel_buf};
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const u8 = 0 as _;
/// let mut buf = [0u8; 16];
/// unsafe { bpf_probe_read_kernel_buf(kernel_ptr, &mut buf)? };
///
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub unsafe fn bpf_probe_read_kernel_buf(src: *const u8, dst: &mut [u8]) -> Result<(), c_long> {
    let ret = gen::bpf_probe_read_kernel(
        dst.as_mut_ptr() as *mut c_void,
        dst.len() as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Read a null-terminated string stored at `src` into `dest`.
///
/// Generally speaking, the more specific [`bpf_probe_read_user_str`] and
/// [`bpf_probe_read_kernel_str`] should be preferred over this function.
///
/// In case the length of `dest` is smaller then the length of `src`, the read bytes will
/// be truncated to the size of `dest`.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_str};
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const u8 = 0 as _;
/// let mut my_str = [0u8; 16];
/// let num_read = unsafe { bpf_probe_read_str(kernel_ptr, &mut my_str)? };
///
/// // Do something with num_read and my_str
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns Err(-1).
#[deprecated(
    note = "Use `bpf_probe_read_user_str_bytes` or `bpf_probe_read_kernel_str_bytes` instead"
)]
#[inline]
pub unsafe fn bpf_probe_read_str(src: *const u8, dest: &mut [u8]) -> Result<usize, c_long> {
    let len = gen::bpf_probe_read_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let mut len = len as usize;
    if len > dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        len = dest.len();
    }
    Ok(len)
}

/// Read a null-terminated string from _user space_ stored at `src` into `dest`.
///
/// In case the length of `dest` is smaller then the length of `src`, the read bytes will
/// be truncated to the size of `dest`.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_user_str};
/// # fn try_test() -> Result<(), c_long> {
/// # let user_ptr: *const u8 = 0 as _;
/// let mut my_str = [0u8; 16];
/// let num_read = unsafe { bpf_probe_read_user_str(user_ptr, &mut my_str)? };
///
/// // Do something with num_read and my_str
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns Err(-1).
#[deprecated(note = "Use `bpf_probe_read_user_str_bytes` instead")]
#[inline]
pub unsafe fn bpf_probe_read_user_str(src: *const u8, dest: &mut [u8]) -> Result<usize, c_long> {
    let len = gen::bpf_probe_read_user_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let mut len = len as usize;
    if len > dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        len = dest.len();
    }
    Ok(len)
}

/// Returns a byte slice read from _user space_ address `src`.
///
/// Reads at most `dest.len()` bytes from the `src` address, truncating if the
/// length of the source string is larger than `dest`. On success, the
/// destination buffer is always null terminated, and the returned slice
/// includes the bytes up to and not including NULL.
///
/// # Examples
///
/// With an array allocated on the stack (not recommended for bigger strings,
/// eBPF stack limit is 512 bytes):
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_user_str_bytes};
/// # fn try_test() -> Result<(), c_long> {
/// # let user_ptr: *const u8 = 0 as _;
/// let mut buf = [0u8; 16];
/// let my_str_bytes = unsafe { bpf_probe_read_user_str_bytes(user_ptr, &mut buf)? };
///
/// // Do something with my_str_bytes
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// With a `PerCpuArray` (with size defined by us):
///
/// ```no_run
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_user_str_bytes};
/// use aya_bpf::{macros::map, maps::PerCpuArray};
///
/// #[repr(C)]
/// pub struct Buf {
///     pub buf: [u8; 4096],
/// }
///
/// #[map]
/// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
///
/// # fn try_test() -> Result<(), c_long> {
/// # let user_ptr: *const u8 = 0 as _;
/// let buf = unsafe {
///     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
///     &mut *ptr
/// };
/// let my_str_bytes = unsafe { bpf_probe_read_user_str_bytes(user_ptr, &mut buf.buf)? };
///
/// // Do something with my_str_bytes
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// You can also convert the resulted bytes slice into `&str` using
/// [core::str::from_utf8_unchecked]:
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_user_str_bytes};
/// # use aya_bpf::{macros::map, maps::PerCpuArray};
/// # #[repr(C)]
/// # pub struct Buf {
/// #     pub buf: [u8; 4096],
/// # }
/// # #[map]
/// # pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
/// # fn try_test() -> Result<(), c_long> {
/// # let user_ptr: *const u8 = 0 as _;
/// # let buf = unsafe {
/// #     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
/// #     &mut *ptr
/// # };
/// let my_str = unsafe {
///     core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(user_ptr, &mut buf.buf)?)
/// };
///
/// // Do something with my_str
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns Err(-1).
#[inline]
pub unsafe fn bpf_probe_read_user_str_bytes(
    src: *const u8,
    dest: &mut [u8],
) -> Result<&[u8], c_long> {
    let len = gen::bpf_probe_read_user_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let len = len as usize;
    if len >= dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        return Err(-1);
    }

    Ok(&dest[..len])
}

/// Read a null-terminated string from _kernel space_ stored at `src` into `dest`.
///
/// In case the length of `dest` is smaller then the length of `src`, the read bytes will
/// be truncated to the size of `dest`.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_kernel_str};
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const u8 = 0 as _;
/// let mut my_str = [0u8; 16];
/// let num_read = unsafe { bpf_probe_read_kernel_str(kernel_ptr, &mut my_str)? };
///
/// // Do something with num_read and my_str
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns Err(-1).
#[deprecated(note = "Use bpf_probe_read_kernel_str_bytes instead")]
#[inline]
pub unsafe fn bpf_probe_read_kernel_str(src: *const u8, dest: &mut [u8]) -> Result<usize, c_long> {
    let len = gen::bpf_probe_read_kernel_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let mut len = len as usize;
    if len > dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        len = dest.len();
    }
    Ok(len)
}

/// Returns a byte slice read from _kernel space_ address `src`.
///
/// Reads at most `dest.len()` bytes from the `src` address, truncating if the
/// length of the source string is larger than `dest`. On success, the
/// destination buffer is always null terminated, and the returned slice
/// includes the bytes up to and not including NULL.
///
/// # Examples
///
/// With an array allocated on the stack (not recommended for bigger strings,
/// eBPF stack limit is 512 bytes):
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_kernel_str_bytes};
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const u8 = 0 as _;
/// let mut buf = [0u8; 16];
/// let my_str_bytes = unsafe { bpf_probe_read_kernel_str_bytes(kernel_ptr, &mut buf)? };
///
/// // Do something with my_str_bytes
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// With a `PerCpuArray` (with size defined by us):
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_kernel_str_bytes};
/// use aya_bpf::{macros::map, maps::PerCpuArray};
///
/// #[repr(C)]
/// pub struct Buf {
///     pub buf: [u8; 4096],
/// }
///
/// #[map]
/// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
///
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const u8 = 0 as _;
/// let buf = unsafe {
///     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
///     &mut *ptr
/// };
/// let my_str_bytes = unsafe { bpf_probe_read_kernel_str_bytes(kernel_ptr, &mut buf.buf)? };
///
/// // Do something with my_str_bytes
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// You can also convert the resulted bytes slice into `&str` using
/// [core::str::from_utf8_unchecked]:
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{cty::c_long, helpers::bpf_probe_read_kernel_str_bytes};
/// # use aya_bpf::{macros::map, maps::PerCpuArray};
/// # #[repr(C)]
/// # pub struct Buf {
/// #     pub buf: [u8; 4096],
/// # }
/// # #[map]
/// # pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
/// # fn try_test() -> Result<(), c_long> {
/// # let kernel_ptr: *const u8 = 0 as _;
/// # let buf = unsafe {
/// #     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
/// #     &mut *ptr
/// # };
/// let my_str = unsafe {
///     core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(kernel_ptr, &mut buf.buf)?)
/// };
///
/// // Do something with my_str
/// # Ok::<(), c_long>(())
/// # }
/// ```
///
/// # Errors
///
/// On failure, this function returns Err(-1).
#[inline]
pub unsafe fn bpf_probe_read_kernel_str_bytes(
    src: *const u8,
    dest: &mut [u8],
) -> Result<&[u8], c_long> {
    let len = gen::bpf_probe_read_kernel_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let len = len as usize;
    if len >= dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        return Err(-1);
    }

    Ok(&dest[..len])
}

/// Write bytes to the _user space_ pointer `src` and store them as a `T`.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::{
/// #     cty::{c_int, c_long},
/// #     helpers::bpf_probe_write_user,
/// #     programs::ProbeContext,
/// # };
/// fn try_test(ctx: ProbeContext) -> Result<(), c_long> {
///     let retp: *mut c_int = ctx.arg(0).ok_or(1)?;
///     let val: i32 = 1;
///     // Write the value to the userspace pointer.
///     unsafe { bpf_probe_write_user(retp, &val as *const i32)? };
///
///     Ok::<(), c_long>(())
/// }
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[allow(clippy::fn_to_numeric_cast_with_truncation)]
#[inline]
pub unsafe fn bpf_probe_write_user<T>(dst: *mut T, src: *const T) -> Result<(), c_long> {
    let ret = gen::bpf_probe_write_user(
        dst as *mut c_void,
        src as *const c_void,
        mem::size_of::<T>() as u32,
    );
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

/// Read the `comm` field associated with the current task struct
/// as a `[u8; 16]`.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::helpers::bpf_get_current_comm;
/// let comm = bpf_get_current_comm();
///
/// // Do something with comm
/// ```
///
/// # Errors
///
/// On failure, this function returns a negative value wrapped in an `Err`.
#[inline]
pub fn bpf_get_current_comm() -> Result<[u8; 16], c_long> {
    let mut comm: [u8; 16usize] = [0; 16];
    let ret = unsafe { gen::bpf_get_current_comm(&mut comm as *mut _ as *mut c_void, 16u32) };
    if ret == 0 {
        Ok(comm)
    } else {
        Err(ret)
    }
}

/// Read the process id and thread group id associated with the current task struct as
/// a `u64`.
///
/// In the return value, the upper 32 bits are the `tgid`, and the lower 32 bits are the
/// `pid`. That is, the returned value is equal to: `(tgid << 32) | pid`. A caller may
/// access the individual fields by either casting to a `u32` or performing a `>> 32` bit
/// shift and casting to a `u32`.
///
/// Note that the naming conventions used in the kernel differ from user space. From the
/// perspective of user space, `pid` may be thought of as the thread id, and `tgid` may be
/// thought of as the process id. For single-threaded processes, these values are
/// typically the same.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::helpers::bpf_get_current_pid_tgid;
/// let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
/// let pid = bpf_get_current_pid_tgid() as u32;
///
/// // Do something with pid and tgid
/// ```
#[inline]
pub fn bpf_get_current_pid_tgid() -> u64 {
    unsafe { gen::bpf_get_current_pid_tgid() }
}

/// Read the user id and group id associated with the current task struct as
/// a `u64`.
///
/// In the return value, the upper 32 bits are the `gid`, and the lower 32 bits are the
/// `uid`. That is, the returned value is equal to: `(gid << 32) | uid`. A caller may
/// access the individual fields by either casting to a `u32` or performing a `>> 32` bit
/// shift and casting to a `u32`.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// # use aya_bpf::helpers::bpf_get_current_uid_gid;
/// let gid = (bpf_get_current_uid_gid() >> 32) as u32;
/// let uid = bpf_get_current_uid_gid() as u32;
///
/// // Do something with uid and gid
/// ```
#[inline]
pub fn bpf_get_current_uid_gid() -> u64 {
    unsafe { gen::bpf_get_current_uid_gid() }
}

/// Prints a debug message to the BPF debugging pipe.
///
/// The [format string syntax][fmt] is the same as that of the `printk` kernel
/// function. It is passed in as a fixed-size byte array (`&[u8; N]`), so you
/// will have to prefix your string literal with a `b`. A terminating zero byte
/// is appended automatically.
///
/// The macro can read from arbitrary pointers, so it must be used in an `unsafe`
/// scope in order to compile.
///
/// Invocations with less than 4 arguments call the `bpf_trace_printk` helper,
/// otherwise the `bpf_trace_vprintk` function is called. The latter function
/// requires a kernel version >= 5.16 whereas the former has been around since
/// the dawn of eBPF. The return value of the BPF helper is also returned from
/// this macro.
///
/// Messages can be read by executing the following command in a second terminal:
///
/// ```bash
/// sudo cat /sys/kernel/debug/tracing/trace_pipe
/// ```
///
/// If no messages are printed when calling [`bpf_printk!`] after executing the
/// above command, it is possible that tracing must first be enabled by running:
///
/// ```bash
/// echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
/// ```
///
/// # Example
///
/// ```no_run
/// # use aya_bpf::helpers::bpf_printk;
/// unsafe {
///   bpf_printk!(b"hi there! dec: %d, hex: 0x%08X", 42, 0x1234);
/// }
/// ```
///
/// [fmt]: https://www.kernel.org/doc/html/latest/core-api/printk-formats.html#printk-specifiers
#[macro_export]
macro_rules! bpf_printk {
    ($fmt:literal $(,)? $($arg:expr),* $(,)?) => {{
        use $crate::helpers::PrintkArg;
        const FMT: [u8; { $fmt.len() + 1 }] = $crate::helpers::zero_pad_array::<
            { $fmt.len() }, { $fmt.len() + 1 }>(*$fmt);
        let data = [$(PrintkArg::from($arg)),*];
        $crate::helpers::bpf_printk_impl(&FMT, &data)
    }};
}

// Macros are always exported from the crate root. Also export it from `helpers`.
#[doc(inline)]
pub use bpf_printk;

/// Argument ready to be passed to `printk` BPF helper.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct PrintkArg(u64);

impl PrintkArg {
    /// Manually construct a `printk` BPF helper argument.
    #[inline]
    pub fn from_raw(x: u64) -> Self {
        Self(x)
    }
}

macro_rules! impl_integer_promotion {
    ($($ty:ty : via $via:ty),* $(,)?) => {$(
        /// Create `printk` arguments from integer types.
        impl From<$ty> for PrintkArg {
            #[inline]
            fn from(x: $ty) -> PrintkArg {
                PrintkArg(x as $via as u64)
            }
        }
    )*}
}

impl_integer_promotion!(
  char:  via u64,
  u8:    via u64,
  u16:   via u64,
  u32:   via u64,
  u64:   via u64,
  usize: via u64,
  i8:    via i64,
  i16:   via i64,
  i32:   via i64,
  i64:   via i64,
  isize: via i64,
);

/// Construct `printk` BPF helper arguments from constant pointers.
impl<T> From<*const T> for PrintkArg {
    #[inline]
    fn from(x: *const T) -> Self {
        PrintkArg(x as usize as u64)
    }
}

/// Construct `printk` BPF helper arguments from mutable pointers.
impl<T> From<*mut T> for PrintkArg {
    #[inline]
    fn from(x: *mut T) -> Self {
        PrintkArg(x as usize as u64)
    }
}

/// Expands the given byte array to `DST_LEN`, right-padding it with zeros. If
/// `DST_LEN` is smaller than `SRC_LEN`, the array is instead truncated.
///
/// This function serves as a helper for the [`bpf_printk!`] macro.
#[doc(hidden)]
pub const fn zero_pad_array<const SRC_LEN: usize, const DST_LEN: usize>(
    src: [u8; SRC_LEN],
) -> [u8; DST_LEN] {
    let mut out: [u8; DST_LEN] = [0u8; DST_LEN];

    // The `min` function is not `const`. Hand-roll it.
    let mut i = if DST_LEN > SRC_LEN { SRC_LEN } else { DST_LEN };

    while i > 0 {
        i -= 1;
        out[i] = src[i];
    }

    out
}

/// Internal helper function for the [`bpf_printk!`] macro.
///
/// The BPF helpers require the length for both the format string as well as
/// the argument array to be of constant size to pass the verifier. Const
/// generics are used to represent this requirement in Rust.
#[inline]
#[doc(hidden)]
pub unsafe fn bpf_printk_impl<const FMT_LEN: usize, const NUM_ARGS: usize>(
    fmt: &[u8; FMT_LEN],
    args: &[PrintkArg; NUM_ARGS],
) -> i64 {
    // This function can't be wrapped in `helpers.rs` because it has variadic
    // arguments. We also can't turn the definitions in `helpers.rs` into
    // `const`s because MIRI believes casting arbitrary integers to function
    // pointers to be an error.
    let printk: unsafe extern "C" fn(fmt: *const c_char, fmt_size: u32, ...) -> c_long =
        mem::transmute(6usize);

    let fmt_ptr = fmt.as_ptr() as *const c_char;
    let fmt_size = fmt.len() as u32;

    match NUM_ARGS {
        0 => printk(fmt_ptr, fmt_size),
        1 => printk(fmt_ptr, fmt_size, args[0]),
        2 => printk(fmt_ptr, fmt_size, args[0], args[1]),
        3 => printk(fmt_ptr, fmt_size, args[0], args[1], args[2]),
        _ => gen::bpf_trace_vprintk(fmt_ptr, fmt_size, args.as_ptr() as _, (NUM_ARGS * 8) as _),
    }
}
