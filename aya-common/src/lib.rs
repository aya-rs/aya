#![no_std]

pub const USDT_MAX_SPEC_COUNT: u32 = 256;
pub const USDT_MAX_IP_COUNT: u32 = 4 * USDT_MAX_SPEC_COUNT;
pub const USDT_MAX_ARG_COUNT: usize = 12;

/// The type of argument in a USDT program.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Debug))]
pub enum UsdtArgType {
    /// Value is Constant.
    Const,
    /// Value is stored in a Register.
    Reg,
    /// Value is stored in a Register and requires dereferencing.
    RegDeref,
}

impl Default for UsdtArgType {
    fn default() -> Self {
        UsdtArgType::Const
    }
}

/// The specifcation of an argument in a USDT program.
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct UsdtArgSpec {
    /// Meaning of val_off differs based on `arg_type`.
    /// If Constant, this holds the scalar value of unknow type, up to u64 in size.
    /// If RegDeref, this contains an offset which is an i64.
    pub val_off: u64,
    /// Type of Argument.
    pub arg_type: UsdtArgType,
    /// Offset of the register within the BPF context
    pub reg_off: i16,
    /// Whether the value should be interpreted as signed
    pub arg_signed: bool,
    /// Number of bits that need to be cleared and, optionally,
    /// sign-extended to cast arguments that are 1, 2, or 4 bytes
    /// long into final 8-byte u64/s64 value returned to user.
    pub arg_bitshift: i8,
}

/// The specification of a USDT
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct UsdtSpec {
    /// Specification used to access arguments.
    pub args: [UsdtArgSpec; USDT_MAX_ARG_COUNT],
    /// User supplied cookie since the BPF Attach Cookie is used internally.
    pub cookie: u64,
    /// Number of args in this tracepoint
    pub arg_count: i16,
}

#[cfg(feature = "user")]
mod generated;

#[cfg(feature = "user")]
extern crate std;
#[cfg(feature = "user")]
pub mod with_std {
    use crate::{UsdtArgSpec, UsdtArgType, UsdtSpec, USDT_MAX_ARG_COUNT};
    use lazy_static::lazy_static;
    use regex::Regex;
    use std::{format, string::String};
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum ParseError {
        #[error("error parsing usdt arg spec: {0}")]
        UsdtArgSpecError(String),
        #[error("error parsing usdt spec: {0}")]
        UsdtSpecError(String),
    }

    lazy_static! {
        static ref USDT_REGEX: Regex =
            Regex::new(r"^(-?[0-9]+)@((-?[0-9]+)\(%(.*)\)|%(.*)|\$([0-9]+))$").unwrap();
    }

    impl std::str::FromStr for UsdtArgSpec {
        type Err = ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut spec = UsdtArgSpec::default();
            let caps = USDT_REGEX.captures(s).unwrap();

            if caps.len() != 7 {
                return Err(ParseError::UsdtArgSpecError(format!(
                    "could not parse {}",
                    s
                )));
            }
            let mut arg_size: isize = caps.get(1).unwrap().as_str().parse().unwrap();
            if caps.get(3).is_some() && caps.get(4).is_some() {
                spec.arg_type = UsdtArgType::RegDeref;
                spec.val_off = caps.get(3).unwrap().as_str().parse::<i64>().map_err(|e| {
                    ParseError::UsdtArgSpecError(format!("could not parse {}: {}", s, e))
                })? as u64;
                spec.reg_off = calc_pt_regs_offset(caps.get(4).unwrap().as_str())?;
            } else if caps.get(5).is_some() {
                spec.arg_type = UsdtArgType::Reg;
                spec.reg_off = calc_pt_regs_offset(caps.get(5).unwrap().as_str())?;
            } else if caps.get(6).is_some() {
                spec.arg_type = UsdtArgType::Const;
                spec.val_off = caps.get(6).unwrap().as_str().parse::<i64>().map_err(|e| {
                    ParseError::UsdtArgSpecError(format!("could not parse {}: {}", s, e))
                })? as u64;
            }
            if arg_size < 0 {
                spec.arg_signed = true;
                arg_size = -arg_size;
            }
            match arg_size {
                1 | 2 | 4 | 8 => spec.arg_bitshift = (arg_size * 8) as i8,
                _ => {
                    return Err(ParseError::UsdtArgSpecError(format!(
                        "arg size was not 1,2,4,8: {}",
                        s
                    )))
                }
            }
            Ok(spec)
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn calc_pt_regs_offset(reg: &str) -> Result<i16, ParseError> {
        use crate::generated::pt_regs;
        use memoffset::offset_of;
        match reg {
            "rip" | "eip" => Ok(offset_of!(pt_regs, rip) as i16),
            "rax" | "eax" | "ax" | "al" => Ok(offset_of!(pt_regs, rax) as i16),
            "rbx" | "ebx" | "bx" | "bl" => Ok(offset_of!(pt_regs, rbx) as i16),
            "rcx" | "ecx" | "cx" | "cl" => Ok(offset_of!(pt_regs, rcx) as i16),
            "rdx" | "edx" | "dx" | "dl" => Ok(offset_of!(pt_regs, rdx) as i16),
            "rsi" | "esi" | "si" | "sil" => Ok(offset_of!(pt_regs, rsi) as i16),
            "rdi" | "edi" | "di" | "dil" => Ok(offset_of!(pt_regs, rdi) as i16),
            "rbp" | "ebp" | "bp" | "bpl" => Ok(offset_of!(pt_regs, rbp) as i16),
            "rsp" | "esp" | "sp" | "bsl" => Ok(offset_of!(pt_regs, rsp) as i16),
            "r8" | "r8d" | "r8w" | "r8b" => Ok(offset_of!(pt_regs, r8) as i16),
            "r9" | "r9d" | "r9w" | "r9b" => Ok(offset_of!(pt_regs, r9) as i16),
            "r10" | "r10d" | "r10w" | "r10b" => Ok(offset_of!(pt_regs, r10) as i16),
            "r11" | "r11d" | "r11w" | "r11b" => Ok(offset_of!(pt_regs, r11) as i16),
            "r12" | "r12d" | "r12w" | "r12b" => Ok(offset_of!(pt_regs, r12) as i16),
            "r13" | "r13d" | "r13w" | "r13b" => Ok(offset_of!(pt_regs, r13) as i16),
            "r14" | "r14d" | "r14w" | "r14b" => Ok(offset_of!(pt_regs, r14) as i16),
            "r15" | "r15d" | "r15w" | "r15b" => Ok(offset_of!(pt_regs, r15) as i16),
            _ => Err(ParseError::UsdtArgSpecError(format!(
                "unknown register: {}",
                reg
            ))),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn calc_pt_regs_offset(reg: &str) -> Result<i16, ParseError> {
        use crate::generated::user_pt_regs;
        use memoffset::offset_of;
        use std::mem;
        match reg {
            r if r.starts_with('x') => {
                let n: usize = r.strip_prefix('x').unwrap().parse().unwrap();
                Ok((offset_of!(user_pt_regs, regs) + (mem::size_of::<u64>() * n)) as i16)
            }
            "sp" => Ok(offset_of!(user_pt_regs, sp) as i16),
            _ => Err(ParseError::UsdtArgSpecError(format!(
                "unknown register: {}",
                reg
            ))),
        }
    }

    #[cfg(target_arch = "arm")]
    fn calc_pt_regs_offset(reg: &str) -> Result<i16, ParseError> {
        use crate::generated::pt_regs;
        use memoffset::offset_of;
        use std::mem;
        match reg {
            // TODO: This assumes the notation is the same as aarch64
            // This needs testing and potentially updating
            r if r.starts_with('x') => {
                let n: usize = r.strip_prefix('x').unwrap().parse().unwrap();
                Ok(
                    (offset_of!(pt_regs, uregs) + (mem::size_of::<std::os::raw::c_long>() * n))
                        as i16,
                )
            }
            _ => Err(ParseError::UsdtArgSpecError(format!(
                "unknown register: {}",
                reg
            ))),
        }
    }

    impl std::str::FromStr for UsdtSpec {
        type Err = ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            use std::vec::Vec;
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() > USDT_MAX_ARG_COUNT {
                return Err(ParseError::UsdtSpecError(format!("too many args: {}", s)));
            }
            let mut args = parts
                .iter()
                .map(|s| s.parse::<UsdtArgSpec>().unwrap())
                .collect::<Vec<UsdtArgSpec>>();
            let arg_count = args.len() as i16;
            args.resize(USDT_MAX_ARG_COUNT, UsdtArgSpec::default());
            Ok(UsdtSpec {
                args: args.try_into().unwrap(),
                cookie: 0,
                arg_count,
            })
        }
    }

    #[cfg(all(target_arch = "x86_64", test))]
    mod test {
        use super::*;
        use memoffset::offset_of;

        #[test]
        fn test_parse_specs() {
            use crate::generated::pt_regs;

            let s = "-8@%rax -8@%rcx";
            let res: UsdtSpec = s.parse().unwrap();
            assert_eq!(res.arg_count, 2);
            assert_eq!(
                res.args[0],
                UsdtArgSpec {
                    val_off: 0,
                    arg_type: UsdtArgType::Reg,
                    reg_off: offset_of!(pt_regs, rax) as i16,
                    arg_signed: true,
                    arg_bitshift: 64
                }
            );
            assert_eq!(
                res.args[1],
                UsdtArgSpec {
                    val_off: 0,
                    arg_type: UsdtArgType::Reg,
                    reg_off: offset_of!(pt_regs, rcx) as i16,
                    arg_signed: true,
                    arg_bitshift: 64
                }
            );
        }

        #[test]
        fn test_parse_args() {
            use crate::generated::pt_regs;

            assert_eq!(
                "-4@-1204(%rbp)".parse::<UsdtArgSpec>().unwrap(),
                UsdtArgSpec {
                    val_off: -1204i64 as u64,
                    arg_type: UsdtArgType::RegDeref,
                    reg_off: offset_of!(pt_regs, rbp) as i16,
                    arg_signed: true,
                    arg_bitshift: 32
                }
            );

            assert_eq!(
                "-4@%edi".parse::<UsdtArgSpec>().unwrap(),
                UsdtArgSpec {
                    val_off: 0,
                    arg_type: UsdtArgType::Reg,
                    reg_off: offset_of!(pt_regs, rdi) as i16,
                    arg_signed: true,
                    arg_bitshift: 32
                }
            );

            assert_eq!(
                "-4@$5".parse::<UsdtArgSpec>().unwrap(),
                UsdtArgSpec {
                    val_off: 5,
                    arg_type: UsdtArgType::Const,
                    reg_off: 0,
                    arg_signed: true,
                    arg_bitshift: 32
                }
            );
        }
    }
}
