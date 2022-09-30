use proc_macro::TokenStream;
use syn::parse_macro_input;

mod expand;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum LevelFilter {
    _Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

cfg_if::cfg_if! {
    if #[cfg(all(not(debug_assertions), feature = "release_max_level_off"))] {
        const MAX_LEVEL: LevelFilter = LevelFilter::_Off;
    } else if #[cfg(all(not(debug_assertions), feature = "release_max_level_error"))] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Error;
    } else if #[cfg(all(not(debug_assertions), feature = "release_max_level_warn"))] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Warn;
    } else if #[cfg(all(not(debug_assertions), feature = "release_max_level_info"))] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Info;
    } else if #[cfg(all(not(debug_assertions), feature = "release_max_level_debug"))] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Debug;
    } else if #[cfg(all(not(debug_assertions), feature = "release_max_level_trace"))] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Trace;
    } else if #[cfg(feature = "max_level_off")] {
        const MAX_LEVEL: LevelFilter = LevelFilter::_Off;
    } else if #[cfg(feature = "max_level_error")] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Error;
    } else if #[cfg(feature = "max_level_warn")] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Warn;
    } else if #[cfg(feature = "max_level_info")] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Info;
    } else if #[cfg(feature = "max_level_debug")] {
        const MAX_LEVEL: LevelFilter = LevelFilter::Debug;
    } else {
        const MAX_LEVEL: LevelFilter = LevelFilter::Trace;
    }
}

#[proc_macro]
pub fn log(args: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as expand::LogArgs);
    expand::log(args, None)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro]
pub fn error(args: TokenStream) -> TokenStream {
    if LevelFilter::Error > MAX_LEVEL {
        return TokenStream::new();
    }
    let args = parse_macro_input!(args as expand::LogArgs);
    expand::error(args)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro]
pub fn warn(args: TokenStream) -> TokenStream {
    if LevelFilter::Warn > MAX_LEVEL {
        return TokenStream::new();
    }
    let args = parse_macro_input!(args as expand::LogArgs);
    expand::warn(args)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro]
pub fn info(args: TokenStream) -> TokenStream {
    if LevelFilter::Info > MAX_LEVEL {
        return TokenStream::new();
    }
    let args = parse_macro_input!(args as expand::LogArgs);
    expand::info(args)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro]
pub fn debug(args: TokenStream) -> TokenStream {
    if LevelFilter::Debug > MAX_LEVEL {
        return TokenStream::new();
    }
    let args = parse_macro_input!(args as expand::LogArgs);
    expand::debug(args)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro]
pub fn trace(args: TokenStream) -> TokenStream {
    if LevelFilter::Trace > MAX_LEVEL {
        return TokenStream::new();
    }
    let args = parse_macro_input!(args as expand::LogArgs);
    expand::trace(args)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
