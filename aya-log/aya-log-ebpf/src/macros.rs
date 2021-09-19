/// Logs a message at the error level.
///
/// # Examples
///
/// ```no_run
/// # let ctx = ();
/// # let err_code = -1;
/// use aya_log_ebpf::error;
///
/// error!(&ctx, "Error redirecting packet: {}", err_code);
/// error!(&ctx, target: "ingress", "Error redirecting packet: {}", err_code);
/// ```
#[macro_export]
macro_rules! error {
    ($ctx:expr, target: $target:expr, $($arg:tt)+) => (
        $crate::log!($ctx, target: $target, $crate::Level::Error, $($arg)+)
    );
    ($ctx:expr, $($arg:tt)+) => (
        $crate::log!($ctx, $crate::Level::Error, $($arg)+)
    )
}

/// Logs a message at the warn level.
///
/// # Examples
///
/// ```
/// use aya_log_ebpf::warn;
///
/// # fn main() {
/// let warn_description = "Invalid Input";
///
/// warn!("Warning! {}!", warn_description);
/// warn!(target: "input_events", "App received warning: {}", warn_description);
/// # }
/// ```
#[macro_export]
macro_rules! warn {
    ($ctx:expr, target: $target:expr, $($arg:tt)+) => (
        $crate::log!($ctx, target: $target, $crate::Level::Warn, $($arg)+)
    );
    ($ctx:expr, $($arg:tt)+) => (
        $crate::log!($ctx, $crate::Level::Warn, $($arg)+)
    )
}

/// Logs a message at the info level.
///
/// # Examples
///
/// ```edition2018
/// use log::info;
///
/// # fn main() {
/// # struct Connection { port: u32, speed: u32 }
/// let conn_info = Connection { port: 40, speed: 3 };
///
/// info!("Connected to port {} at {} Mb/s", conn_info.port, conn_info.speed);
/// info!(target: "connection_events", "Successfull connection, port: {}, speed: {}",
///       conn_info.port, conn_info.speed);
/// # }
/// ```
#[macro_export]
macro_rules! info {
    ($ctx:expr, target: $target:expr, $($arg:tt)+) => (
        $crate::log!($ctx, target: $target, $crate::Level::Info, $($arg)+)
    );
    ($ctx:expr, $($arg:tt)+) => (
        $crate::log!($ctx, $crate::Level::Info, $($arg)+)
    )
}

/// Logs a message at the debug level.
///
/// # Examples
///
/// ```edition2018
/// use log::debug;
///
/// # fn main() {
/// # struct Position { x: i64, y: i64 }
/// let pos = Position { x: 3.234, y: -1223 };
///
/// debug!("New position: x: {}, y: {}", pos.x, pos.y);
/// debug!(target: "app_events", "New position: x: {}, y: {}", pos.x, pos.y);
/// # }
/// ```
#[macro_export]
macro_rules! debug {
    ($ctx:expr, target: $target:expr, $($arg:tt)+) => (
        $crate::log!($ctx, target: $target, $crate::Level::Debug, $($arg)+)
    );
    ($ctx:expr, $($arg:tt)+) => (
        $crate::log!($ctx, $crate::Level::Debug, $($arg)+)
    )
}

/// Logs a message at the trace level.
///
/// # Examples
///
/// ```edition2018
/// use log::trace;
///
/// # fn main() {
/// # struct Position { x: i64, y: i64 }
/// let pos = Position { x: 3234, y: -1223 };
///
/// trace!("Position is: x: {}, y: {}", pos.x, pos.y);
/// trace!(target: "app_events", "x is {} and y is {}",
///        if pos.x >= 0 { "positive" } else { "negative" },
///        if pos.y >= 0 { "positive" } else { "negative" });
/// # }
/// ```
#[macro_export]
macro_rules! trace {
    ($ctx:expr, target: $target:expr, $($arg:tt)+) => (
        $crate::log!($ctx, target: $target, $crate::Level::Trace, $($arg)+)
    );
    ($ctx:expr, $($arg:tt)+) => (
        $crate::log!($ctx, $crate::Level::Trace, $($arg)+)
    )
}

// /// Determines if a message logged at the specified level in that module will
// /// be logged.
// ///
// /// This can be used to avoid expensive computation of log message arguments if
// /// the message would be ignored anyway.
// ///
// /// # Examples
// ///
// /// ```edition2018
// /// use log::Level::Debug;
// /// use log::{debug, log_enabled};
// ///
// /// # fn foo() {
// /// if log_enabled!(Debug) {
// ///     let data = expensive_call();
// ///     debug!("expensive debug data: {} {}", data.x, data.y);
// /// }
// /// if log_enabled!(target: "Global", Debug) {
// ///    let data = expensive_call();
// ///    debug!(target: "Global", "expensive debug data: {} {}", data.x, data.y);
// /// }
// /// # }
// /// # struct Data { x: u32, y: u32 }
// /// # fn expensive_call() -> Data { Data { x: 0, y: 0 } }
// /// # fn main() {}
// /// ```
// macro_rules! log_enabled {
//     (target: $target:expr, $lvl:expr) => {{
//         let lvl = $lvl;
//         lvl <= $crate::STATIC_MAX_LEVEL
//     }};
//     ($lvl:expr) => {
//         log_enabled!(target: __log_module_path!(), $lvl)
//     };
// }

/// Log a message at the given level.
///
/// This macro will generically log with the specified `Level` and `format!`
/// based argument list.
///
/// # Examples
///
/// ```edition2018
/// use log::{log, Level};
///
/// # fn main() {
/// let data = (42, "Forty-two");
/// let private_data = "private";
///
/// log!(Level::Error, "Received errors: {}, {}", data.0, data.1);
/// log!(target: "app_events", Level::Warn, "App warning: {}, {}, {}",
///     data.0, data.1, private_data);
/// # }
/// ```
#[macro_export]
macro_rules! log {
    ($ctx:expr, target: $target:expr, $lvl:expr, $($arg:tt)+) => ({
        if let Some(buf) = unsafe { $crate::AYA_LOG_BUF.get_mut(0) } {
            if let Ok(header_len) = $crate::write_record_header(&mut buf.buf, module_path!(), $lvl, module_path!(), file!(), line!()) {
                if let Ok(message_len) = $crate::write_record_message!(&mut buf.buf[header_len..], $($arg)+) {
                    let _ = unsafe { $crate::AYA_LOGS.output($ctx, buf, header_len + message_len) };
                };
            }
        }
    });
    ($ctx:expr, $lvl:expr, $($arg:tt)+) => ($crate::log!($ctx, target: __log_module_path!(), $lvl, $($arg)+))
}

#[doc(hidden)]
#[macro_export]
macro_rules! write_record_message {
    ($buf:expr, $($arg:tt)+) => {{
        let mut writer = $crate::LogBufWriter::new($buf);
        ufmt::uwrite!(writer, $($arg)+).map(|_| writer.finish())
    }}
}
