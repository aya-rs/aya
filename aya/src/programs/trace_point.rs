use std::{fs, io};
use thiserror::Error;

use crate::{generated::bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT, sys::perf_event_open_trace_point};

use super::{load_program, perf_attach, LinkRef, ProgramData, ProgramError};

#[derive(Debug, Error)]
pub enum TracePointError {
    #[error("`{filename}`")]
    FileError {
        filename: String,
        #[source]
        io_error: io::Error,
    },
}

#[derive(Debug)]
pub struct TracePoint {
    pub(crate) data: ProgramData,
}

impl TracePoint {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_TRACEPOINT, &mut self.data)
    }

    pub fn attach(&mut self, category: &str, name: &str) -> Result<LinkRef, ProgramError> {
        let id = read_sys_fs_trace_point_id(category, name)?;
        let fd = perf_event_open_trace_point(id)
            .map_err(|(_code, io_error)| ProgramError::PerfEventOpenError { io_error })?
            as i32;

        perf_attach(&mut self.data, fd)
    }
}

fn read_sys_fs_trace_point_id(category: &str, name: &str) -> Result<u32, TracePointError> {
    let file = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);

    let id = fs::read_to_string(&file).map_err(|io_error| TracePointError::FileError {
        filename: file.clone(),
        io_error,
    })?;
    let id = id
        .trim()
        .parse::<u32>()
        .map_err(|error| TracePointError::FileError {
            filename: file.clone(),
            io_error: io::Error::new(io::ErrorKind::Other, error),
        })?;

    Ok(id)
}
