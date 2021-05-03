use crate::{
    generated::bpf_prog_type::{BPF_PROG_TYPE_SCHED_ACT, BPF_PROG_TYPE_SCHED_CLS},
    programs::{load_program, ProgramData, ProgramError},
};

#[derive(Debug)]
pub struct SchedClassifier {
    pub(crate) data: ProgramData,
}

impl SchedClassifier {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SCHED_CLS, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }
}

#[derive(Debug)]
pub struct SchedAction {
    pub(crate) data: ProgramData,
}

impl SchedAction {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SCHED_ACT, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }
}
