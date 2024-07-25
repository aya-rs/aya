//! Command types for BPFFS Permissions

use crate::generated::bpf_cmd;

/// The type of BPF link
#[derive(Copy, Clone, Debug)]
pub enum BpfCommand {
    /// Map Create
    MapCreate,
    /// Map Lookup Element
    MapLookupElem,
    /// Map Update Element
    MapUpdateElem,
    /// Map Delete Element
    MapDeleteElem,
    /// Map Get Next Key
    MapGetNextKey,
    /// Program Load
    ProgLoad,
    /// Object Pin
    ObjPin,
    /// Object Get
    ObjGet,
    /// Program Attach
    ProgAttach,
    /// Program Detach
    ProgDetach,
    /// Program Test Run
    ProgTestRun,
    /// Program Get Next Id
    ProgGetNextId,
    /// Map Get Next Id
    MapGetNextId,
    /// Program Get FD By Id
    ProgGetFdById,
    /// Map Get FD By Id
    MapGetFdById,
    /// Object Get Info By FD
    ObjGetInfoByFd,
    /// Program Query
    ProgQuery,
    /// Raw Tracepoint Open
    RawTracepointOpen,
    /// BTF Load
    BtfLoad,
    /// BTF Get FD By Id
    BtfGetFdById,
    /// Task FD Query
    TaskFdQuery,
    /// Map Lookup And Delete Element
    MapLookupAndDeleteElem,
    /// Map Freeze
    MapFreeze,
    /// BTF Get Next Id
    BtfGetNextId,
    /// Map Lookup Batch
    MapLookupBatch,
    /// Map Lookup And Delete Batch
    MapLookupAndDeleteBatch,
    /// Map Update Batch
    MapUpdateBatch,
    /// Map Delete Batch
    MapDeleteBatch,
    /// Link Create
    LinkCreate,
    /// Link Update
    LinkUpdate,
    /// Link Get FD By Id
    LinkGetFdById,
    /// Link Get Next Id
    LinkGetNextId,
    /// Enable Stats
    EnableStats,
    /// Iter Create
    IterCreate,
    /// Link Detach
    LinkDetach,
    /// Program Bind Map
    ProgBindMap,
    /// Token Create
    TokenCreate,
}

impl From<BpfCommand> for bpf_cmd {
    fn from(value: BpfCommand) -> Self {
        match value {
            BpfCommand::MapCreate => bpf_cmd::BPF_MAP_CREATE,
            BpfCommand::MapLookupElem => bpf_cmd::BPF_MAP_LOOKUP_ELEM,
            BpfCommand::MapUpdateElem => bpf_cmd::BPF_MAP_UPDATE_ELEM,
            BpfCommand::MapDeleteElem => bpf_cmd::BPF_MAP_DELETE_ELEM,
            BpfCommand::MapGetNextKey => bpf_cmd::BPF_MAP_GET_NEXT_KEY,
            BpfCommand::ProgLoad => bpf_cmd::BPF_PROG_LOAD,
            BpfCommand::ObjPin => bpf_cmd::BPF_OBJ_PIN,
            BpfCommand::ObjGet => bpf_cmd::BPF_OBJ_GET,
            BpfCommand::ProgAttach => bpf_cmd::BPF_PROG_ATTACH,
            BpfCommand::ProgDetach => bpf_cmd::BPF_PROG_DETACH,
            BpfCommand::ProgTestRun => bpf_cmd::BPF_PROG_TEST_RUN,
            BpfCommand::ProgGetNextId => bpf_cmd::BPF_PROG_GET_NEXT_ID,
            BpfCommand::MapGetNextId => bpf_cmd::BPF_MAP_GET_NEXT_ID,
            BpfCommand::ProgGetFdById => bpf_cmd::BPF_PROG_GET_FD_BY_ID,
            BpfCommand::MapGetFdById => bpf_cmd::BPF_MAP_GET_FD_BY_ID,
            BpfCommand::ObjGetInfoByFd => bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
            BpfCommand::ProgQuery => bpf_cmd::BPF_PROG_QUERY,
            BpfCommand::RawTracepointOpen => bpf_cmd::BPF_RAW_TRACEPOINT_OPEN,
            BpfCommand::BtfLoad => bpf_cmd::BPF_BTF_LOAD,
            BpfCommand::BtfGetFdById => bpf_cmd::BPF_BTF_GET_FD_BY_ID,
            BpfCommand::TaskFdQuery => bpf_cmd::BPF_TASK_FD_QUERY,
            BpfCommand::MapLookupAndDeleteElem => bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM,
            BpfCommand::MapFreeze => bpf_cmd::BPF_MAP_FREEZE,
            BpfCommand::BtfGetNextId => bpf_cmd::BPF_BTF_GET_NEXT_ID,
            BpfCommand::MapLookupBatch => bpf_cmd::BPF_MAP_LOOKUP_BATCH,
            BpfCommand::MapLookupAndDeleteBatch => bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH,
            BpfCommand::MapUpdateBatch => bpf_cmd::BPF_MAP_UPDATE_BATCH,
            BpfCommand::MapDeleteBatch => bpf_cmd::BPF_MAP_DELETE_BATCH,
            BpfCommand::LinkCreate => bpf_cmd::BPF_LINK_CREATE,
            BpfCommand::LinkUpdate => bpf_cmd::BPF_LINK_UPDATE,
            BpfCommand::LinkGetFdById => bpf_cmd::BPF_LINK_GET_FD_BY_ID,
            BpfCommand::LinkGetNextId => bpf_cmd::BPF_LINK_GET_NEXT_ID,
            BpfCommand::EnableStats => bpf_cmd::BPF_ENABLE_STATS,
            BpfCommand::IterCreate => bpf_cmd::BPF_ITER_CREATE,
            BpfCommand::LinkDetach => bpf_cmd::BPF_LINK_DETACH,
            BpfCommand::ProgBindMap => bpf_cmd::BPF_PROG_BIND_MAP,
            BpfCommand::TokenCreate => bpf_cmd::BPF_TOKEN_CREATE,
        }
    }
}
