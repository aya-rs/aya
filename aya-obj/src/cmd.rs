//! Command types for BPFFS Permissions

use crate::generated::bpf_cmd;

/// The type of BPF command
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
            BpfCommand::MapCreate => Self::BPF_MAP_CREATE,
            BpfCommand::MapLookupElem => Self::BPF_MAP_LOOKUP_ELEM,
            BpfCommand::MapUpdateElem => Self::BPF_MAP_UPDATE_ELEM,
            BpfCommand::MapDeleteElem => Self::BPF_MAP_DELETE_ELEM,
            BpfCommand::MapGetNextKey => Self::BPF_MAP_GET_NEXT_KEY,
            BpfCommand::ProgLoad => Self::BPF_PROG_LOAD,
            BpfCommand::ObjPin => Self::BPF_OBJ_PIN,
            BpfCommand::ObjGet => Self::BPF_OBJ_GET,
            BpfCommand::ProgAttach => Self::BPF_PROG_ATTACH,
            BpfCommand::ProgDetach => Self::BPF_PROG_DETACH,
            BpfCommand::ProgTestRun => Self::BPF_PROG_TEST_RUN,
            BpfCommand::ProgGetNextId => Self::BPF_PROG_GET_NEXT_ID,
            BpfCommand::MapGetNextId => Self::BPF_MAP_GET_NEXT_ID,
            BpfCommand::ProgGetFdById => Self::BPF_PROG_GET_FD_BY_ID,
            BpfCommand::MapGetFdById => Self::BPF_MAP_GET_FD_BY_ID,
            BpfCommand::ObjGetInfoByFd => Self::BPF_OBJ_GET_INFO_BY_FD,
            BpfCommand::ProgQuery => Self::BPF_PROG_QUERY,
            BpfCommand::RawTracepointOpen => Self::BPF_RAW_TRACEPOINT_OPEN,
            BpfCommand::BtfLoad => Self::BPF_BTF_LOAD,
            BpfCommand::BtfGetFdById => Self::BPF_BTF_GET_FD_BY_ID,
            BpfCommand::TaskFdQuery => Self::BPF_TASK_FD_QUERY,
            BpfCommand::MapLookupAndDeleteElem => Self::BPF_MAP_LOOKUP_AND_DELETE_ELEM,
            BpfCommand::MapFreeze => Self::BPF_MAP_FREEZE,
            BpfCommand::BtfGetNextId => Self::BPF_BTF_GET_NEXT_ID,
            BpfCommand::MapLookupBatch => Self::BPF_MAP_LOOKUP_BATCH,
            BpfCommand::MapLookupAndDeleteBatch => Self::BPF_MAP_LOOKUP_AND_DELETE_BATCH,
            BpfCommand::MapUpdateBatch => Self::BPF_MAP_UPDATE_BATCH,
            BpfCommand::MapDeleteBatch => Self::BPF_MAP_DELETE_BATCH,
            BpfCommand::LinkCreate => Self::BPF_LINK_CREATE,
            BpfCommand::LinkUpdate => Self::BPF_LINK_UPDATE,
            BpfCommand::LinkGetFdById => Self::BPF_LINK_GET_FD_BY_ID,
            BpfCommand::LinkGetNextId => Self::BPF_LINK_GET_NEXT_ID,
            BpfCommand::EnableStats => Self::BPF_ENABLE_STATS,
            BpfCommand::IterCreate => Self::BPF_ITER_CREATE,
            BpfCommand::LinkDetach => Self::BPF_LINK_DETACH,
            BpfCommand::ProgBindMap => Self::BPF_PROG_BIND_MAP,
            BpfCommand::TokenCreate => Self::BPF_TOKEN_CREATE,
        }
    }
}
