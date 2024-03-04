#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}
impl<Storage> __BindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> __BindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::core::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::core::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::core::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::core::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub const BPF_LD: u32 = 0;
pub const BPF_LDX: u32 = 1;
pub const BPF_ST: u32 = 2;
pub const BPF_STX: u32 = 3;
pub const BPF_ALU: u32 = 4;
pub const BPF_JMP: u32 = 5;
pub const BPF_RET: u32 = 6;
pub const BPF_MISC: u32 = 7;
pub const BPF_W: u32 = 0;
pub const BPF_H: u32 = 8;
pub const BPF_B: u32 = 16;
pub const BPF_IMM: u32 = 0;
pub const BPF_ABS: u32 = 32;
pub const BPF_IND: u32 = 64;
pub const BPF_MEM: u32 = 96;
pub const BPF_LEN: u32 = 128;
pub const BPF_MSH: u32 = 160;
pub const BPF_ADD: u32 = 0;
pub const BPF_SUB: u32 = 16;
pub const BPF_MUL: u32 = 32;
pub const BPF_DIV: u32 = 48;
pub const BPF_OR: u32 = 64;
pub const BPF_AND: u32 = 80;
pub const BPF_LSH: u32 = 96;
pub const BPF_RSH: u32 = 112;
pub const BPF_NEG: u32 = 128;
pub const BPF_MOD: u32 = 144;
pub const BPF_XOR: u32 = 160;
pub const BPF_JA: u32 = 0;
pub const BPF_JEQ: u32 = 16;
pub const BPF_JGT: u32 = 32;
pub const BPF_JGE: u32 = 48;
pub const BPF_JSET: u32 = 64;
pub const BPF_K: u32 = 0;
pub const BPF_X: u32 = 8;
pub const BPF_MAXINSNS: u32 = 4096;
pub const BPF_JMP32: u32 = 6;
pub const BPF_ALU64: u32 = 7;
pub const BPF_DW: u32 = 24;
pub const BPF_ATOMIC: u32 = 192;
pub const BPF_XADD: u32 = 192;
pub const BPF_MOV: u32 = 176;
pub const BPF_ARSH: u32 = 192;
pub const BPF_END: u32 = 208;
pub const BPF_TO_LE: u32 = 0;
pub const BPF_TO_BE: u32 = 8;
pub const BPF_FROM_LE: u32 = 0;
pub const BPF_FROM_BE: u32 = 8;
pub const BPF_JNE: u32 = 80;
pub const BPF_JLT: u32 = 160;
pub const BPF_JLE: u32 = 176;
pub const BPF_JSGT: u32 = 96;
pub const BPF_JSGE: u32 = 112;
pub const BPF_JSLT: u32 = 192;
pub const BPF_JSLE: u32 = 208;
pub const BPF_CALL: u32 = 128;
pub const BPF_EXIT: u32 = 144;
pub const BPF_FETCH: u32 = 1;
pub const BPF_XCHG: u32 = 225;
pub const BPF_CMPXCHG: u32 = 241;
pub const BPF_F_ALLOW_OVERRIDE: u32 = 1;
pub const BPF_F_ALLOW_MULTI: u32 = 2;
pub const BPF_F_REPLACE: u32 = 4;
pub const BPF_F_STRICT_ALIGNMENT: u32 = 1;
pub const BPF_F_ANY_ALIGNMENT: u32 = 2;
pub const BPF_F_TEST_RND_HI32: u32 = 4;
pub const BPF_F_TEST_STATE_FREQ: u32 = 8;
pub const BPF_F_SLEEPABLE: u32 = 16;
pub const BPF_F_XDP_HAS_FRAGS: u32 = 32;
pub const BPF_F_XDP_DEV_BOUND_ONLY: u32 = 64;
pub const BPF_F_KPROBE_MULTI_RETURN: u32 = 1;
pub const BPF_PSEUDO_MAP_FD: u32 = 1;
pub const BPF_PSEUDO_MAP_IDX: u32 = 5;
pub const BPF_PSEUDO_MAP_VALUE: u32 = 2;
pub const BPF_PSEUDO_MAP_IDX_VALUE: u32 = 6;
pub const BPF_PSEUDO_BTF_ID: u32 = 3;
pub const BPF_PSEUDO_FUNC: u32 = 4;
pub const BPF_PSEUDO_CALL: u32 = 1;
pub const BPF_PSEUDO_KFUNC_CALL: u32 = 2;
pub const BPF_F_QUERY_EFFECTIVE: u32 = 1;
pub const BPF_F_TEST_RUN_ON_CPU: u32 = 1;
pub const BPF_F_TEST_XDP_LIVE_FRAMES: u32 = 2;
pub const BPF_BUILD_ID_SIZE: u32 = 20;
pub const BPF_OBJ_NAME_LEN: u32 = 16;
pub const BPF_TAG_SIZE: u32 = 8;
pub const SOL_SOCKET: u32 = 1;
pub const SO_DEBUG: u32 = 1;
pub const SO_REUSEADDR: u32 = 2;
pub const SO_TYPE: u32 = 3;
pub const SO_ERROR: u32 = 4;
pub const SO_DONTROUTE: u32 = 5;
pub const SO_BROADCAST: u32 = 6;
pub const SO_SNDBUF: u32 = 7;
pub const SO_RCVBUF: u32 = 8;
pub const SO_SNDBUFFORCE: u32 = 32;
pub const SO_RCVBUFFORCE: u32 = 33;
pub const SO_KEEPALIVE: u32 = 9;
pub const SO_OOBINLINE: u32 = 10;
pub const SO_NO_CHECK: u32 = 11;
pub const SO_PRIORITY: u32 = 12;
pub const SO_LINGER: u32 = 13;
pub const SO_BSDCOMPAT: u32 = 14;
pub const SO_REUSEPORT: u32 = 15;
pub const SO_PASSCRED: u32 = 16;
pub const SO_PEERCRED: u32 = 17;
pub const SO_RCVLOWAT: u32 = 18;
pub const SO_SNDLOWAT: u32 = 19;
pub const SO_RCVTIMEO_OLD: u32 = 20;
pub const SO_SNDTIMEO_OLD: u32 = 21;
pub const SO_SECURITY_AUTHENTICATION: u32 = 22;
pub const SO_SECURITY_ENCRYPTION_TRANSPORT: u32 = 23;
pub const SO_SECURITY_ENCRYPTION_NETWORK: u32 = 24;
pub const SO_BINDTODEVICE: u32 = 25;
pub const SO_ATTACH_FILTER: u32 = 26;
pub const SO_DETACH_FILTER: u32 = 27;
pub const SO_GET_FILTER: u32 = 26;
pub const SO_PEERNAME: u32 = 28;
pub const SO_ACCEPTCONN: u32 = 30;
pub const SO_PEERSEC: u32 = 31;
pub const SO_PASSSEC: u32 = 34;
pub const SO_MARK: u32 = 36;
pub const SO_PROTOCOL: u32 = 38;
pub const SO_DOMAIN: u32 = 39;
pub const SO_RXQ_OVFL: u32 = 40;
pub const SO_WIFI_STATUS: u32 = 41;
pub const SO_PEEK_OFF: u32 = 42;
pub const SO_NOFCS: u32 = 43;
pub const SO_LOCK_FILTER: u32 = 44;
pub const SO_SELECT_ERR_QUEUE: u32 = 45;
pub const SO_BUSY_POLL: u32 = 46;
pub const SO_MAX_PACING_RATE: u32 = 47;
pub const SO_BPF_EXTENSIONS: u32 = 48;
pub const SO_INCOMING_CPU: u32 = 49;
pub const SO_ATTACH_BPF: u32 = 50;
pub const SO_DETACH_BPF: u32 = 27;
pub const SO_ATTACH_REUSEPORT_CBPF: u32 = 51;
pub const SO_ATTACH_REUSEPORT_EBPF: u32 = 52;
pub const SO_CNX_ADVICE: u32 = 53;
pub const SO_MEMINFO: u32 = 55;
pub const SO_INCOMING_NAPI_ID: u32 = 56;
pub const SO_COOKIE: u32 = 57;
pub const SO_PEERGROUPS: u32 = 59;
pub const SO_ZEROCOPY: u32 = 60;
pub const SO_TXTIME: u32 = 61;
pub const SO_BINDTOIFINDEX: u32 = 62;
pub const SO_TIMESTAMP_OLD: u32 = 29;
pub const SO_TIMESTAMPNS_OLD: u32 = 35;
pub const SO_TIMESTAMPING_OLD: u32 = 37;
pub const SO_TIMESTAMP_NEW: u32 = 63;
pub const SO_TIMESTAMPNS_NEW: u32 = 64;
pub const SO_TIMESTAMPING_NEW: u32 = 65;
pub const SO_RCVTIMEO_NEW: u32 = 66;
pub const SO_SNDTIMEO_NEW: u32 = 67;
pub const SO_DETACH_REUSEPORT_BPF: u32 = 68;
pub const SO_TIMESTAMP: u32 = 29;
pub const SO_TIMESTAMPNS: u32 = 35;
pub const SO_TIMESTAMPING: u32 = 37;
pub const SO_RCVTIMEO: u32 = 20;
pub const SO_SNDTIMEO: u32 = 21;
pub const TC_ACT_UNSPEC: i32 = -1;
pub const TC_ACT_OK: u32 = 0;
pub const TC_ACT_RECLASSIFY: u32 = 1;
pub const TC_ACT_SHOT: u32 = 2;
pub const TC_ACT_PIPE: u32 = 3;
pub const TC_ACT_STOLEN: u32 = 4;
pub const TC_ACT_QUEUED: u32 = 5;
pub const TC_ACT_REPEAT: u32 = 6;
pub const TC_ACT_REDIRECT: u32 = 7;
pub const TC_ACT_TRAP: u32 = 8;
pub const TC_ACT_VALUE_MAX: u32 = 8;
pub const TC_ACT_EXT_VAL_MASK: u32 = 268435455;
pub type __u8 = ::aya_bpf_cty::c_uchar;
pub type __s16 = ::aya_bpf_cty::c_short;
pub type __u16 = ::aya_bpf_cty::c_ushort;
pub type __s32 = ::aya_bpf_cty::c_int;
pub type __u32 = ::aya_bpf_cty::c_uint;
pub type __s64 = ::aya_bpf_cty::c_longlong;
pub type __u64 = ::aya_bpf_cty::c_ulonglong;
pub type __be16 = __u16;
pub type __be32 = __u32;
pub type __wsum = __u32;
pub const BPF_REG_0: _bindgen_ty_1 = 0;
pub const BPF_REG_1: _bindgen_ty_1 = 1;
pub const BPF_REG_2: _bindgen_ty_1 = 2;
pub const BPF_REG_3: _bindgen_ty_1 = 3;
pub const BPF_REG_4: _bindgen_ty_1 = 4;
pub const BPF_REG_5: _bindgen_ty_1 = 5;
pub const BPF_REG_6: _bindgen_ty_1 = 6;
pub const BPF_REG_7: _bindgen_ty_1 = 7;
pub const BPF_REG_8: _bindgen_ty_1 = 8;
pub const BPF_REG_9: _bindgen_ty_1 = 9;
pub const BPF_REG_10: _bindgen_ty_1 = 10;
pub const __MAX_BPF_REG: _bindgen_ty_1 = 11;
pub type _bindgen_ty_1 = ::aya_bpf_cty::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_insn {
    pub code: __u8,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
    pub off: __s16,
    pub imm: __s32,
}
impl bpf_insn {
    #[inline]
    pub fn dst_reg(&self) -> __u8 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_dst_reg(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn src_reg(&self) -> __u8 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_src_reg(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::core::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(dst_reg: __u8, src_reg: __u8) -> __BindgenBitfieldUnit<[u8; 1usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 4u8, {
            let dst_reg: u8 = unsafe { ::core::mem::transmute(dst_reg) };
            dst_reg as u64
        });
        __bindgen_bitfield_unit.set(4usize, 4u8, {
            let src_reg: u8 = unsafe { ::core::mem::transmute(src_reg) };
            src_reg as u64
        });
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug)]
pub struct bpf_lpm_trie_key {
    pub prefixlen: __u32,
    pub data: __IncompleteArrayField<__u8>,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_cgroup_storage_key {
    pub cgroup_inode_id: __u64,
    pub attach_type: __u32,
}
pub mod bpf_cgroup_iter_order {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_CGROUP_ITER_ORDER_UNSPEC: Type = 0;
    pub const BPF_CGROUP_ITER_SELF_ONLY: Type = 1;
    pub const BPF_CGROUP_ITER_DESCENDANTS_PRE: Type = 2;
    pub const BPF_CGROUP_ITER_DESCENDANTS_POST: Type = 3;
    pub const BPF_CGROUP_ITER_ANCESTORS_UP: Type = 4;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_iter_link_info {
    pub map: bpf_iter_link_info__bindgen_ty_1,
    pub cgroup: bpf_iter_link_info__bindgen_ty_2,
    pub task: bpf_iter_link_info__bindgen_ty_3,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_iter_link_info__bindgen_ty_1 {
    pub map_fd: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_iter_link_info__bindgen_ty_2 {
    pub order: bpf_cgroup_iter_order::Type,
    pub cgroup_fd: __u32,
    pub cgroup_id: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_iter_link_info__bindgen_ty_3 {
    pub tid: __u32,
    pub pid: __u32,
    pub pid_fd: __u32,
}
pub mod bpf_cmd {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_MAP_CREATE: Type = 0;
    pub const BPF_MAP_LOOKUP_ELEM: Type = 1;
    pub const BPF_MAP_UPDATE_ELEM: Type = 2;
    pub const BPF_MAP_DELETE_ELEM: Type = 3;
    pub const BPF_MAP_GET_NEXT_KEY: Type = 4;
    pub const BPF_PROG_LOAD: Type = 5;
    pub const BPF_OBJ_PIN: Type = 6;
    pub const BPF_OBJ_GET: Type = 7;
    pub const BPF_PROG_ATTACH: Type = 8;
    pub const BPF_PROG_DETACH: Type = 9;
    pub const BPF_PROG_TEST_RUN: Type = 10;
    pub const BPF_PROG_RUN: Type = 10;
    pub const BPF_PROG_GET_NEXT_ID: Type = 11;
    pub const BPF_MAP_GET_NEXT_ID: Type = 12;
    pub const BPF_PROG_GET_FD_BY_ID: Type = 13;
    pub const BPF_MAP_GET_FD_BY_ID: Type = 14;
    pub const BPF_OBJ_GET_INFO_BY_FD: Type = 15;
    pub const BPF_PROG_QUERY: Type = 16;
    pub const BPF_RAW_TRACEPOINT_OPEN: Type = 17;
    pub const BPF_BTF_LOAD: Type = 18;
    pub const BPF_BTF_GET_FD_BY_ID: Type = 19;
    pub const BPF_TASK_FD_QUERY: Type = 20;
    pub const BPF_MAP_LOOKUP_AND_DELETE_ELEM: Type = 21;
    pub const BPF_MAP_FREEZE: Type = 22;
    pub const BPF_BTF_GET_NEXT_ID: Type = 23;
    pub const BPF_MAP_LOOKUP_BATCH: Type = 24;
    pub const BPF_MAP_LOOKUP_AND_DELETE_BATCH: Type = 25;
    pub const BPF_MAP_UPDATE_BATCH: Type = 26;
    pub const BPF_MAP_DELETE_BATCH: Type = 27;
    pub const BPF_LINK_CREATE: Type = 28;
    pub const BPF_LINK_UPDATE: Type = 29;
    pub const BPF_LINK_GET_FD_BY_ID: Type = 30;
    pub const BPF_LINK_GET_NEXT_ID: Type = 31;
    pub const BPF_ENABLE_STATS: Type = 32;
    pub const BPF_ITER_CREATE: Type = 33;
    pub const BPF_LINK_DETACH: Type = 34;
    pub const BPF_PROG_BIND_MAP: Type = 35;
}
pub mod bpf_map_type {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_MAP_TYPE_UNSPEC: Type = 0;
    pub const BPF_MAP_TYPE_HASH: Type = 1;
    pub const BPF_MAP_TYPE_ARRAY: Type = 2;
    pub const BPF_MAP_TYPE_PROG_ARRAY: Type = 3;
    pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: Type = 4;
    pub const BPF_MAP_TYPE_PERCPU_HASH: Type = 5;
    pub const BPF_MAP_TYPE_PERCPU_ARRAY: Type = 6;
    pub const BPF_MAP_TYPE_STACK_TRACE: Type = 7;
    pub const BPF_MAP_TYPE_CGROUP_ARRAY: Type = 8;
    pub const BPF_MAP_TYPE_LRU_HASH: Type = 9;
    pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: Type = 10;
    pub const BPF_MAP_TYPE_LPM_TRIE: Type = 11;
    pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: Type = 12;
    pub const BPF_MAP_TYPE_HASH_OF_MAPS: Type = 13;
    pub const BPF_MAP_TYPE_DEVMAP: Type = 14;
    pub const BPF_MAP_TYPE_SOCKMAP: Type = 15;
    pub const BPF_MAP_TYPE_CPUMAP: Type = 16;
    pub const BPF_MAP_TYPE_XSKMAP: Type = 17;
    pub const BPF_MAP_TYPE_SOCKHASH: Type = 18;
    pub const BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED: Type = 19;
    pub const BPF_MAP_TYPE_CGROUP_STORAGE: Type = 19;
    pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: Type = 20;
    pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: Type = 21;
    pub const BPF_MAP_TYPE_QUEUE: Type = 22;
    pub const BPF_MAP_TYPE_STACK: Type = 23;
    pub const BPF_MAP_TYPE_SK_STORAGE: Type = 24;
    pub const BPF_MAP_TYPE_DEVMAP_HASH: Type = 25;
    pub const BPF_MAP_TYPE_STRUCT_OPS: Type = 26;
    pub const BPF_MAP_TYPE_RINGBUF: Type = 27;
    pub const BPF_MAP_TYPE_INODE_STORAGE: Type = 28;
    pub const BPF_MAP_TYPE_TASK_STORAGE: Type = 29;
    pub const BPF_MAP_TYPE_BLOOM_FILTER: Type = 30;
    pub const BPF_MAP_TYPE_USER_RINGBUF: Type = 31;
    pub const BPF_MAP_TYPE_CGRP_STORAGE: Type = 32;
}
pub mod bpf_prog_type {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_PROG_TYPE_UNSPEC: Type = 0;
    pub const BPF_PROG_TYPE_SOCKET_FILTER: Type = 1;
    pub const BPF_PROG_TYPE_KPROBE: Type = 2;
    pub const BPF_PROG_TYPE_SCHED_CLS: Type = 3;
    pub const BPF_PROG_TYPE_SCHED_ACT: Type = 4;
    pub const BPF_PROG_TYPE_TRACEPOINT: Type = 5;
    pub const BPF_PROG_TYPE_XDP: Type = 6;
    pub const BPF_PROG_TYPE_PERF_EVENT: Type = 7;
    pub const BPF_PROG_TYPE_CGROUP_SKB: Type = 8;
    pub const BPF_PROG_TYPE_CGROUP_SOCK: Type = 9;
    pub const BPF_PROG_TYPE_LWT_IN: Type = 10;
    pub const BPF_PROG_TYPE_LWT_OUT: Type = 11;
    pub const BPF_PROG_TYPE_LWT_XMIT: Type = 12;
    pub const BPF_PROG_TYPE_SOCK_OPS: Type = 13;
    pub const BPF_PROG_TYPE_SK_SKB: Type = 14;
    pub const BPF_PROG_TYPE_CGROUP_DEVICE: Type = 15;
    pub const BPF_PROG_TYPE_SK_MSG: Type = 16;
    pub const BPF_PROG_TYPE_RAW_TRACEPOINT: Type = 17;
    pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: Type = 18;
    pub const BPF_PROG_TYPE_LWT_SEG6LOCAL: Type = 19;
    pub const BPF_PROG_TYPE_LIRC_MODE2: Type = 20;
    pub const BPF_PROG_TYPE_SK_REUSEPORT: Type = 21;
    pub const BPF_PROG_TYPE_FLOW_DISSECTOR: Type = 22;
    pub const BPF_PROG_TYPE_CGROUP_SYSCTL: Type = 23;
    pub const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: Type = 24;
    pub const BPF_PROG_TYPE_CGROUP_SOCKOPT: Type = 25;
    pub const BPF_PROG_TYPE_TRACING: Type = 26;
    pub const BPF_PROG_TYPE_STRUCT_OPS: Type = 27;
    pub const BPF_PROG_TYPE_EXT: Type = 28;
    pub const BPF_PROG_TYPE_LSM: Type = 29;
    pub const BPF_PROG_TYPE_SK_LOOKUP: Type = 30;
    pub const BPF_PROG_TYPE_SYSCALL: Type = 31;
    pub const BPF_PROG_TYPE_NETFILTER: Type = 32;
}
pub mod bpf_attach_type {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_CGROUP_INET_INGRESS: Type = 0;
    pub const BPF_CGROUP_INET_EGRESS: Type = 1;
    pub const BPF_CGROUP_INET_SOCK_CREATE: Type = 2;
    pub const BPF_CGROUP_SOCK_OPS: Type = 3;
    pub const BPF_SK_SKB_STREAM_PARSER: Type = 4;
    pub const BPF_SK_SKB_STREAM_VERDICT: Type = 5;
    pub const BPF_CGROUP_DEVICE: Type = 6;
    pub const BPF_SK_MSG_VERDICT: Type = 7;
    pub const BPF_CGROUP_INET4_BIND: Type = 8;
    pub const BPF_CGROUP_INET6_BIND: Type = 9;
    pub const BPF_CGROUP_INET4_CONNECT: Type = 10;
    pub const BPF_CGROUP_INET6_CONNECT: Type = 11;
    pub const BPF_CGROUP_INET4_POST_BIND: Type = 12;
    pub const BPF_CGROUP_INET6_POST_BIND: Type = 13;
    pub const BPF_CGROUP_UDP4_SENDMSG: Type = 14;
    pub const BPF_CGROUP_UDP6_SENDMSG: Type = 15;
    pub const BPF_LIRC_MODE2: Type = 16;
    pub const BPF_FLOW_DISSECTOR: Type = 17;
    pub const BPF_CGROUP_SYSCTL: Type = 18;
    pub const BPF_CGROUP_UDP4_RECVMSG: Type = 19;
    pub const BPF_CGROUP_UDP6_RECVMSG: Type = 20;
    pub const BPF_CGROUP_GETSOCKOPT: Type = 21;
    pub const BPF_CGROUP_SETSOCKOPT: Type = 22;
    pub const BPF_TRACE_RAW_TP: Type = 23;
    pub const BPF_TRACE_FENTRY: Type = 24;
    pub const BPF_TRACE_FEXIT: Type = 25;
    pub const BPF_MODIFY_RETURN: Type = 26;
    pub const BPF_LSM_MAC: Type = 27;
    pub const BPF_TRACE_ITER: Type = 28;
    pub const BPF_CGROUP_INET4_GETPEERNAME: Type = 29;
    pub const BPF_CGROUP_INET6_GETPEERNAME: Type = 30;
    pub const BPF_CGROUP_INET4_GETSOCKNAME: Type = 31;
    pub const BPF_CGROUP_INET6_GETSOCKNAME: Type = 32;
    pub const BPF_XDP_DEVMAP: Type = 33;
    pub const BPF_CGROUP_INET_SOCK_RELEASE: Type = 34;
    pub const BPF_XDP_CPUMAP: Type = 35;
    pub const BPF_SK_LOOKUP: Type = 36;
    pub const BPF_XDP: Type = 37;
    pub const BPF_SK_SKB_VERDICT: Type = 38;
    pub const BPF_SK_REUSEPORT_SELECT: Type = 39;
    pub const BPF_SK_REUSEPORT_SELECT_OR_MIGRATE: Type = 40;
    pub const BPF_PERF_EVENT: Type = 41;
    pub const BPF_TRACE_KPROBE_MULTI: Type = 42;
    pub const BPF_LSM_CGROUP: Type = 43;
    pub const BPF_STRUCT_OPS: Type = 44;
    pub const __MAX_BPF_ATTACH_TYPE: Type = 45;
}
pub mod bpf_link_type {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_LINK_TYPE_UNSPEC: Type = 0;
    pub const BPF_LINK_TYPE_RAW_TRACEPOINT: Type = 1;
    pub const BPF_LINK_TYPE_TRACING: Type = 2;
    pub const BPF_LINK_TYPE_CGROUP: Type = 3;
    pub const BPF_LINK_TYPE_ITER: Type = 4;
    pub const BPF_LINK_TYPE_NETNS: Type = 5;
    pub const BPF_LINK_TYPE_XDP: Type = 6;
    pub const BPF_LINK_TYPE_PERF_EVENT: Type = 7;
    pub const BPF_LINK_TYPE_KPROBE_MULTI: Type = 8;
    pub const BPF_LINK_TYPE_STRUCT_OPS: Type = 9;
    pub const BPF_LINK_TYPE_NETFILTER: Type = 10;
    pub const MAX_BPF_LINK_TYPE: Type = 11;
}
pub const BPF_ANY: _bindgen_ty_2 = 0;
pub const BPF_NOEXIST: _bindgen_ty_2 = 1;
pub const BPF_EXIST: _bindgen_ty_2 = 2;
pub const BPF_F_LOCK: _bindgen_ty_2 = 4;
pub type _bindgen_ty_2 = ::aya_bpf_cty::c_uint;
pub const BPF_F_NO_PREALLOC: _bindgen_ty_3 = 1;
pub const BPF_F_NO_COMMON_LRU: _bindgen_ty_3 = 2;
pub const BPF_F_NUMA_NODE: _bindgen_ty_3 = 4;
pub const BPF_F_RDONLY: _bindgen_ty_3 = 8;
pub const BPF_F_WRONLY: _bindgen_ty_3 = 16;
pub const BPF_F_STACK_BUILD_ID: _bindgen_ty_3 = 32;
pub const BPF_F_ZERO_SEED: _bindgen_ty_3 = 64;
pub const BPF_F_RDONLY_PROG: _bindgen_ty_3 = 128;
pub const BPF_F_WRONLY_PROG: _bindgen_ty_3 = 256;
pub const BPF_F_CLONE: _bindgen_ty_3 = 512;
pub const BPF_F_MMAPABLE: _bindgen_ty_3 = 1024;
pub const BPF_F_PRESERVE_ELEMS: _bindgen_ty_3 = 2048;
pub const BPF_F_INNER_MAP: _bindgen_ty_3 = 4096;
pub const BPF_F_LINK: _bindgen_ty_3 = 8192;
pub const BPF_F_PATH_FD: _bindgen_ty_3 = 16384;
pub type _bindgen_ty_3 = ::aya_bpf_cty::c_uint;
pub mod bpf_stats_type {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_STATS_RUN_TIME: Type = 0;
}
pub mod bpf_stack_build_id_status {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_STACK_BUILD_ID_EMPTY: Type = 0;
    pub const BPF_STACK_BUILD_ID_VALID: Type = 1;
    pub const BPF_STACK_BUILD_ID_IP: Type = 2;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_stack_build_id {
    pub status: __s32,
    pub build_id: [::aya_bpf_cty::c_uchar; 20usize],
    pub __bindgen_anon_1: bpf_stack_build_id__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_stack_build_id__bindgen_ty_1 {
    pub offset: __u64,
    pub ip: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr {
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_attr__bindgen_ty_2,
    pub batch: bpf_attr__bindgen_ty_3,
    pub __bindgen_anon_3: bpf_attr__bindgen_ty_4,
    pub __bindgen_anon_4: bpf_attr__bindgen_ty_5,
    pub __bindgen_anon_5: bpf_attr__bindgen_ty_6,
    pub test: bpf_attr__bindgen_ty_7,
    pub __bindgen_anon_6: bpf_attr__bindgen_ty_8,
    pub info: bpf_attr__bindgen_ty_9,
    pub query: bpf_attr__bindgen_ty_10,
    pub raw_tracepoint: bpf_attr__bindgen_ty_11,
    pub __bindgen_anon_7: bpf_attr__bindgen_ty_12,
    pub task_fd_query: bpf_attr__bindgen_ty_13,
    pub link_create: bpf_attr__bindgen_ty_14,
    pub link_update: bpf_attr__bindgen_ty_15,
    pub link_detach: bpf_attr__bindgen_ty_16,
    pub enable_stats: bpf_attr__bindgen_ty_17,
    pub iter_create: bpf_attr__bindgen_ty_18,
    pub prog_bind_map: bpf_attr__bindgen_ty_19,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_1 {
    pub map_type: __u32,
    pub key_size: __u32,
    pub value_size: __u32,
    pub max_entries: __u32,
    pub map_flags: __u32,
    pub inner_map_fd: __u32,
    pub numa_node: __u32,
    pub map_name: [::aya_bpf_cty::c_char; 16usize],
    pub map_ifindex: __u32,
    pub btf_fd: __u32,
    pub btf_key_type_id: __u32,
    pub btf_value_type_id: __u32,
    pub btf_vmlinux_value_type_id: __u32,
    pub map_extra: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_2 {
    pub map_fd: __u32,
    pub key: __u64,
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_2__bindgen_ty_1,
    pub flags: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_2__bindgen_ty_1 {
    pub value: __u64,
    pub next_key: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_3 {
    pub in_batch: __u64,
    pub out_batch: __u64,
    pub keys: __u64,
    pub values: __u64,
    pub count: __u32,
    pub map_fd: __u32,
    pub elem_flags: __u64,
    pub flags: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_4 {
    pub prog_type: __u32,
    pub insn_cnt: __u32,
    pub insns: __u64,
    pub license: __u64,
    pub log_level: __u32,
    pub log_size: __u32,
    pub log_buf: __u64,
    pub kern_version: __u32,
    pub prog_flags: __u32,
    pub prog_name: [::aya_bpf_cty::c_char; 16usize],
    pub prog_ifindex: __u32,
    pub expected_attach_type: __u32,
    pub prog_btf_fd: __u32,
    pub func_info_rec_size: __u32,
    pub func_info: __u64,
    pub func_info_cnt: __u32,
    pub line_info_rec_size: __u32,
    pub line_info: __u64,
    pub line_info_cnt: __u32,
    pub attach_btf_id: __u32,
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_4__bindgen_ty_1,
    pub core_relo_cnt: __u32,
    pub fd_array: __u64,
    pub core_relos: __u64,
    pub core_relo_rec_size: __u32,
    pub log_true_size: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_4__bindgen_ty_1 {
    pub attach_prog_fd: __u32,
    pub attach_btf_obj_fd: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_5 {
    pub pathname: __u64,
    pub bpf_fd: __u32,
    pub file_flags: __u32,
    pub path_fd: __s32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_6 {
    pub target_fd: __u32,
    pub attach_bpf_fd: __u32,
    pub attach_type: __u32,
    pub attach_flags: __u32,
    pub replace_bpf_fd: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_7 {
    pub prog_fd: __u32,
    pub retval: __u32,
    pub data_size_in: __u32,
    pub data_size_out: __u32,
    pub data_in: __u64,
    pub data_out: __u64,
    pub repeat: __u32,
    pub duration: __u32,
    pub ctx_size_in: __u32,
    pub ctx_size_out: __u32,
    pub ctx_in: __u64,
    pub ctx_out: __u64,
    pub flags: __u32,
    pub cpu: __u32,
    pub batch_size: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_8 {
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_8__bindgen_ty_1,
    pub next_id: __u32,
    pub open_flags: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_8__bindgen_ty_1 {
    pub start_id: __u32,
    pub prog_id: __u32,
    pub map_id: __u32,
    pub btf_id: __u32,
    pub link_id: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_9 {
    pub bpf_fd: __u32,
    pub info_len: __u32,
    pub info: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_10 {
    pub target_fd: __u32,
    pub attach_type: __u32,
    pub query_flags: __u32,
    pub attach_flags: __u32,
    pub prog_ids: __u64,
    pub prog_cnt: __u32,
    pub prog_attach_flags: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_11 {
    pub name: __u64,
    pub prog_fd: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_12 {
    pub btf: __u64,
    pub btf_log_buf: __u64,
    pub btf_size: __u32,
    pub btf_log_size: __u32,
    pub btf_log_level: __u32,
    pub btf_log_true_size: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_13 {
    pub pid: __u32,
    pub fd: __u32,
    pub flags: __u32,
    pub buf_len: __u32,
    pub buf: __u64,
    pub prog_id: __u32,
    pub fd_type: __u32,
    pub probe_offset: __u64,
    pub probe_addr: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_14 {
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_14__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_attr__bindgen_ty_14__bindgen_ty_2,
    pub attach_type: __u32,
    pub flags: __u32,
    pub __bindgen_anon_3: bpf_attr__bindgen_ty_14__bindgen_ty_3,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_14__bindgen_ty_1 {
    pub prog_fd: __u32,
    pub map_fd: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_14__bindgen_ty_2 {
    pub target_fd: __u32,
    pub target_ifindex: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_14__bindgen_ty_3 {
    pub target_btf_id: __u32,
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_1,
    pub perf_event: bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_2,
    pub kprobe_multi: bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_3,
    pub tracing: bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_4,
    pub netfilter: bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_5,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_1 {
    pub iter_info: __u64,
    pub iter_info_len: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_2 {
    pub bpf_cookie: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_3 {
    pub flags: __u32,
    pub cnt: __u32,
    pub syms: __u64,
    pub addrs: __u64,
    pub cookies: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_4 {
    pub target_btf_id: __u32,
    pub cookie: __u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_14__bindgen_ty_3__bindgen_ty_5 {
    pub pf: __u32,
    pub hooknum: __u32,
    pub priority: __s32,
    pub flags: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_15 {
    pub link_fd: __u32,
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_15__bindgen_ty_1,
    pub flags: __u32,
    pub __bindgen_anon_2: bpf_attr__bindgen_ty_15__bindgen_ty_2,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_15__bindgen_ty_1 {
    pub new_prog_fd: __u32,
    pub new_map_fd: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_15__bindgen_ty_2 {
    pub old_prog_fd: __u32,
    pub old_map_fd: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_16 {
    pub link_fd: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_17 {
    pub type_: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_18 {
    pub link_fd: __u32,
    pub flags: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_19 {
    pub prog_fd: __u32,
    pub map_fd: __u32,
    pub flags: __u32,
}
pub mod bpf_func_id {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_FUNC_unspec: Type = 0;
    pub const BPF_FUNC_map_lookup_elem: Type = 1;
    pub const BPF_FUNC_map_update_elem: Type = 2;
    pub const BPF_FUNC_map_delete_elem: Type = 3;
    pub const BPF_FUNC_probe_read: Type = 4;
    pub const BPF_FUNC_ktime_get_ns: Type = 5;
    pub const BPF_FUNC_trace_printk: Type = 6;
    pub const BPF_FUNC_get_prandom_u32: Type = 7;
    pub const BPF_FUNC_get_smp_processor_id: Type = 8;
    pub const BPF_FUNC_skb_store_bytes: Type = 9;
    pub const BPF_FUNC_l3_csum_replace: Type = 10;
    pub const BPF_FUNC_l4_csum_replace: Type = 11;
    pub const BPF_FUNC_tail_call: Type = 12;
    pub const BPF_FUNC_clone_redirect: Type = 13;
    pub const BPF_FUNC_get_current_pid_tgid: Type = 14;
    pub const BPF_FUNC_get_current_uid_gid: Type = 15;
    pub const BPF_FUNC_get_current_comm: Type = 16;
    pub const BPF_FUNC_get_cgroup_classid: Type = 17;
    pub const BPF_FUNC_skb_vlan_push: Type = 18;
    pub const BPF_FUNC_skb_vlan_pop: Type = 19;
    pub const BPF_FUNC_skb_get_tunnel_key: Type = 20;
    pub const BPF_FUNC_skb_set_tunnel_key: Type = 21;
    pub const BPF_FUNC_perf_event_read: Type = 22;
    pub const BPF_FUNC_redirect: Type = 23;
    pub const BPF_FUNC_get_route_realm: Type = 24;
    pub const BPF_FUNC_perf_event_output: Type = 25;
    pub const BPF_FUNC_skb_load_bytes: Type = 26;
    pub const BPF_FUNC_get_stackid: Type = 27;
    pub const BPF_FUNC_csum_diff: Type = 28;
    pub const BPF_FUNC_skb_get_tunnel_opt: Type = 29;
    pub const BPF_FUNC_skb_set_tunnel_opt: Type = 30;
    pub const BPF_FUNC_skb_change_proto: Type = 31;
    pub const BPF_FUNC_skb_change_type: Type = 32;
    pub const BPF_FUNC_skb_under_cgroup: Type = 33;
    pub const BPF_FUNC_get_hash_recalc: Type = 34;
    pub const BPF_FUNC_get_current_task: Type = 35;
    pub const BPF_FUNC_probe_write_user: Type = 36;
    pub const BPF_FUNC_current_task_under_cgroup: Type = 37;
    pub const BPF_FUNC_skb_change_tail: Type = 38;
    pub const BPF_FUNC_skb_pull_data: Type = 39;
    pub const BPF_FUNC_csum_update: Type = 40;
    pub const BPF_FUNC_set_hash_invalid: Type = 41;
    pub const BPF_FUNC_get_numa_node_id: Type = 42;
    pub const BPF_FUNC_skb_change_head: Type = 43;
    pub const BPF_FUNC_xdp_adjust_head: Type = 44;
    pub const BPF_FUNC_probe_read_str: Type = 45;
    pub const BPF_FUNC_get_socket_cookie: Type = 46;
    pub const BPF_FUNC_get_socket_uid: Type = 47;
    pub const BPF_FUNC_set_hash: Type = 48;
    pub const BPF_FUNC_setsockopt: Type = 49;
    pub const BPF_FUNC_skb_adjust_room: Type = 50;
    pub const BPF_FUNC_redirect_map: Type = 51;
    pub const BPF_FUNC_sk_redirect_map: Type = 52;
    pub const BPF_FUNC_sock_map_update: Type = 53;
    pub const BPF_FUNC_xdp_adjust_meta: Type = 54;
    pub const BPF_FUNC_perf_event_read_value: Type = 55;
    pub const BPF_FUNC_perf_prog_read_value: Type = 56;
    pub const BPF_FUNC_getsockopt: Type = 57;
    pub const BPF_FUNC_override_return: Type = 58;
    pub const BPF_FUNC_sock_ops_cb_flags_set: Type = 59;
    pub const BPF_FUNC_msg_redirect_map: Type = 60;
    pub const BPF_FUNC_msg_apply_bytes: Type = 61;
    pub const BPF_FUNC_msg_cork_bytes: Type = 62;
    pub const BPF_FUNC_msg_pull_data: Type = 63;
    pub const BPF_FUNC_bind: Type = 64;
    pub const BPF_FUNC_xdp_adjust_tail: Type = 65;
    pub const BPF_FUNC_skb_get_xfrm_state: Type = 66;
    pub const BPF_FUNC_get_stack: Type = 67;
    pub const BPF_FUNC_skb_load_bytes_relative: Type = 68;
    pub const BPF_FUNC_fib_lookup: Type = 69;
    pub const BPF_FUNC_sock_hash_update: Type = 70;
    pub const BPF_FUNC_msg_redirect_hash: Type = 71;
    pub const BPF_FUNC_sk_redirect_hash: Type = 72;
    pub const BPF_FUNC_lwt_push_encap: Type = 73;
    pub const BPF_FUNC_lwt_seg6_store_bytes: Type = 74;
    pub const BPF_FUNC_lwt_seg6_adjust_srh: Type = 75;
    pub const BPF_FUNC_lwt_seg6_action: Type = 76;
    pub const BPF_FUNC_rc_repeat: Type = 77;
    pub const BPF_FUNC_rc_keydown: Type = 78;
    pub const BPF_FUNC_skb_cgroup_id: Type = 79;
    pub const BPF_FUNC_get_current_cgroup_id: Type = 80;
    pub const BPF_FUNC_get_local_storage: Type = 81;
    pub const BPF_FUNC_sk_select_reuseport: Type = 82;
    pub const BPF_FUNC_skb_ancestor_cgroup_id: Type = 83;
    pub const BPF_FUNC_sk_lookup_tcp: Type = 84;
    pub const BPF_FUNC_sk_lookup_udp: Type = 85;
    pub const BPF_FUNC_sk_release: Type = 86;
    pub const BPF_FUNC_map_push_elem: Type = 87;
    pub const BPF_FUNC_map_pop_elem: Type = 88;
    pub const BPF_FUNC_map_peek_elem: Type = 89;
    pub const BPF_FUNC_msg_push_data: Type = 90;
    pub const BPF_FUNC_msg_pop_data: Type = 91;
    pub const BPF_FUNC_rc_pointer_rel: Type = 92;
    pub const BPF_FUNC_spin_lock: Type = 93;
    pub const BPF_FUNC_spin_unlock: Type = 94;
    pub const BPF_FUNC_sk_fullsock: Type = 95;
    pub const BPF_FUNC_tcp_sock: Type = 96;
    pub const BPF_FUNC_skb_ecn_set_ce: Type = 97;
    pub const BPF_FUNC_get_listener_sock: Type = 98;
    pub const BPF_FUNC_skc_lookup_tcp: Type = 99;
    pub const BPF_FUNC_tcp_check_syncookie: Type = 100;
    pub const BPF_FUNC_sysctl_get_name: Type = 101;
    pub const BPF_FUNC_sysctl_get_current_value: Type = 102;
    pub const BPF_FUNC_sysctl_get_new_value: Type = 103;
    pub const BPF_FUNC_sysctl_set_new_value: Type = 104;
    pub const BPF_FUNC_strtol: Type = 105;
    pub const BPF_FUNC_strtoul: Type = 106;
    pub const BPF_FUNC_sk_storage_get: Type = 107;
    pub const BPF_FUNC_sk_storage_delete: Type = 108;
    pub const BPF_FUNC_send_signal: Type = 109;
    pub const BPF_FUNC_tcp_gen_syncookie: Type = 110;
    pub const BPF_FUNC_skb_output: Type = 111;
    pub const BPF_FUNC_probe_read_user: Type = 112;
    pub const BPF_FUNC_probe_read_kernel: Type = 113;
    pub const BPF_FUNC_probe_read_user_str: Type = 114;
    pub const BPF_FUNC_probe_read_kernel_str: Type = 115;
    pub const BPF_FUNC_tcp_send_ack: Type = 116;
    pub const BPF_FUNC_send_signal_thread: Type = 117;
    pub const BPF_FUNC_jiffies64: Type = 118;
    pub const BPF_FUNC_read_branch_records: Type = 119;
    pub const BPF_FUNC_get_ns_current_pid_tgid: Type = 120;
    pub const BPF_FUNC_xdp_output: Type = 121;
    pub const BPF_FUNC_get_netns_cookie: Type = 122;
    pub const BPF_FUNC_get_current_ancestor_cgroup_id: Type = 123;
    pub const BPF_FUNC_sk_assign: Type = 124;
    pub const BPF_FUNC_ktime_get_boot_ns: Type = 125;
    pub const BPF_FUNC_seq_printf: Type = 126;
    pub const BPF_FUNC_seq_write: Type = 127;
    pub const BPF_FUNC_sk_cgroup_id: Type = 128;
    pub const BPF_FUNC_sk_ancestor_cgroup_id: Type = 129;
    pub const BPF_FUNC_ringbuf_output: Type = 130;
    pub const BPF_FUNC_ringbuf_reserve: Type = 131;
    pub const BPF_FUNC_ringbuf_submit: Type = 132;
    pub const BPF_FUNC_ringbuf_discard: Type = 133;
    pub const BPF_FUNC_ringbuf_query: Type = 134;
    pub const BPF_FUNC_csum_level: Type = 135;
    pub const BPF_FUNC_skc_to_tcp6_sock: Type = 136;
    pub const BPF_FUNC_skc_to_tcp_sock: Type = 137;
    pub const BPF_FUNC_skc_to_tcp_timewait_sock: Type = 138;
    pub const BPF_FUNC_skc_to_tcp_request_sock: Type = 139;
    pub const BPF_FUNC_skc_to_udp6_sock: Type = 140;
    pub const BPF_FUNC_get_task_stack: Type = 141;
    pub const BPF_FUNC_load_hdr_opt: Type = 142;
    pub const BPF_FUNC_store_hdr_opt: Type = 143;
    pub const BPF_FUNC_reserve_hdr_opt: Type = 144;
    pub const BPF_FUNC_inode_storage_get: Type = 145;
    pub const BPF_FUNC_inode_storage_delete: Type = 146;
    pub const BPF_FUNC_d_path: Type = 147;
    pub const BPF_FUNC_copy_from_user: Type = 148;
    pub const BPF_FUNC_snprintf_btf: Type = 149;
    pub const BPF_FUNC_seq_printf_btf: Type = 150;
    pub const BPF_FUNC_skb_cgroup_classid: Type = 151;
    pub const BPF_FUNC_redirect_neigh: Type = 152;
    pub const BPF_FUNC_per_cpu_ptr: Type = 153;
    pub const BPF_FUNC_this_cpu_ptr: Type = 154;
    pub const BPF_FUNC_redirect_peer: Type = 155;
    pub const BPF_FUNC_task_storage_get: Type = 156;
    pub const BPF_FUNC_task_storage_delete: Type = 157;
    pub const BPF_FUNC_get_current_task_btf: Type = 158;
    pub const BPF_FUNC_bprm_opts_set: Type = 159;
    pub const BPF_FUNC_ktime_get_coarse_ns: Type = 160;
    pub const BPF_FUNC_ima_inode_hash: Type = 161;
    pub const BPF_FUNC_sock_from_file: Type = 162;
    pub const BPF_FUNC_check_mtu: Type = 163;
    pub const BPF_FUNC_for_each_map_elem: Type = 164;
    pub const BPF_FUNC_snprintf: Type = 165;
    pub const BPF_FUNC_sys_bpf: Type = 166;
    pub const BPF_FUNC_btf_find_by_name_kind: Type = 167;
    pub const BPF_FUNC_sys_close: Type = 168;
    pub const BPF_FUNC_timer_init: Type = 169;
    pub const BPF_FUNC_timer_set_callback: Type = 170;
    pub const BPF_FUNC_timer_start: Type = 171;
    pub const BPF_FUNC_timer_cancel: Type = 172;
    pub const BPF_FUNC_get_func_ip: Type = 173;
    pub const BPF_FUNC_get_attach_cookie: Type = 174;
    pub const BPF_FUNC_task_pt_regs: Type = 175;
    pub const BPF_FUNC_get_branch_snapshot: Type = 176;
    pub const BPF_FUNC_trace_vprintk: Type = 177;
    pub const BPF_FUNC_skc_to_unix_sock: Type = 178;
    pub const BPF_FUNC_kallsyms_lookup_name: Type = 179;
    pub const BPF_FUNC_find_vma: Type = 180;
    pub const BPF_FUNC_loop: Type = 181;
    pub const BPF_FUNC_strncmp: Type = 182;
    pub const BPF_FUNC_get_func_arg: Type = 183;
    pub const BPF_FUNC_get_func_ret: Type = 184;
    pub const BPF_FUNC_get_func_arg_cnt: Type = 185;
    pub const BPF_FUNC_get_retval: Type = 186;
    pub const BPF_FUNC_set_retval: Type = 187;
    pub const BPF_FUNC_xdp_get_buff_len: Type = 188;
    pub const BPF_FUNC_xdp_load_bytes: Type = 189;
    pub const BPF_FUNC_xdp_store_bytes: Type = 190;
    pub const BPF_FUNC_copy_from_user_task: Type = 191;
    pub const BPF_FUNC_skb_set_tstamp: Type = 192;
    pub const BPF_FUNC_ima_file_hash: Type = 193;
    pub const BPF_FUNC_kptr_xchg: Type = 194;
    pub const BPF_FUNC_map_lookup_percpu_elem: Type = 195;
    pub const BPF_FUNC_skc_to_mptcp_sock: Type = 196;
    pub const BPF_FUNC_dynptr_from_mem: Type = 197;
    pub const BPF_FUNC_ringbuf_reserve_dynptr: Type = 198;
    pub const BPF_FUNC_ringbuf_submit_dynptr: Type = 199;
    pub const BPF_FUNC_ringbuf_discard_dynptr: Type = 200;
    pub const BPF_FUNC_dynptr_read: Type = 201;
    pub const BPF_FUNC_dynptr_write: Type = 202;
    pub const BPF_FUNC_dynptr_data: Type = 203;
    pub const BPF_FUNC_tcp_raw_gen_syncookie_ipv4: Type = 204;
    pub const BPF_FUNC_tcp_raw_gen_syncookie_ipv6: Type = 205;
    pub const BPF_FUNC_tcp_raw_check_syncookie_ipv4: Type = 206;
    pub const BPF_FUNC_tcp_raw_check_syncookie_ipv6: Type = 207;
    pub const BPF_FUNC_ktime_get_tai_ns: Type = 208;
    pub const BPF_FUNC_user_ringbuf_drain: Type = 209;
    pub const BPF_FUNC_cgrp_storage_get: Type = 210;
    pub const BPF_FUNC_cgrp_storage_delete: Type = 211;
    pub const __BPF_FUNC_MAX_ID: Type = 212;
}
pub const BPF_F_RECOMPUTE_CSUM: _bindgen_ty_4 = 1;
pub const BPF_F_INVALIDATE_HASH: _bindgen_ty_4 = 2;
pub type _bindgen_ty_4 = ::aya_bpf_cty::c_uint;
pub const BPF_F_HDR_FIELD_MASK: _bindgen_ty_5 = 15;
pub type _bindgen_ty_5 = ::aya_bpf_cty::c_uint;
pub const BPF_F_PSEUDO_HDR: _bindgen_ty_6 = 16;
pub const BPF_F_MARK_MANGLED_0: _bindgen_ty_6 = 32;
pub const BPF_F_MARK_ENFORCE: _bindgen_ty_6 = 64;
pub type _bindgen_ty_6 = ::aya_bpf_cty::c_uint;
pub const BPF_F_INGRESS: _bindgen_ty_7 = 1;
pub type _bindgen_ty_7 = ::aya_bpf_cty::c_uint;
pub const BPF_F_TUNINFO_IPV6: _bindgen_ty_8 = 1;
pub type _bindgen_ty_8 = ::aya_bpf_cty::c_uint;
pub const BPF_F_SKIP_FIELD_MASK: _bindgen_ty_9 = 255;
pub const BPF_F_USER_STACK: _bindgen_ty_9 = 256;
pub const BPF_F_FAST_STACK_CMP: _bindgen_ty_9 = 512;
pub const BPF_F_REUSE_STACKID: _bindgen_ty_9 = 1024;
pub const BPF_F_USER_BUILD_ID: _bindgen_ty_9 = 2048;
pub type _bindgen_ty_9 = ::aya_bpf_cty::c_uint;
pub const BPF_F_ZERO_CSUM_TX: _bindgen_ty_10 = 2;
pub const BPF_F_DONT_FRAGMENT: _bindgen_ty_10 = 4;
pub const BPF_F_SEQ_NUMBER: _bindgen_ty_10 = 8;
pub const BPF_F_NO_TUNNEL_KEY: _bindgen_ty_10 = 16;
pub type _bindgen_ty_10 = ::aya_bpf_cty::c_uint;
pub const BPF_F_TUNINFO_FLAGS: _bindgen_ty_11 = 16;
pub type _bindgen_ty_11 = ::aya_bpf_cty::c_uint;
pub const BPF_F_INDEX_MASK: _bindgen_ty_12 = 4294967295;
pub const BPF_F_CURRENT_CPU: _bindgen_ty_12 = 4294967295;
pub const BPF_F_CTXLEN_MASK: _bindgen_ty_12 = 4503595332403200;
pub type _bindgen_ty_12 = ::aya_bpf_cty::c_ulong;
pub const BPF_F_CURRENT_NETNS: _bindgen_ty_13 = -1;
pub type _bindgen_ty_13 = ::aya_bpf_cty::c_int;
pub const BPF_CSUM_LEVEL_QUERY: _bindgen_ty_14 = 0;
pub const BPF_CSUM_LEVEL_INC: _bindgen_ty_14 = 1;
pub const BPF_CSUM_LEVEL_DEC: _bindgen_ty_14 = 2;
pub const BPF_CSUM_LEVEL_RESET: _bindgen_ty_14 = 3;
pub type _bindgen_ty_14 = ::aya_bpf_cty::c_uint;
pub const BPF_F_ADJ_ROOM_FIXED_GSO: _bindgen_ty_15 = 1;
pub const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: _bindgen_ty_15 = 2;
pub const BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: _bindgen_ty_15 = 4;
pub const BPF_F_ADJ_ROOM_ENCAP_L4_GRE: _bindgen_ty_15 = 8;
pub const BPF_F_ADJ_ROOM_ENCAP_L4_UDP: _bindgen_ty_15 = 16;
pub const BPF_F_ADJ_ROOM_NO_CSUM_RESET: _bindgen_ty_15 = 32;
pub const BPF_F_ADJ_ROOM_ENCAP_L2_ETH: _bindgen_ty_15 = 64;
pub const BPF_F_ADJ_ROOM_DECAP_L3_IPV4: _bindgen_ty_15 = 128;
pub const BPF_F_ADJ_ROOM_DECAP_L3_IPV6: _bindgen_ty_15 = 256;
pub type _bindgen_ty_15 = ::aya_bpf_cty::c_uint;
pub const BPF_ADJ_ROOM_ENCAP_L2_MASK: _bindgen_ty_16 = 255;
pub const BPF_ADJ_ROOM_ENCAP_L2_SHIFT: _bindgen_ty_16 = 56;
pub type _bindgen_ty_16 = ::aya_bpf_cty::c_uint;
pub const BPF_F_SYSCTL_BASE_NAME: _bindgen_ty_17 = 1;
pub type _bindgen_ty_17 = ::aya_bpf_cty::c_uint;
pub const BPF_LOCAL_STORAGE_GET_F_CREATE: _bindgen_ty_18 = 1;
pub const BPF_SK_STORAGE_GET_F_CREATE: _bindgen_ty_18 = 1;
pub type _bindgen_ty_18 = ::aya_bpf_cty::c_uint;
pub const BPF_F_GET_BRANCH_RECORDS_SIZE: _bindgen_ty_19 = 1;
pub type _bindgen_ty_19 = ::aya_bpf_cty::c_uint;
pub const BPF_RB_NO_WAKEUP: _bindgen_ty_20 = 1;
pub const BPF_RB_FORCE_WAKEUP: _bindgen_ty_20 = 2;
pub type _bindgen_ty_20 = ::aya_bpf_cty::c_uint;
pub const BPF_RB_AVAIL_DATA: _bindgen_ty_21 = 0;
pub const BPF_RB_RING_SIZE: _bindgen_ty_21 = 1;
pub const BPF_RB_CONS_POS: _bindgen_ty_21 = 2;
pub const BPF_RB_PROD_POS: _bindgen_ty_21 = 3;
pub type _bindgen_ty_21 = ::aya_bpf_cty::c_uint;
pub const BPF_RINGBUF_BUSY_BIT: _bindgen_ty_22 = 2147483648;
pub const BPF_RINGBUF_DISCARD_BIT: _bindgen_ty_22 = 1073741824;
pub const BPF_RINGBUF_HDR_SZ: _bindgen_ty_22 = 8;
pub type _bindgen_ty_22 = ::aya_bpf_cty::c_uint;
pub const BPF_SK_LOOKUP_F_REPLACE: _bindgen_ty_23 = 1;
pub const BPF_SK_LOOKUP_F_NO_REUSEPORT: _bindgen_ty_23 = 2;
pub type _bindgen_ty_23 = ::aya_bpf_cty::c_uint;
pub mod bpf_adj_room_mode {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_ADJ_ROOM_NET: Type = 0;
    pub const BPF_ADJ_ROOM_MAC: Type = 1;
}
pub mod bpf_hdr_start_off {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_HDR_START_MAC: Type = 0;
    pub const BPF_HDR_START_NET: Type = 1;
}
pub mod bpf_lwt_encap_mode {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_LWT_ENCAP_SEG6: Type = 0;
    pub const BPF_LWT_ENCAP_SEG6_INLINE: Type = 1;
    pub const BPF_LWT_ENCAP_IP: Type = 2;
}
pub const BPF_F_BPRM_SECUREEXEC: _bindgen_ty_24 = 1;
pub type _bindgen_ty_24 = ::aya_bpf_cty::c_uint;
pub const BPF_F_BROADCAST: _bindgen_ty_25 = 8;
pub const BPF_F_EXCLUDE_INGRESS: _bindgen_ty_25 = 16;
pub type _bindgen_ty_25 = ::aya_bpf_cty::c_uint;
pub mod _bindgen_ty_26 {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_SKB_TSTAMP_UNSPEC: Type = 0;
    pub const BPF_SKB_TSTAMP_DELIVERY_MONO: Type = 1;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __sk_buff {
    pub len: __u32,
    pub pkt_type: __u32,
    pub mark: __u32,
    pub queue_mapping: __u32,
    pub protocol: __u32,
    pub vlan_present: __u32,
    pub vlan_tci: __u32,
    pub vlan_proto: __u32,
    pub priority: __u32,
    pub ingress_ifindex: __u32,
    pub ifindex: __u32,
    pub tc_index: __u32,
    pub cb: [__u32; 5usize],
    pub hash: __u32,
    pub tc_classid: __u32,
    pub data: __u32,
    pub data_end: __u32,
    pub napi_id: __u32,
    pub family: __u32,
    pub remote_ip4: __u32,
    pub local_ip4: __u32,
    pub remote_ip6: [__u32; 4usize],
    pub local_ip6: [__u32; 4usize],
    pub remote_port: __u32,
    pub local_port: __u32,
    pub data_meta: __u32,
    pub __bindgen_anon_1: __sk_buff__bindgen_ty_1,
    pub tstamp: __u64,
    pub wire_len: __u32,
    pub gso_segs: __u32,
    pub __bindgen_anon_2: __sk_buff__bindgen_ty_2,
    pub gso_size: __u32,
    pub tstamp_type: __u8,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 3usize]>,
    pub hwtstamp: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union __sk_buff__bindgen_ty_1 {
    pub flow_keys: *mut bpf_flow_keys,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl __sk_buff__bindgen_ty_1 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union __sk_buff__bindgen_ty_2 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl __sk_buff__bindgen_ty_2 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
impl __sk_buff {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 3usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 3usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_tunnel_key {
    pub tunnel_id: __u32,
    pub __bindgen_anon_1: bpf_tunnel_key__bindgen_ty_1,
    pub tunnel_tos: __u8,
    pub tunnel_ttl: __u8,
    pub __bindgen_anon_2: bpf_tunnel_key__bindgen_ty_2,
    pub tunnel_label: __u32,
    pub __bindgen_anon_3: bpf_tunnel_key__bindgen_ty_3,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_tunnel_key__bindgen_ty_1 {
    pub remote_ipv4: __u32,
    pub remote_ipv6: [__u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_tunnel_key__bindgen_ty_2 {
    pub tunnel_ext: __u16,
    pub tunnel_flags: __be16,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_tunnel_key__bindgen_ty_3 {
    pub local_ipv4: __u32,
    pub local_ipv6: [__u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_xfrm_state {
    pub reqid: __u32,
    pub spi: __u32,
    pub family: __u16,
    pub ext: __u16,
    pub __bindgen_anon_1: bpf_xfrm_state__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_xfrm_state__bindgen_ty_1 {
    pub remote_ipv4: __u32,
    pub remote_ipv6: [__u32; 4usize],
}
pub mod bpf_ret_code {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_OK: Type = 0;
    pub const BPF_DROP: Type = 2;
    pub const BPF_REDIRECT: Type = 7;
    pub const BPF_LWT_REROUTE: Type = 128;
    pub const BPF_FLOW_DISSECTOR_CONTINUE: Type = 129;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sock {
    pub bound_dev_if: __u32,
    pub family: __u32,
    pub type_: __u32,
    pub protocol: __u32,
    pub mark: __u32,
    pub priority: __u32,
    pub src_ip4: __u32,
    pub src_ip6: [__u32; 4usize],
    pub src_port: __u32,
    pub dst_port: __be16,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize]>,
    pub dst_ip4: __u32,
    pub dst_ip6: [__u32; 4usize],
    pub state: __u32,
    pub rx_queue_mapping: __s32,
}
impl bpf_sock {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 2usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 2usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_tcp_sock {
    pub snd_cwnd: __u32,
    pub srtt_us: __u32,
    pub rtt_min: __u32,
    pub snd_ssthresh: __u32,
    pub rcv_nxt: __u32,
    pub snd_nxt: __u32,
    pub snd_una: __u32,
    pub mss_cache: __u32,
    pub ecn_flags: __u32,
    pub rate_delivered: __u32,
    pub rate_interval_us: __u32,
    pub packets_out: __u32,
    pub retrans_out: __u32,
    pub total_retrans: __u32,
    pub segs_in: __u32,
    pub data_segs_in: __u32,
    pub segs_out: __u32,
    pub data_segs_out: __u32,
    pub lost_out: __u32,
    pub sacked_out: __u32,
    pub bytes_received: __u64,
    pub bytes_acked: __u64,
    pub dsack_dups: __u32,
    pub delivered: __u32,
    pub delivered_ce: __u32,
    pub icsk_retransmits: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sock_tuple {
    pub __bindgen_anon_1: bpf_sock_tuple__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_tuple__bindgen_ty_1 {
    pub ipv4: bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1,
    pub ipv6: bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
    pub saddr: __be32,
    pub daddr: __be32,
    pub sport: __be16,
    pub dport: __be16,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2 {
    pub saddr: [__be32; 4usize],
    pub daddr: [__be32; 4usize],
    pub sport: __be16,
    pub dport: __be16,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_xdp_sock {
    pub queue_id: __u32,
}
pub mod xdp_action {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const XDP_ABORTED: Type = 0;
    pub const XDP_DROP: Type = 1;
    pub const XDP_PASS: Type = 2;
    pub const XDP_TX: Type = 3;
    pub const XDP_REDIRECT: Type = 4;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xdp_md {
    pub data: __u32,
    pub data_end: __u32,
    pub data_meta: __u32,
    pub ingress_ifindex: __u32,
    pub rx_queue_index: __u32,
    pub egress_ifindex: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_devmap_val {
    pub ifindex: __u32,
    pub bpf_prog: bpf_devmap_val__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_devmap_val__bindgen_ty_1 {
    pub fd: ::aya_bpf_cty::c_int,
    pub id: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_cpumap_val {
    pub qsize: __u32,
    pub bpf_prog: bpf_cpumap_val__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_cpumap_val__bindgen_ty_1 {
    pub fd: ::aya_bpf_cty::c_int,
    pub id: __u32,
}
pub mod sk_action {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const SK_DROP: Type = 0;
    pub const SK_PASS: Type = 1;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sk_msg_md {
    pub __bindgen_anon_1: sk_msg_md__bindgen_ty_1,
    pub __bindgen_anon_2: sk_msg_md__bindgen_ty_2,
    pub family: __u32,
    pub remote_ip4: __u32,
    pub local_ip4: __u32,
    pub remote_ip6: [__u32; 4usize],
    pub local_ip6: [__u32; 4usize],
    pub remote_port: __u32,
    pub local_port: __u32,
    pub size: __u32,
    pub __bindgen_anon_3: sk_msg_md__bindgen_ty_3,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_msg_md__bindgen_ty_1 {
    pub data: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_msg_md__bindgen_ty_1 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_msg_md__bindgen_ty_2 {
    pub data_end: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_msg_md__bindgen_ty_2 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_msg_md__bindgen_ty_3 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_msg_md__bindgen_ty_3 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sk_reuseport_md {
    pub __bindgen_anon_1: sk_reuseport_md__bindgen_ty_1,
    pub __bindgen_anon_2: sk_reuseport_md__bindgen_ty_2,
    pub len: __u32,
    pub eth_protocol: __u32,
    pub ip_protocol: __u32,
    pub bind_inany: __u32,
    pub hash: __u32,
    pub __bindgen_anon_3: sk_reuseport_md__bindgen_ty_3,
    pub __bindgen_anon_4: sk_reuseport_md__bindgen_ty_4,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_reuseport_md__bindgen_ty_1 {
    pub data: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_reuseport_md__bindgen_ty_1 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_reuseport_md__bindgen_ty_2 {
    pub data_end: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_reuseport_md__bindgen_ty_2 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_reuseport_md__bindgen_ty_3 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_reuseport_md__bindgen_ty_3 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sk_reuseport_md__bindgen_ty_4 {
    pub migrating_sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl sk_reuseport_md__bindgen_ty_4 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_prog_info {
    pub type_: __u32,
    pub id: __u32,
    pub tag: [__u8; 8usize],
    pub jited_prog_len: __u32,
    pub xlated_prog_len: __u32,
    pub jited_prog_insns: __u64,
    pub xlated_prog_insns: __u64,
    pub load_time: __u64,
    pub created_by_uid: __u32,
    pub nr_map_ids: __u32,
    pub map_ids: __u64,
    pub name: [::aya_bpf_cty::c_char; 16usize],
    pub ifindex: __u32,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize]>,
    pub netns_dev: __u64,
    pub netns_ino: __u64,
    pub nr_jited_ksyms: __u32,
    pub nr_jited_func_lens: __u32,
    pub jited_ksyms: __u64,
    pub jited_func_lens: __u64,
    pub btf_id: __u32,
    pub func_info_rec_size: __u32,
    pub func_info: __u64,
    pub nr_func_info: __u32,
    pub nr_line_info: __u32,
    pub line_info: __u64,
    pub jited_line_info: __u64,
    pub nr_jited_line_info: __u32,
    pub line_info_rec_size: __u32,
    pub jited_line_info_rec_size: __u32,
    pub nr_prog_tags: __u32,
    pub prog_tags: __u64,
    pub run_time_ns: __u64,
    pub run_cnt: __u64,
    pub recursion_misses: __u64,
    pub verified_insns: __u32,
    pub attach_btf_obj_id: __u32,
    pub attach_btf_id: __u32,
}
impl bpf_prog_info {
    #[inline]
    pub fn gpl_compatible(&self) -> __u32 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_gpl_compatible(&mut self, val: __u32) {
        unsafe {
            let val: u32 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(gpl_compatible: __u32) -> __BindgenBitfieldUnit<[u8; 4usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 4usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let gpl_compatible: u32 = unsafe { ::core::mem::transmute(gpl_compatible) };
            gpl_compatible as u64
        });
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_map_info {
    pub type_: __u32,
    pub id: __u32,
    pub key_size: __u32,
    pub value_size: __u32,
    pub max_entries: __u32,
    pub map_flags: __u32,
    pub name: [::aya_bpf_cty::c_char; 16usize],
    pub ifindex: __u32,
    pub btf_vmlinux_value_type_id: __u32,
    pub netns_dev: __u64,
    pub netns_ino: __u64,
    pub btf_id: __u32,
    pub btf_key_type_id: __u32,
    pub btf_value_type_id: __u32,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize]>,
    pub map_extra: __u64,
}
impl bpf_map_info {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 4usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 4usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_btf_info {
    pub btf: __u64,
    pub btf_size: __u32,
    pub id: __u32,
    pub name: __u64,
    pub name_len: __u32,
    pub kernel_btf: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_link_info {
    pub type_: __u32,
    pub id: __u32,
    pub prog_id: __u32,
    pub __bindgen_anon_1: bpf_link_info__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_link_info__bindgen_ty_1 {
    pub raw_tracepoint: bpf_link_info__bindgen_ty_1__bindgen_ty_1,
    pub tracing: bpf_link_info__bindgen_ty_1__bindgen_ty_2,
    pub cgroup: bpf_link_info__bindgen_ty_1__bindgen_ty_3,
    pub iter: bpf_link_info__bindgen_ty_1__bindgen_ty_4,
    pub netns: bpf_link_info__bindgen_ty_1__bindgen_ty_5,
    pub xdp: bpf_link_info__bindgen_ty_1__bindgen_ty_6,
    pub struct_ops: bpf_link_info__bindgen_ty_1__bindgen_ty_7,
    pub netfilter: bpf_link_info__bindgen_ty_1__bindgen_ty_8,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_1 {
    pub tp_name: __u64,
    pub tp_name_len: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_2 {
    pub attach_type: __u32,
    pub target_obj_id: __u32,
    pub target_btf_id: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_3 {
    pub cgroup_id: __u64,
    pub attach_type: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_4 {
    pub target_name: __u64,
    pub target_name_len: __u32,
    pub __bindgen_anon_1: bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_2,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1 {
    pub map: bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1 {
    pub map_id: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_2 {
    pub cgroup: bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_2__bindgen_ty_1,
    pub task: bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_2__bindgen_ty_2,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_2__bindgen_ty_1 {
    pub cgroup_id: __u64,
    pub order: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_2__bindgen_ty_2 {
    pub tid: __u32,
    pub pid: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_5 {
    pub netns_ino: __u32,
    pub attach_type: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_6 {
    pub ifindex: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_7 {
    pub map_id: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_link_info__bindgen_ty_1__bindgen_ty_8 {
    pub pf: __u32,
    pub hooknum: __u32,
    pub priority: __s32,
    pub flags: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sock_addr {
    pub user_family: __u32,
    pub user_ip4: __u32,
    pub user_ip6: [__u32; 4usize],
    pub user_port: __u32,
    pub family: __u32,
    pub type_: __u32,
    pub protocol: __u32,
    pub msg_src_ip4: __u32,
    pub msg_src_ip6: [__u32; 4usize],
    pub __bindgen_anon_1: bpf_sock_addr__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_addr__bindgen_ty_1 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sock_addr__bindgen_ty_1 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sock_ops {
    pub op: __u32,
    pub __bindgen_anon_1: bpf_sock_ops__bindgen_ty_1,
    pub family: __u32,
    pub remote_ip4: __u32,
    pub local_ip4: __u32,
    pub remote_ip6: [__u32; 4usize],
    pub local_ip6: [__u32; 4usize],
    pub remote_port: __u32,
    pub local_port: __u32,
    pub is_fullsock: __u32,
    pub snd_cwnd: __u32,
    pub srtt_us: __u32,
    pub bpf_sock_ops_cb_flags: __u32,
    pub state: __u32,
    pub rtt_min: __u32,
    pub snd_ssthresh: __u32,
    pub rcv_nxt: __u32,
    pub snd_nxt: __u32,
    pub snd_una: __u32,
    pub mss_cache: __u32,
    pub ecn_flags: __u32,
    pub rate_delivered: __u32,
    pub rate_interval_us: __u32,
    pub packets_out: __u32,
    pub retrans_out: __u32,
    pub total_retrans: __u32,
    pub segs_in: __u32,
    pub data_segs_in: __u32,
    pub segs_out: __u32,
    pub data_segs_out: __u32,
    pub lost_out: __u32,
    pub sacked_out: __u32,
    pub sk_txhash: __u32,
    pub bytes_received: __u64,
    pub bytes_acked: __u64,
    pub __bindgen_anon_2: bpf_sock_ops__bindgen_ty_2,
    pub __bindgen_anon_3: bpf_sock_ops__bindgen_ty_3,
    pub __bindgen_anon_4: bpf_sock_ops__bindgen_ty_4,
    pub skb_len: __u32,
    pub skb_tcp_flags: __u32,
    pub skb_hwtstamp: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_1 {
    pub args: [__u32; 4usize],
    pub reply: __u32,
    pub replylong: [__u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_2 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sock_ops__bindgen_ty_2 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_3 {
    pub skb_data: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sock_ops__bindgen_ty_3 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_4 {
    pub skb_data_end: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sock_ops__bindgen_ty_4 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
pub const BPF_SOCK_OPS_RTO_CB_FLAG: _bindgen_ty_27 = 1;
pub const BPF_SOCK_OPS_RETRANS_CB_FLAG: _bindgen_ty_27 = 2;
pub const BPF_SOCK_OPS_STATE_CB_FLAG: _bindgen_ty_27 = 4;
pub const BPF_SOCK_OPS_RTT_CB_FLAG: _bindgen_ty_27 = 8;
pub const BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG: _bindgen_ty_27 = 16;
pub const BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG: _bindgen_ty_27 = 32;
pub const BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG: _bindgen_ty_27 = 64;
pub const BPF_SOCK_OPS_ALL_CB_FLAGS: _bindgen_ty_27 = 127;
pub type _bindgen_ty_27 = ::aya_bpf_cty::c_uint;
pub const BPF_SOCK_OPS_VOID: _bindgen_ty_28 = 0;
pub const BPF_SOCK_OPS_TIMEOUT_INIT: _bindgen_ty_28 = 1;
pub const BPF_SOCK_OPS_RWND_INIT: _bindgen_ty_28 = 2;
pub const BPF_SOCK_OPS_TCP_CONNECT_CB: _bindgen_ty_28 = 3;
pub const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: _bindgen_ty_28 = 4;
pub const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: _bindgen_ty_28 = 5;
pub const BPF_SOCK_OPS_NEEDS_ECN: _bindgen_ty_28 = 6;
pub const BPF_SOCK_OPS_BASE_RTT: _bindgen_ty_28 = 7;
pub const BPF_SOCK_OPS_RTO_CB: _bindgen_ty_28 = 8;
pub const BPF_SOCK_OPS_RETRANS_CB: _bindgen_ty_28 = 9;
pub const BPF_SOCK_OPS_STATE_CB: _bindgen_ty_28 = 10;
pub const BPF_SOCK_OPS_TCP_LISTEN_CB: _bindgen_ty_28 = 11;
pub const BPF_SOCK_OPS_RTT_CB: _bindgen_ty_28 = 12;
pub const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: _bindgen_ty_28 = 13;
pub const BPF_SOCK_OPS_HDR_OPT_LEN_CB: _bindgen_ty_28 = 14;
pub const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: _bindgen_ty_28 = 15;
pub type _bindgen_ty_28 = ::aya_bpf_cty::c_uint;
pub const BPF_TCP_ESTABLISHED: _bindgen_ty_29 = 1;
pub const BPF_TCP_SYN_SENT: _bindgen_ty_29 = 2;
pub const BPF_TCP_SYN_RECV: _bindgen_ty_29 = 3;
pub const BPF_TCP_FIN_WAIT1: _bindgen_ty_29 = 4;
pub const BPF_TCP_FIN_WAIT2: _bindgen_ty_29 = 5;
pub const BPF_TCP_TIME_WAIT: _bindgen_ty_29 = 6;
pub const BPF_TCP_CLOSE: _bindgen_ty_29 = 7;
pub const BPF_TCP_CLOSE_WAIT: _bindgen_ty_29 = 8;
pub const BPF_TCP_LAST_ACK: _bindgen_ty_29 = 9;
pub const BPF_TCP_LISTEN: _bindgen_ty_29 = 10;
pub const BPF_TCP_CLOSING: _bindgen_ty_29 = 11;
pub const BPF_TCP_NEW_SYN_RECV: _bindgen_ty_29 = 12;
pub const BPF_TCP_MAX_STATES: _bindgen_ty_29 = 13;
pub type _bindgen_ty_29 = ::aya_bpf_cty::c_uint;
pub mod _bindgen_ty_31 {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_LOAD_HDR_OPT_TCP_SYN: Type = 1;
}
pub mod _bindgen_ty_32 {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_WRITE_HDR_TCP_CURRENT_MSS: Type = 1;
    pub const BPF_WRITE_HDR_TCP_SYNACK_COOKIE: Type = 2;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_value {
    pub counter: __u64,
    pub enabled: __u64,
    pub running: __u64,
}
pub const BPF_DEVCG_ACC_MKNOD: _bindgen_ty_33 = 1;
pub const BPF_DEVCG_ACC_READ: _bindgen_ty_33 = 2;
pub const BPF_DEVCG_ACC_WRITE: _bindgen_ty_33 = 4;
pub type _bindgen_ty_33 = ::aya_bpf_cty::c_uint;
pub const BPF_DEVCG_DEV_BLOCK: _bindgen_ty_34 = 1;
pub const BPF_DEVCG_DEV_CHAR: _bindgen_ty_34 = 2;
pub type _bindgen_ty_34 = ::aya_bpf_cty::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_cgroup_dev_ctx {
    pub access_type: __u32,
    pub major: __u32,
    pub minor: __u32,
}
#[repr(C)]
#[derive(Debug)]
pub struct bpf_raw_tracepoint_args {
    pub args: __IncompleteArrayField<__u64>,
}
pub const BPF_FIB_LOOKUP_DIRECT: _bindgen_ty_35 = 1;
pub const BPF_FIB_LOOKUP_OUTPUT: _bindgen_ty_35 = 2;
pub const BPF_FIB_LOOKUP_SKIP_NEIGH: _bindgen_ty_35 = 4;
pub type _bindgen_ty_35 = ::aya_bpf_cty::c_uint;
pub const BPF_FIB_LKUP_RET_SUCCESS: _bindgen_ty_36 = 0;
pub const BPF_FIB_LKUP_RET_BLACKHOLE: _bindgen_ty_36 = 1;
pub const BPF_FIB_LKUP_RET_UNREACHABLE: _bindgen_ty_36 = 2;
pub const BPF_FIB_LKUP_RET_PROHIBIT: _bindgen_ty_36 = 3;
pub const BPF_FIB_LKUP_RET_NOT_FWDED: _bindgen_ty_36 = 4;
pub const BPF_FIB_LKUP_RET_FWD_DISABLED: _bindgen_ty_36 = 5;
pub const BPF_FIB_LKUP_RET_UNSUPP_LWT: _bindgen_ty_36 = 6;
pub const BPF_FIB_LKUP_RET_NO_NEIGH: _bindgen_ty_36 = 7;
pub const BPF_FIB_LKUP_RET_FRAG_NEEDED: _bindgen_ty_36 = 8;
pub type _bindgen_ty_36 = ::aya_bpf_cty::c_uint;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_fib_lookup {
    pub family: __u8,
    pub l4_protocol: __u8,
    pub sport: __be16,
    pub dport: __be16,
    pub __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1,
    pub ifindex: __u32,
    pub __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2,
    pub __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3,
    pub __bindgen_anon_4: bpf_fib_lookup__bindgen_ty_4,
    pub h_vlan_proto: __be16,
    pub h_vlan_TCI: __be16,
    pub smac: [__u8; 6usize],
    pub dmac: [__u8; 6usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_1 {
    pub tot_len: __u16,
    pub mtu_result: __u16,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_2 {
    pub tos: __u8,
    pub flowinfo: __be32,
    pub rt_metric: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_3 {
    pub ipv4_src: __be32,
    pub ipv6_src: [__u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_4 {
    pub ipv4_dst: __be32,
    pub ipv6_dst: [__u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_redir_neigh {
    pub nh_family: __u32,
    pub __bindgen_anon_1: bpf_redir_neigh__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_redir_neigh__bindgen_ty_1 {
    pub ipv4_nh: __be32,
    pub ipv6_nh: [__u32; 4usize],
}
pub mod bpf_check_mtu_flags {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_MTU_CHK_SEGS: Type = 1;
}
pub mod bpf_check_mtu_ret {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_MTU_CHK_RET_SUCCESS: Type = 0;
    pub const BPF_MTU_CHK_RET_FRAG_NEEDED: Type = 1;
    pub const BPF_MTU_CHK_RET_SEGS_TOOBIG: Type = 2;
}
pub mod bpf_task_fd_type {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_FD_TYPE_RAW_TRACEPOINT: Type = 0;
    pub const BPF_FD_TYPE_TRACEPOINT: Type = 1;
    pub const BPF_FD_TYPE_KPROBE: Type = 2;
    pub const BPF_FD_TYPE_KRETPROBE: Type = 3;
    pub const BPF_FD_TYPE_UPROBE: Type = 4;
    pub const BPF_FD_TYPE_URETPROBE: Type = 5;
}
pub const BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG: _bindgen_ty_37 = 1;
pub const BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL: _bindgen_ty_37 = 2;
pub const BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP: _bindgen_ty_37 = 4;
pub type _bindgen_ty_37 = ::aya_bpf_cty::c_uint;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_flow_keys {
    pub nhoff: __u16,
    pub thoff: __u16,
    pub addr_proto: __u16,
    pub is_frag: __u8,
    pub is_first_frag: __u8,
    pub is_encap: __u8,
    pub ip_proto: __u8,
    pub n_proto: __be16,
    pub sport: __be16,
    pub dport: __be16,
    pub __bindgen_anon_1: bpf_flow_keys__bindgen_ty_1,
    pub flags: __u32,
    pub flow_label: __be32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_flow_keys__bindgen_ty_1 {
    pub __bindgen_anon_1: bpf_flow_keys__bindgen_ty_1__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_flow_keys__bindgen_ty_1__bindgen_ty_2,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_flow_keys__bindgen_ty_1__bindgen_ty_1 {
    pub ipv4_src: __be32,
    pub ipv4_dst: __be32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_flow_keys__bindgen_ty_1__bindgen_ty_2 {
    pub ipv6_src: [__u32; 4usize],
    pub ipv6_dst: [__u32; 4usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_func_info {
    pub insn_off: __u32,
    pub type_id: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_line_info {
    pub insn_off: __u32,
    pub file_name_off: __u32,
    pub line_off: __u32,
    pub line_col: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_spin_lock {
    pub val: __u32,
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_timer {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 16usize]>,
}
impl bpf_timer {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 16usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 16usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_dynptr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 16usize]>,
}
impl bpf_dynptr {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 16usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 16usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_list_head {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 16usize]>,
}
impl bpf_list_head {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 16usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 16usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_list_node {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 16usize]>,
}
impl bpf_list_node {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 16usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 16usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_rb_root {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 16usize]>,
}
impl bpf_rb_root {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 16usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 16usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_rb_node {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 24usize]>,
}
impl bpf_rb_node {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 24usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 24usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[repr(align(4))]
#[derive(Debug, Copy, Clone)]
pub struct bpf_refcount {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize]>,
}
impl bpf_refcount {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 4usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 4usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sysctl {
    pub write: __u32,
    pub file_pos: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sockopt {
    pub __bindgen_anon_1: bpf_sockopt__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_sockopt__bindgen_ty_2,
    pub __bindgen_anon_3: bpf_sockopt__bindgen_ty_3,
    pub level: __s32,
    pub optname: __s32,
    pub optlen: __s32,
    pub retval: __s32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sockopt__bindgen_ty_1 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sockopt__bindgen_ty_1 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sockopt__bindgen_ty_2 {
    pub optval: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sockopt__bindgen_ty_2 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sockopt__bindgen_ty_3 {
    pub optval_end: *mut ::aya_bpf_cty::c_void,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sockopt__bindgen_ty_3 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_pidns_info {
    pub pid: __u32,
    pub tgid: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sk_lookup {
    pub __bindgen_anon_1: bpf_sk_lookup__bindgen_ty_1,
    pub family: __u32,
    pub protocol: __u32,
    pub remote_ip4: __u32,
    pub remote_ip6: [__u32; 4usize],
    pub remote_port: __be16,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize]>,
    pub local_ip4: __u32,
    pub local_ip6: [__u32; 4usize],
    pub local_port: __u32,
    pub ingress_ifindex: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sk_lookup__bindgen_ty_1 {
    pub __bindgen_anon_1: bpf_sk_lookup__bindgen_ty_1__bindgen_ty_1,
    pub cookie: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sk_lookup__bindgen_ty_1__bindgen_ty_1 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl bpf_sk_lookup__bindgen_ty_1__bindgen_ty_1 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
impl bpf_sk_lookup {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 2usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 2usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_ptr {
    pub ptr: *mut ::aya_bpf_cty::c_void,
    pub type_id: __u32,
    pub flags: __u32,
}
pub mod bpf_core_relo_kind {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_CORE_FIELD_BYTE_OFFSET: Type = 0;
    pub const BPF_CORE_FIELD_BYTE_SIZE: Type = 1;
    pub const BPF_CORE_FIELD_EXISTS: Type = 2;
    pub const BPF_CORE_FIELD_SIGNED: Type = 3;
    pub const BPF_CORE_FIELD_LSHIFT_U64: Type = 4;
    pub const BPF_CORE_FIELD_RSHIFT_U64: Type = 5;
    pub const BPF_CORE_TYPE_ID_LOCAL: Type = 6;
    pub const BPF_CORE_TYPE_ID_TARGET: Type = 7;
    pub const BPF_CORE_TYPE_EXISTS: Type = 8;
    pub const BPF_CORE_TYPE_SIZE: Type = 9;
    pub const BPF_CORE_ENUMVAL_EXISTS: Type = 10;
    pub const BPF_CORE_ENUMVAL_VALUE: Type = 11;
    pub const BPF_CORE_TYPE_MATCHES: Type = 12;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_core_relo {
    pub insn_off: __u32,
    pub type_id: __u32,
    pub access_str_off: __u32,
    pub kind: bpf_core_relo_kind::Type,
}
pub const BPF_F_TIMER_ABS: _bindgen_ty_39 = 1;
pub type _bindgen_ty_39 = ::aya_bpf_cty::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_iter_num {
    pub __opaque: [__u64; 1usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_regs_struct {
    pub pc: ::aya_bpf_cty::c_ulong,
    pub ra: ::aya_bpf_cty::c_ulong,
    pub sp: ::aya_bpf_cty::c_ulong,
    pub gp: ::aya_bpf_cty::c_ulong,
    pub tp: ::aya_bpf_cty::c_ulong,
    pub t0: ::aya_bpf_cty::c_ulong,
    pub t1: ::aya_bpf_cty::c_ulong,
    pub t2: ::aya_bpf_cty::c_ulong,
    pub s0: ::aya_bpf_cty::c_ulong,
    pub s1: ::aya_bpf_cty::c_ulong,
    pub a0: ::aya_bpf_cty::c_ulong,
    pub a1: ::aya_bpf_cty::c_ulong,
    pub a2: ::aya_bpf_cty::c_ulong,
    pub a3: ::aya_bpf_cty::c_ulong,
    pub a4: ::aya_bpf_cty::c_ulong,
    pub a5: ::aya_bpf_cty::c_ulong,
    pub a6: ::aya_bpf_cty::c_ulong,
    pub a7: ::aya_bpf_cty::c_ulong,
    pub s2: ::aya_bpf_cty::c_ulong,
    pub s3: ::aya_bpf_cty::c_ulong,
    pub s4: ::aya_bpf_cty::c_ulong,
    pub s5: ::aya_bpf_cty::c_ulong,
    pub s6: ::aya_bpf_cty::c_ulong,
    pub s7: ::aya_bpf_cty::c_ulong,
    pub s8: ::aya_bpf_cty::c_ulong,
    pub s9: ::aya_bpf_cty::c_ulong,
    pub s10: ::aya_bpf_cty::c_ulong,
    pub s11: ::aya_bpf_cty::c_ulong,
    pub t3: ::aya_bpf_cty::c_ulong,
    pub t4: ::aya_bpf_cty::c_ulong,
    pub t5: ::aya_bpf_cty::c_ulong,
    pub t6: ::aya_bpf_cty::c_ulong,
}
pub type sa_family_t = ::aya_bpf_cty::c_ushort;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [::aya_bpf_cty::c_char; 14usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_data {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct linux_binprm {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pt_regs {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcphdr {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct seq_file {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcp6_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcp_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcp_timewait_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcp_request_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct udp6_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct unix_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct task_struct {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cgroup {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct path {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct inode {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct socket {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct file {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mptcp_sock {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iphdr {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipv6hdr {
    _unused: [u8; 0],
}
