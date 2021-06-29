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
pub const SO_PREFER_BUSY_POLL: u32 = 69;
pub const SO_BUSY_POLL_BUDGET: u32 = 70;
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
pub type __u16 = ::aya_bpf_cty::c_ushort;
pub type __s32 = ::aya_bpf_cty::c_int;
pub type __u32 = ::aya_bpf_cty::c_uint;
pub type __s64 = ::aya_bpf_cty::c_longlong;
pub type __u64 = ::aya_bpf_cty::c_ulonglong;
pub type __be16 = __u16;
pub type __be32 = __u32;
pub type __wsum = __u32;
pub const BPF_REG_0: ::aya_bpf_cty::c_uint = 0;
pub const BPF_REG_1: ::aya_bpf_cty::c_uint = 1;
pub const BPF_REG_2: ::aya_bpf_cty::c_uint = 2;
pub const BPF_REG_3: ::aya_bpf_cty::c_uint = 3;
pub const BPF_REG_4: ::aya_bpf_cty::c_uint = 4;
pub const BPF_REG_5: ::aya_bpf_cty::c_uint = 5;
pub const BPF_REG_6: ::aya_bpf_cty::c_uint = 6;
pub const BPF_REG_7: ::aya_bpf_cty::c_uint = 7;
pub const BPF_REG_8: ::aya_bpf_cty::c_uint = 8;
pub const BPF_REG_9: ::aya_bpf_cty::c_uint = 9;
pub const BPF_REG_10: ::aya_bpf_cty::c_uint = 10;
pub const __MAX_BPF_REG: ::aya_bpf_cty::c_uint = 11;
pub type _bindgen_ty_1 = ::aya_bpf_cty::c_uint;
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
}
pub const BPF_ANY: ::aya_bpf_cty::c_uint = 0;
pub const BPF_NOEXIST: ::aya_bpf_cty::c_uint = 1;
pub const BPF_EXIST: ::aya_bpf_cty::c_uint = 2;
pub const BPF_F_LOCK: ::aya_bpf_cty::c_uint = 4;
pub type _bindgen_ty_2 = ::aya_bpf_cty::c_uint;
pub const BPF_F_NO_PREALLOC: ::aya_bpf_cty::c_uint = 1;
pub const BPF_F_NO_COMMON_LRU: ::aya_bpf_cty::c_uint = 2;
pub const BPF_F_NUMA_NODE: ::aya_bpf_cty::c_uint = 4;
pub const BPF_F_RDONLY: ::aya_bpf_cty::c_uint = 8;
pub const BPF_F_WRONLY: ::aya_bpf_cty::c_uint = 16;
pub const BPF_F_STACK_BUILD_ID: ::aya_bpf_cty::c_uint = 32;
pub const BPF_F_ZERO_SEED: ::aya_bpf_cty::c_uint = 64;
pub const BPF_F_RDONLY_PROG: ::aya_bpf_cty::c_uint = 128;
pub const BPF_F_WRONLY_PROG: ::aya_bpf_cty::c_uint = 256;
pub const BPF_F_CLONE: ::aya_bpf_cty::c_uint = 512;
pub const BPF_F_MMAPABLE: ::aya_bpf_cty::c_uint = 1024;
pub const BPF_F_PRESERVE_ELEMS: ::aya_bpf_cty::c_uint = 2048;
pub const BPF_F_INNER_MAP: ::aya_bpf_cty::c_uint = 4096;
pub type _bindgen_ty_3 = ::aya_bpf_cty::c_uint;
pub const BPF_F_RECOMPUTE_CSUM: ::aya_bpf_cty::c_uint = 1;
pub const BPF_F_INVALIDATE_HASH: ::aya_bpf_cty::c_uint = 2;
pub type _bindgen_ty_4 = ::aya_bpf_cty::c_uint;
pub const BPF_F_HDR_FIELD_MASK: ::aya_bpf_cty::c_uint = 15;
pub type _bindgen_ty_5 = ::aya_bpf_cty::c_uint;
pub const BPF_F_PSEUDO_HDR: ::aya_bpf_cty::c_uint = 16;
pub const BPF_F_MARK_MANGLED_0: ::aya_bpf_cty::c_uint = 32;
pub const BPF_F_MARK_ENFORCE: ::aya_bpf_cty::c_uint = 64;
pub type _bindgen_ty_6 = ::aya_bpf_cty::c_uint;
pub const BPF_F_INGRESS: ::aya_bpf_cty::c_uint = 1;
pub type _bindgen_ty_7 = ::aya_bpf_cty::c_uint;
pub const BPF_F_TUNINFO_IPV6: ::aya_bpf_cty::c_uint = 1;
pub type _bindgen_ty_8 = ::aya_bpf_cty::c_uint;
pub const BPF_F_SKIP_FIELD_MASK: ::aya_bpf_cty::c_uint = 255;
pub const BPF_F_USER_STACK: ::aya_bpf_cty::c_uint = 256;
pub const BPF_F_FAST_STACK_CMP: ::aya_bpf_cty::c_uint = 512;
pub const BPF_F_REUSE_STACKID: ::aya_bpf_cty::c_uint = 1024;
pub const BPF_F_USER_BUILD_ID: ::aya_bpf_cty::c_uint = 2048;
pub type _bindgen_ty_9 = ::aya_bpf_cty::c_uint;
pub const BPF_F_ZERO_CSUM_TX: ::aya_bpf_cty::c_uint = 2;
pub const BPF_F_DONT_FRAGMENT: ::aya_bpf_cty::c_uint = 4;
pub const BPF_F_SEQ_NUMBER: ::aya_bpf_cty::c_uint = 8;
pub type _bindgen_ty_10 = ::aya_bpf_cty::c_uint;
pub const BPF_F_INDEX_MASK: ::aya_bpf_cty::c_ulong = 4294967295;
pub const BPF_F_CURRENT_CPU: ::aya_bpf_cty::c_ulong = 4294967295;
pub const BPF_F_CTXLEN_MASK: ::aya_bpf_cty::c_ulong = 4503595332403200;
pub type _bindgen_ty_11 = ::aya_bpf_cty::c_ulong;
pub const BPF_F_CURRENT_NETNS: ::aya_bpf_cty::c_int = -1;
pub type _bindgen_ty_12 = ::aya_bpf_cty::c_int;
pub const BPF_CSUM_LEVEL_QUERY: ::aya_bpf_cty::c_uint = 0;
pub const BPF_CSUM_LEVEL_INC: ::aya_bpf_cty::c_uint = 1;
pub const BPF_CSUM_LEVEL_DEC: ::aya_bpf_cty::c_uint = 2;
pub const BPF_CSUM_LEVEL_RESET: ::aya_bpf_cty::c_uint = 3;
pub type _bindgen_ty_13 = ::aya_bpf_cty::c_uint;
pub const BPF_F_ADJ_ROOM_FIXED_GSO: ::aya_bpf_cty::c_uint = 1;
pub const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: ::aya_bpf_cty::c_uint = 2;
pub const BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: ::aya_bpf_cty::c_uint = 4;
pub const BPF_F_ADJ_ROOM_ENCAP_L4_GRE: ::aya_bpf_cty::c_uint = 8;
pub const BPF_F_ADJ_ROOM_ENCAP_L4_UDP: ::aya_bpf_cty::c_uint = 16;
pub const BPF_F_ADJ_ROOM_NO_CSUM_RESET: ::aya_bpf_cty::c_uint = 32;
pub const BPF_F_ADJ_ROOM_ENCAP_L2_ETH: ::aya_bpf_cty::c_uint = 64;
pub type _bindgen_ty_14 = ::aya_bpf_cty::c_uint;
pub const BPF_ADJ_ROOM_ENCAP_L2_MASK: ::aya_bpf_cty::c_uint = 255;
pub const BPF_ADJ_ROOM_ENCAP_L2_SHIFT: ::aya_bpf_cty::c_uint = 56;
pub type _bindgen_ty_15 = ::aya_bpf_cty::c_uint;
pub const BPF_F_SYSCTL_BASE_NAME: ::aya_bpf_cty::c_uint = 1;
pub type _bindgen_ty_16 = ::aya_bpf_cty::c_uint;
pub const BPF_LOCAL_STORAGE_GET_F_CREATE: ::aya_bpf_cty::c_uint = 1;
pub const BPF_SK_STORAGE_GET_F_CREATE: ::aya_bpf_cty::c_uint = 1;
pub type _bindgen_ty_17 = ::aya_bpf_cty::c_uint;
pub const BPF_F_GET_BRANCH_RECORDS_SIZE: ::aya_bpf_cty::c_uint = 1;
pub type _bindgen_ty_18 = ::aya_bpf_cty::c_uint;
pub const BPF_RB_NO_WAKEUP: ::aya_bpf_cty::c_uint = 1;
pub const BPF_RB_FORCE_WAKEUP: ::aya_bpf_cty::c_uint = 2;
pub type _bindgen_ty_19 = ::aya_bpf_cty::c_uint;
pub const BPF_RB_AVAIL_DATA: ::aya_bpf_cty::c_uint = 0;
pub const BPF_RB_RING_SIZE: ::aya_bpf_cty::c_uint = 1;
pub const BPF_RB_CONS_POS: ::aya_bpf_cty::c_uint = 2;
pub const BPF_RB_PROD_POS: ::aya_bpf_cty::c_uint = 3;
pub type _bindgen_ty_20 = ::aya_bpf_cty::c_uint;
pub const BPF_RINGBUF_BUSY_BIT: ::aya_bpf_cty::c_uint = 2147483648;
pub const BPF_RINGBUF_DISCARD_BIT: ::aya_bpf_cty::c_uint = 1073741824;
pub const BPF_RINGBUF_HDR_SZ: ::aya_bpf_cty::c_uint = 8;
pub type _bindgen_ty_21 = ::aya_bpf_cty::c_uint;
pub const BPF_SK_LOOKUP_F_REPLACE: ::aya_bpf_cty::c_uint = 1;
pub const BPF_SK_LOOKUP_F_NO_REUSEPORT: ::aya_bpf_cty::c_uint = 2;
pub type _bindgen_ty_22 = ::aya_bpf_cty::c_uint;
pub mod bpf_adj_room_mode {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_ADJ_ROOM_NET: Type = 0;
    pub const BPF_ADJ_ROOM_MAC: Type = 1;
}
pub const BPF_F_BPRM_SECUREEXEC: ::aya_bpf_cty::c_uint = 1;
pub type _bindgen_ty_23 = ::aya_bpf_cty::c_uint;
pub const BPF_F_BROADCAST: ::aya_bpf_cty::c_uint = 8;
pub const BPF_F_EXCLUDE_INGRESS: ::aya_bpf_cty::c_uint = 16;
pub type _bindgen_ty_24 = ::aya_bpf_cty::c_uint;
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
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union __sk_buff__bindgen_ty_1 {
    pub flow_keys: *mut bpf_flow_keys,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
}
impl __sk_buff__bindgen_ty_2 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
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
    pub tunnel_ext: __u16,
    pub tunnel_label: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_tunnel_key__bindgen_ty_1 {
    pub remote_ipv4: __u32,
    pub remote_ipv6: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
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
    _bindgen_union_align: [u32; 4usize],
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
    pub dst_port: __u32,
    pub dst_ip4: __u32,
    pub dst_ip6: [__u32; 4usize],
    pub state: __u32,
    pub rx_queue_mapping: __s32,
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
    _bindgen_union_align: [u32; 9usize],
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_1 {
    pub args: [__u32; 4usize],
    pub reply: __u32,
    pub replylong: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_2 {
    pub sk: *mut bpf_sock,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
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
    _bindgen_union_align: u64,
}
impl bpf_sock_ops__bindgen_ty_4 {
    #[inline]
    pub fn new_bitfield_1() -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit
    }
}
pub const BPF_SOCK_OPS_RTO_CB_FLAG: ::aya_bpf_cty::c_uint = 1;
pub const BPF_SOCK_OPS_RETRANS_CB_FLAG: ::aya_bpf_cty::c_uint = 2;
pub const BPF_SOCK_OPS_STATE_CB_FLAG: ::aya_bpf_cty::c_uint = 4;
pub const BPF_SOCK_OPS_RTT_CB_FLAG: ::aya_bpf_cty::c_uint = 8;
pub const BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG: ::aya_bpf_cty::c_uint = 16;
pub const BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG: ::aya_bpf_cty::c_uint = 32;
pub const BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG: ::aya_bpf_cty::c_uint = 64;
pub const BPF_SOCK_OPS_ALL_CB_FLAGS: ::aya_bpf_cty::c_uint = 127;
pub type _bindgen_ty_25 = ::aya_bpf_cty::c_uint;
pub const BPF_SOCK_OPS_VOID: ::aya_bpf_cty::c_uint = 0;
pub const BPF_SOCK_OPS_TIMEOUT_INIT: ::aya_bpf_cty::c_uint = 1;
pub const BPF_SOCK_OPS_RWND_INIT: ::aya_bpf_cty::c_uint = 2;
pub const BPF_SOCK_OPS_TCP_CONNECT_CB: ::aya_bpf_cty::c_uint = 3;
pub const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: ::aya_bpf_cty::c_uint = 4;
pub const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: ::aya_bpf_cty::c_uint = 5;
pub const BPF_SOCK_OPS_NEEDS_ECN: ::aya_bpf_cty::c_uint = 6;
pub const BPF_SOCK_OPS_BASE_RTT: ::aya_bpf_cty::c_uint = 7;
pub const BPF_SOCK_OPS_RTO_CB: ::aya_bpf_cty::c_uint = 8;
pub const BPF_SOCK_OPS_RETRANS_CB: ::aya_bpf_cty::c_uint = 9;
pub const BPF_SOCK_OPS_STATE_CB: ::aya_bpf_cty::c_uint = 10;
pub const BPF_SOCK_OPS_TCP_LISTEN_CB: ::aya_bpf_cty::c_uint = 11;
pub const BPF_SOCK_OPS_RTT_CB: ::aya_bpf_cty::c_uint = 12;
pub const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: ::aya_bpf_cty::c_uint = 13;
pub const BPF_SOCK_OPS_HDR_OPT_LEN_CB: ::aya_bpf_cty::c_uint = 14;
pub const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: ::aya_bpf_cty::c_uint = 15;
pub type _bindgen_ty_26 = ::aya_bpf_cty::c_uint;
pub const BPF_TCP_ESTABLISHED: ::aya_bpf_cty::c_uint = 1;
pub const BPF_TCP_SYN_SENT: ::aya_bpf_cty::c_uint = 2;
pub const BPF_TCP_SYN_RECV: ::aya_bpf_cty::c_uint = 3;
pub const BPF_TCP_FIN_WAIT1: ::aya_bpf_cty::c_uint = 4;
pub const BPF_TCP_FIN_WAIT2: ::aya_bpf_cty::c_uint = 5;
pub const BPF_TCP_TIME_WAIT: ::aya_bpf_cty::c_uint = 6;
pub const BPF_TCP_CLOSE: ::aya_bpf_cty::c_uint = 7;
pub const BPF_TCP_CLOSE_WAIT: ::aya_bpf_cty::c_uint = 8;
pub const BPF_TCP_LAST_ACK: ::aya_bpf_cty::c_uint = 9;
pub const BPF_TCP_LISTEN: ::aya_bpf_cty::c_uint = 10;
pub const BPF_TCP_CLOSING: ::aya_bpf_cty::c_uint = 11;
pub const BPF_TCP_NEW_SYN_RECV: ::aya_bpf_cty::c_uint = 12;
pub const BPF_TCP_MAX_STATES: ::aya_bpf_cty::c_uint = 13;
pub type _bindgen_ty_27 = ::aya_bpf_cty::c_uint;
pub mod _bindgen_ty_29 {
    pub type Type = ::aya_bpf_cty::c_uint;
    pub const BPF_LOAD_HDR_OPT_TCP_SYN: Type = 1;
}
pub mod _bindgen_ty_30 {
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
pub const BPF_DEVCG_ACC_MKNOD: ::aya_bpf_cty::c_uint = 1;
pub const BPF_DEVCG_ACC_READ: ::aya_bpf_cty::c_uint = 2;
pub const BPF_DEVCG_ACC_WRITE: ::aya_bpf_cty::c_uint = 4;
pub type _bindgen_ty_31 = ::aya_bpf_cty::c_uint;
pub const BPF_DEVCG_DEV_BLOCK: ::aya_bpf_cty::c_uint = 1;
pub const BPF_DEVCG_DEV_CHAR: ::aya_bpf_cty::c_uint = 2;
pub type _bindgen_ty_32 = ::aya_bpf_cty::c_uint;
pub const BPF_FIB_LOOKUP_DIRECT: ::aya_bpf_cty::c_uint = 1;
pub const BPF_FIB_LOOKUP_OUTPUT: ::aya_bpf_cty::c_uint = 2;
pub type _bindgen_ty_33 = ::aya_bpf_cty::c_uint;
pub const BPF_FIB_LKUP_RET_SUCCESS: ::aya_bpf_cty::c_uint = 0;
pub const BPF_FIB_LKUP_RET_BLACKHOLE: ::aya_bpf_cty::c_uint = 1;
pub const BPF_FIB_LKUP_RET_UNREACHABLE: ::aya_bpf_cty::c_uint = 2;
pub const BPF_FIB_LKUP_RET_PROHIBIT: ::aya_bpf_cty::c_uint = 3;
pub const BPF_FIB_LKUP_RET_NOT_FWDED: ::aya_bpf_cty::c_uint = 4;
pub const BPF_FIB_LKUP_RET_FWD_DISABLED: ::aya_bpf_cty::c_uint = 5;
pub const BPF_FIB_LKUP_RET_UNSUPP_LWT: ::aya_bpf_cty::c_uint = 6;
pub const BPF_FIB_LKUP_RET_NO_NEIGH: ::aya_bpf_cty::c_uint = 7;
pub const BPF_FIB_LKUP_RET_FRAG_NEEDED: ::aya_bpf_cty::c_uint = 8;
pub type _bindgen_ty_34 = ::aya_bpf_cty::c_uint;
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
    _bindgen_union_align: u16,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_2 {
    pub tos: __u8,
    pub flowinfo: __be32,
    pub rt_metric: __u32,
    _bindgen_union_align: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_3 {
    pub ipv4_src: __be32,
    pub ipv6_src: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_4 {
    pub ipv4_dst: __be32,
    pub ipv6_dst: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
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
    _bindgen_union_align: [u32; 4usize],
}
pub const BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG: ::aya_bpf_cty::c_uint = 1;
pub const BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL: ::aya_bpf_cty::c_uint = 2;
pub const BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP: ::aya_bpf_cty::c_uint = 4;
pub type _bindgen_ty_35 = ::aya_bpf_cty::c_uint;
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
    _bindgen_union_align: [u32; 8usize],
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
pub struct bpf_spin_lock {
    pub val: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sysctl {
    pub write: __u32,
    pub file_pos: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_pidns_info {
    pub pid: __u32,
    pub tgid: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_ptr {
    pub ptr: *mut ::aya_bpf_cty::c_void,
    pub type_id: __u32,
    pub flags: __u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pt_regs {
    pub r15: ::aya_bpf_cty::c_ulong,
    pub r14: ::aya_bpf_cty::c_ulong,
    pub r13: ::aya_bpf_cty::c_ulong,
    pub r12: ::aya_bpf_cty::c_ulong,
    pub rbp: ::aya_bpf_cty::c_ulong,
    pub rbx: ::aya_bpf_cty::c_ulong,
    pub r11: ::aya_bpf_cty::c_ulong,
    pub r10: ::aya_bpf_cty::c_ulong,
    pub r9: ::aya_bpf_cty::c_ulong,
    pub r8: ::aya_bpf_cty::c_ulong,
    pub rax: ::aya_bpf_cty::c_ulong,
    pub rcx: ::aya_bpf_cty::c_ulong,
    pub rdx: ::aya_bpf_cty::c_ulong,
    pub rsi: ::aya_bpf_cty::c_ulong,
    pub rdi: ::aya_bpf_cty::c_ulong,
    pub orig_rax: ::aya_bpf_cty::c_ulong,
    pub rip: ::aya_bpf_cty::c_ulong,
    pub cs: ::aya_bpf_cty::c_ulong,
    pub eflags: ::aya_bpf_cty::c_ulong,
    pub rsp: ::aya_bpf_cty::c_ulong,
    pub ss: ::aya_bpf_cty::c_ulong,
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
pub struct task_struct {
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
