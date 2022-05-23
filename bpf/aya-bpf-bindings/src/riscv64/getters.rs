use super::bindings::*;
impl<Storage> __BindgenBitfieldUnit<Storage> {}
impl bpf_insn {
    pub fn code(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.code) }.ok()
    }
    pub fn off(&self) -> Option<__s16> {
        unsafe { crate::bpf_probe_read(&self.off) }.ok()
    }
    pub fn imm(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.imm) }.ok()
    }
}
impl bpf_lpm_trie_key {
    pub fn prefixlen(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prefixlen) }.ok()
    }
    pub fn data(&self) -> Option<__IncompleteArrayField<__u8>> {
        unsafe { crate::bpf_probe_read(&self.data) }.ok()
    }
}
impl bpf_cgroup_storage_key {
    pub fn cgroup_inode_id(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.cgroup_inode_id) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
}
impl bpf_iter_link_info {
    pub fn map(&self) -> Option<bpf_iter_link_info__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.map) }.ok()
    }
}
impl bpf_iter_link_info__bindgen_ty_1 {
    pub fn map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_fd) }.ok()
    }
}
impl bpf_stack_build_id {
    pub fn status(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.status) }.ok()
    }
    pub fn build_id(&self) -> Option<[::aya_bpf_cty::c_uchar; 20usize]> {
        unsafe { crate::bpf_probe_read(&self.build_id) }.ok()
    }
    pub fn offset(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.offset) }.ok()
    }
    pub fn ip(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ip) }.ok()
    }
}
impl bpf_stack_build_id__bindgen_ty_1 {
    pub fn offset(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.offset) }.ok()
    }
    pub fn ip(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.ip) }.ok()
    }
}
impl bpf_attr {
    pub fn map_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map_type) }.ok()
    }
    pub fn key_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.key_size) }.ok()
    }
    pub fn value_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.value_size) }.ok()
    }
    pub fn max_entries(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.max_entries) }.ok()
    }
    pub fn map_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map_flags) }.ok()
    }
    pub fn inner_map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.inner_map_fd) }.ok()
    }
    pub fn numa_node(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.numa_node) }.ok()
    }
    pub fn map_name(&self) -> Option<[::aya_bpf_cty::c_char; 16usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map_name) }.ok()
    }
    pub fn map_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map_ifindex) }.ok()
    }
    pub fn btf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.btf_fd) }.ok()
    }
    pub fn btf_key_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.btf_key_type_id) }.ok()
    }
    pub fn btf_value_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.btf_value_type_id) }.ok()
    }
    pub fn btf_vmlinux_value_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.btf_vmlinux_value_type_id) }.ok()
    }
    pub fn map_extra(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map_extra) }.ok()
    }
    pub fn map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.map_fd) }.ok()
    }
    pub fn key(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.key) }.ok()
    }
    pub fn value(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.__bindgen_anon_1.value) }.ok()
    }
    pub fn next_key(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.__bindgen_anon_1.next_key) }.ok()
    }
    pub fn flags(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.flags) }.ok()
    }
    pub fn batch(&self) -> Option<bpf_attr__bindgen_ty_3> {
        unsafe { crate::bpf_probe_read(&self.batch) }.ok()
    }
    pub fn prog_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.prog_type) }.ok()
    }
    pub fn insn_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.insn_cnt) }.ok()
    }
    pub fn insns(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.insns) }.ok()
    }
    pub fn license(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.license) }.ok()
    }
    pub fn log_level(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.log_level) }.ok()
    }
    pub fn log_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.log_size) }.ok()
    }
    pub fn log_buf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.log_buf) }.ok()
    }
    pub fn kern_version(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.kern_version) }.ok()
    }
    pub fn prog_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.prog_flags) }.ok()
    }
    pub fn prog_name(&self) -> Option<[::aya_bpf_cty::c_char; 16usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.prog_name) }.ok()
    }
    pub fn prog_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.prog_ifindex) }.ok()
    }
    pub fn expected_attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.expected_attach_type) }.ok()
    }
    pub fn prog_btf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.prog_btf_fd) }.ok()
    }
    pub fn func_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.func_info_rec_size) }.ok()
    }
    pub fn func_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.func_info) }.ok()
    }
    pub fn func_info_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.func_info_cnt) }.ok()
    }
    pub fn line_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.line_info_rec_size) }.ok()
    }
    pub fn line_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.line_info) }.ok()
    }
    pub fn line_info_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.line_info_cnt) }.ok()
    }
    pub fn attach_btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.attach_btf_id) }.ok()
    }
    pub fn attach_prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.__bindgen_anon_1.attach_prog_fd) }
            .ok()
    }
    pub fn attach_btf_obj_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.__bindgen_anon_1.attach_btf_obj_fd) }
            .ok()
    }
    pub fn core_relo_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.core_relo_cnt) }.ok()
    }
    pub fn fd_array(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.fd_array) }.ok()
    }
    pub fn core_relos(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.core_relos) }.ok()
    }
    pub fn core_relo_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.core_relo_rec_size) }.ok()
    }
    pub fn pathname(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.pathname) }.ok()
    }
    pub fn bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.bpf_fd) }.ok()
    }
    pub fn file_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.file_flags) }.ok()
    }
    pub fn target_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_5.target_fd) }.ok()
    }
    pub fn attach_bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_5.attach_bpf_fd) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_5.attach_type) }.ok()
    }
    pub fn attach_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_5.attach_flags) }.ok()
    }
    pub fn replace_bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_5.replace_bpf_fd) }.ok()
    }
    pub fn test(&self) -> Option<bpf_attr__bindgen_ty_7> {
        unsafe { crate::bpf_probe_read(&self.test) }.ok()
    }
    pub fn start_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.__bindgen_anon_1.start_id) }.ok()
    }
    pub fn prog_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.__bindgen_anon_1.prog_id) }.ok()
    }
    pub fn map_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.__bindgen_anon_1.map_id) }.ok()
    }
    pub fn btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.__bindgen_anon_1.btf_id) }.ok()
    }
    pub fn link_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.__bindgen_anon_1.link_id) }.ok()
    }
    pub fn next_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.next_id) }.ok()
    }
    pub fn open_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_6.open_flags) }.ok()
    }
    pub fn info(&self) -> Option<bpf_attr__bindgen_ty_9> {
        unsafe { crate::bpf_probe_read(&self.info) }.ok()
    }
    pub fn query(&self) -> Option<bpf_attr__bindgen_ty_10> {
        unsafe { crate::bpf_probe_read(&self.query) }.ok()
    }
    pub fn raw_tracepoint(&self) -> Option<bpf_attr__bindgen_ty_11> {
        unsafe { crate::bpf_probe_read(&self.raw_tracepoint) }.ok()
    }
    pub fn btf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_7.btf) }.ok()
    }
    pub fn btf_log_buf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_7.btf_log_buf) }.ok()
    }
    pub fn btf_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_7.btf_size) }.ok()
    }
    pub fn btf_log_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_7.btf_log_size) }.ok()
    }
    pub fn btf_log_level(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_7.btf_log_level) }.ok()
    }
    pub fn task_fd_query(&self) -> Option<bpf_attr__bindgen_ty_13> {
        unsafe { crate::bpf_probe_read(&self.task_fd_query) }.ok()
    }
    pub fn link_create(&self) -> Option<bpf_attr__bindgen_ty_14> {
        unsafe { crate::bpf_probe_read(&self.link_create) }.ok()
    }
    pub fn link_update(&self) -> Option<bpf_attr__bindgen_ty_15> {
        unsafe { crate::bpf_probe_read(&self.link_update) }.ok()
    }
    pub fn link_detach(&self) -> Option<bpf_attr__bindgen_ty_16> {
        unsafe { crate::bpf_probe_read(&self.link_detach) }.ok()
    }
    pub fn enable_stats(&self) -> Option<bpf_attr__bindgen_ty_17> {
        unsafe { crate::bpf_probe_read(&self.enable_stats) }.ok()
    }
    pub fn iter_create(&self) -> Option<bpf_attr__bindgen_ty_18> {
        unsafe { crate::bpf_probe_read(&self.iter_create) }.ok()
    }
    pub fn prog_bind_map(&self) -> Option<bpf_attr__bindgen_ty_19> {
        unsafe { crate::bpf_probe_read(&self.prog_bind_map) }.ok()
    }
}
impl bpf_attr__bindgen_ty_1 {
    pub fn map_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_type) }.ok()
    }
    pub fn key_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.key_size) }.ok()
    }
    pub fn value_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.value_size) }.ok()
    }
    pub fn max_entries(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.max_entries) }.ok()
    }
    pub fn map_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_flags) }.ok()
    }
    pub fn inner_map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.inner_map_fd) }.ok()
    }
    pub fn numa_node(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.numa_node) }.ok()
    }
    pub fn map_name(&self) -> Option<[::aya_bpf_cty::c_char; 16usize]> {
        unsafe { crate::bpf_probe_read(&self.map_name) }.ok()
    }
    pub fn map_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_ifindex) }.ok()
    }
    pub fn btf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_fd) }.ok()
    }
    pub fn btf_key_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_key_type_id) }.ok()
    }
    pub fn btf_value_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_value_type_id) }.ok()
    }
    pub fn btf_vmlinux_value_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_vmlinux_value_type_id) }.ok()
    }
    pub fn map_extra(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.map_extra) }.ok()
    }
}
impl bpf_attr__bindgen_ty_2 {
    pub fn map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_fd) }.ok()
    }
    pub fn key(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.key) }.ok()
    }
    pub fn value(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.value) }.ok()
    }
    pub fn next_key(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.next_key) }.ok()
    }
    pub fn flags(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
}
impl bpf_attr__bindgen_ty_2__bindgen_ty_1 {
    pub fn value(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.value) }.ok()
    }
    pub fn next_key(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.next_key) }.ok()
    }
}
impl bpf_attr__bindgen_ty_3 {
    pub fn in_batch(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.in_batch) }.ok()
    }
    pub fn out_batch(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.out_batch) }.ok()
    }
    pub fn keys(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.keys) }.ok()
    }
    pub fn values(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.values) }.ok()
    }
    pub fn count(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.count) }.ok()
    }
    pub fn map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_fd) }.ok()
    }
    pub fn elem_flags(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.elem_flags) }.ok()
    }
    pub fn flags(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
}
impl bpf_attr__bindgen_ty_4 {
    pub fn prog_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_type) }.ok()
    }
    pub fn insn_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.insn_cnt) }.ok()
    }
    pub fn insns(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.insns) }.ok()
    }
    pub fn license(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.license) }.ok()
    }
    pub fn log_level(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.log_level) }.ok()
    }
    pub fn log_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.log_size) }.ok()
    }
    pub fn log_buf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.log_buf) }.ok()
    }
    pub fn kern_version(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.kern_version) }.ok()
    }
    pub fn prog_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_flags) }.ok()
    }
    pub fn prog_name(&self) -> Option<[::aya_bpf_cty::c_char; 16usize]> {
        unsafe { crate::bpf_probe_read(&self.prog_name) }.ok()
    }
    pub fn prog_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_ifindex) }.ok()
    }
    pub fn expected_attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.expected_attach_type) }.ok()
    }
    pub fn prog_btf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_btf_fd) }.ok()
    }
    pub fn func_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.func_info_rec_size) }.ok()
    }
    pub fn func_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.func_info) }.ok()
    }
    pub fn func_info_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.func_info_cnt) }.ok()
    }
    pub fn line_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.line_info_rec_size) }.ok()
    }
    pub fn line_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.line_info) }.ok()
    }
    pub fn line_info_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.line_info_cnt) }.ok()
    }
    pub fn attach_btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_btf_id) }.ok()
    }
    pub fn attach_prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.attach_prog_fd) }.ok()
    }
    pub fn attach_btf_obj_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.attach_btf_obj_fd) }.ok()
    }
    pub fn core_relo_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.core_relo_cnt) }.ok()
    }
    pub fn fd_array(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.fd_array) }.ok()
    }
    pub fn core_relos(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.core_relos) }.ok()
    }
    pub fn core_relo_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.core_relo_rec_size) }.ok()
    }
}
impl bpf_attr__bindgen_ty_4__bindgen_ty_1 {
    pub fn attach_prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_prog_fd) }.ok()
    }
    pub fn attach_btf_obj_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_btf_obj_fd) }.ok()
    }
}
impl bpf_attr__bindgen_ty_5 {
    pub fn pathname(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.pathname) }.ok()
    }
    pub fn bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.bpf_fd) }.ok()
    }
    pub fn file_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.file_flags) }.ok()
    }
}
impl bpf_attr__bindgen_ty_6 {
    pub fn target_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_fd) }.ok()
    }
    pub fn attach_bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_bpf_fd) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
    pub fn attach_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_flags) }.ok()
    }
    pub fn replace_bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.replace_bpf_fd) }.ok()
    }
}
impl bpf_attr__bindgen_ty_7 {
    pub fn prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_fd) }.ok()
    }
    pub fn retval(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.retval) }.ok()
    }
    pub fn data_size_in(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_size_in) }.ok()
    }
    pub fn data_size_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_size_out) }.ok()
    }
    pub fn data_in(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.data_in) }.ok()
    }
    pub fn data_out(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.data_out) }.ok()
    }
    pub fn repeat(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.repeat) }.ok()
    }
    pub fn duration(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.duration) }.ok()
    }
    pub fn ctx_size_in(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ctx_size_in) }.ok()
    }
    pub fn ctx_size_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ctx_size_out) }.ok()
    }
    pub fn ctx_in(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.ctx_in) }.ok()
    }
    pub fn ctx_out(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.ctx_out) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
    pub fn cpu(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.cpu) }.ok()
    }
    pub fn batch_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.batch_size) }.ok()
    }
}
impl bpf_attr__bindgen_ty_8 {
    pub fn start_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.start_id) }.ok()
    }
    pub fn prog_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.prog_id) }.ok()
    }
    pub fn map_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map_id) }.ok()
    }
    pub fn btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.btf_id) }.ok()
    }
    pub fn link_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.link_id) }.ok()
    }
    pub fn next_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.next_id) }.ok()
    }
    pub fn open_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.open_flags) }.ok()
    }
}
impl bpf_attr__bindgen_ty_8__bindgen_ty_1 {
    pub fn start_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.start_id) }.ok()
    }
    pub fn prog_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_id) }.ok()
    }
    pub fn map_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_id) }.ok()
    }
    pub fn btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_id) }.ok()
    }
    pub fn link_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.link_id) }.ok()
    }
}
impl bpf_attr__bindgen_ty_9 {
    pub fn bpf_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.bpf_fd) }.ok()
    }
    pub fn info_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.info_len) }.ok()
    }
    pub fn info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.info) }.ok()
    }
}
impl bpf_attr__bindgen_ty_10 {
    pub fn target_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_fd) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
    pub fn query_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.query_flags) }.ok()
    }
    pub fn attach_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_flags) }.ok()
    }
    pub fn prog_ids(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.prog_ids) }.ok()
    }
    pub fn prog_cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_cnt) }.ok()
    }
}
impl bpf_attr__bindgen_ty_11 {
    pub fn name(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.name) }.ok()
    }
    pub fn prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_fd) }.ok()
    }
}
impl bpf_attr__bindgen_ty_12 {
    pub fn btf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.btf) }.ok()
    }
    pub fn btf_log_buf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.btf_log_buf) }.ok()
    }
    pub fn btf_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_size) }.ok()
    }
    pub fn btf_log_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_log_size) }.ok()
    }
    pub fn btf_log_level(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_log_level) }.ok()
    }
}
impl bpf_attr__bindgen_ty_13 {
    pub fn pid(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.pid) }.ok()
    }
    pub fn fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.fd) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
    pub fn buf_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.buf_len) }.ok()
    }
    pub fn buf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.buf) }.ok()
    }
    pub fn prog_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_id) }.ok()
    }
    pub fn fd_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.fd_type) }.ok()
    }
    pub fn probe_offset(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.probe_offset) }.ok()
    }
    pub fn probe_addr(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.probe_addr) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14 {
    pub fn prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_fd) }.ok()
    }
    pub fn target_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.target_fd) }.ok()
    }
    pub fn target_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.target_ifindex) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
    pub fn target_btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.target_btf_id) }.ok()
    }
    pub fn iter_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.__bindgen_anon_1.iter_info) }.ok()
    }
    pub fn iter_info_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.__bindgen_anon_1.iter_info_len) }.ok()
    }
    pub fn perf_event(&self) -> Option<bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_2> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.perf_event) }.ok()
    }
    pub fn kprobe_multi(&self) -> Option<bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_3> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.kprobe_multi) }.ok()
    }
    pub fn tracing(&self) -> Option<bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_4> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.tracing) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14__bindgen_ty_1 {
    pub fn target_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_fd) }.ok()
    }
    pub fn target_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_ifindex) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14__bindgen_ty_2 {
    pub fn target_btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_btf_id) }.ok()
    }
    pub fn iter_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.iter_info) }.ok()
    }
    pub fn iter_info_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.iter_info_len) }.ok()
    }
    pub fn perf_event(&self) -> Option<bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_2> {
        unsafe { crate::bpf_probe_read(&self.perf_event) }.ok()
    }
    pub fn kprobe_multi(&self) -> Option<bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_3> {
        unsafe { crate::bpf_probe_read(&self.kprobe_multi) }.ok()
    }
    pub fn tracing(&self) -> Option<bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_4> {
        unsafe { crate::bpf_probe_read(&self.tracing) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_1 {
    pub fn iter_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.iter_info) }.ok()
    }
    pub fn iter_info_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.iter_info_len) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_2 {
    pub fn bpf_cookie(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.bpf_cookie) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_3 {
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
    pub fn cnt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.cnt) }.ok()
    }
    pub fn syms(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.syms) }.ok()
    }
    pub fn addrs(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.addrs) }.ok()
    }
    pub fn cookies(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.cookies) }.ok()
    }
}
impl bpf_attr__bindgen_ty_14__bindgen_ty_2__bindgen_ty_4 {
    pub fn target_btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_btf_id) }.ok()
    }
    pub fn cookie(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.cookie) }.ok()
    }
}
impl bpf_attr__bindgen_ty_15 {
    pub fn link_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.link_fd) }.ok()
    }
    pub fn new_prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.new_prog_fd) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
    pub fn old_prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.old_prog_fd) }.ok()
    }
}
impl bpf_attr__bindgen_ty_16 {
    pub fn link_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.link_fd) }.ok()
    }
}
impl bpf_attr__bindgen_ty_17 {
    pub fn type_(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_) }.ok()
    }
}
impl bpf_attr__bindgen_ty_18 {
    pub fn link_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.link_fd) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
}
impl bpf_attr__bindgen_ty_19 {
    pub fn prog_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_fd) }.ok()
    }
    pub fn map_fd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_fd) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
}
impl __sk_buff {
    pub fn len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.len) }.ok()
    }
    pub fn pkt_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.pkt_type) }.ok()
    }
    pub fn mark(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.mark) }.ok()
    }
    pub fn queue_mapping(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.queue_mapping) }.ok()
    }
    pub fn protocol(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.protocol) }.ok()
    }
    pub fn vlan_present(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.vlan_present) }.ok()
    }
    pub fn vlan_tci(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.vlan_tci) }.ok()
    }
    pub fn vlan_proto(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.vlan_proto) }.ok()
    }
    pub fn priority(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.priority) }.ok()
    }
    pub fn ingress_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ingress_ifindex) }.ok()
    }
    pub fn ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ifindex) }.ok()
    }
    pub fn tc_index(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.tc_index) }.ok()
    }
    pub fn cb(&self) -> Option<[__u32; 5usize]> {
        unsafe { crate::bpf_probe_read(&self.cb) }.ok()
    }
    pub fn hash(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.hash) }.ok()
    }
    pub fn tc_classid(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.tc_classid) }.ok()
    }
    pub fn data(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data) }.ok()
    }
    pub fn data_end(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_end) }.ok()
    }
    pub fn napi_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.napi_id) }.ok()
    }
    pub fn family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn remote_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ip4) }.ok()
    }
    pub fn local_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_ip4) }.ok()
    }
    pub fn remote_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ip6) }.ok()
    }
    pub fn local_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.local_ip6) }.ok()
    }
    pub fn remote_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_port) }.ok()
    }
    pub fn local_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_port) }.ok()
    }
    pub fn data_meta(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_meta) }.ok()
    }
    pub fn flow_keys(&self) -> Option<*mut bpf_flow_keys> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.flow_keys) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn tstamp(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.tstamp) }.ok()
    }
    pub fn wire_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.wire_len) }.ok()
    }
    pub fn gso_segs(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.gso_segs) }.ok()
    }
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn gso_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.gso_size) }.ok()
    }
    pub fn tstamp_type(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.tstamp_type) }.ok()
    }
    pub fn hwtstamp(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.hwtstamp) }.ok()
    }
}
impl __sk_buff__bindgen_ty_1 {
    pub fn flow_keys(&self) -> Option<*mut bpf_flow_keys> {
        let v = unsafe { crate::bpf_probe_read(&self.flow_keys) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl __sk_buff__bindgen_ty_2 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_tunnel_key {
    pub fn tunnel_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.tunnel_id) }.ok()
    }
    pub fn remote_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.remote_ipv4) }.ok()
    }
    pub fn remote_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.remote_ipv6) }.ok()
    }
    pub fn tunnel_tos(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.tunnel_tos) }.ok()
    }
    pub fn tunnel_ttl(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.tunnel_ttl) }.ok()
    }
    pub fn tunnel_ext(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.tunnel_ext) }.ok()
    }
    pub fn tunnel_label(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.tunnel_label) }.ok()
    }
    pub fn local_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.local_ipv4) }.ok()
    }
    pub fn local_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.local_ipv6) }.ok()
    }
}
impl bpf_tunnel_key__bindgen_ty_1 {
    pub fn remote_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ipv4) }.ok()
    }
    pub fn remote_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ipv6) }.ok()
    }
}
impl bpf_tunnel_key__bindgen_ty_2 {
    pub fn local_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_ipv4) }.ok()
    }
    pub fn local_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.local_ipv6) }.ok()
    }
}
impl bpf_xfrm_state {
    pub fn reqid(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.reqid) }.ok()
    }
    pub fn spi(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.spi) }.ok()
    }
    pub fn family(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn ext(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.ext) }.ok()
    }
    pub fn remote_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.remote_ipv4) }.ok()
    }
    pub fn remote_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.remote_ipv6) }.ok()
    }
}
impl bpf_xfrm_state__bindgen_ty_1 {
    pub fn remote_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ipv4) }.ok()
    }
    pub fn remote_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ipv6) }.ok()
    }
}
impl bpf_sock {
    pub fn bound_dev_if(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.bound_dev_if) }.ok()
    }
    pub fn family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn type_(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_) }.ok()
    }
    pub fn protocol(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.protocol) }.ok()
    }
    pub fn mark(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.mark) }.ok()
    }
    pub fn priority(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.priority) }.ok()
    }
    pub fn src_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.src_ip4) }.ok()
    }
    pub fn src_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.src_ip6) }.ok()
    }
    pub fn src_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.src_port) }.ok()
    }
    pub fn dst_port(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.dst_port) }.ok()
    }
    pub fn dst_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.dst_ip4) }.ok()
    }
    pub fn dst_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.dst_ip6) }.ok()
    }
    pub fn state(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.state) }.ok()
    }
    pub fn rx_queue_mapping(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.rx_queue_mapping) }.ok()
    }
}
impl bpf_tcp_sock {
    pub fn snd_cwnd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_cwnd) }.ok()
    }
    pub fn srtt_us(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.srtt_us) }.ok()
    }
    pub fn rtt_min(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rtt_min) }.ok()
    }
    pub fn snd_ssthresh(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_ssthresh) }.ok()
    }
    pub fn rcv_nxt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rcv_nxt) }.ok()
    }
    pub fn snd_nxt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_nxt) }.ok()
    }
    pub fn snd_una(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_una) }.ok()
    }
    pub fn mss_cache(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.mss_cache) }.ok()
    }
    pub fn ecn_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ecn_flags) }.ok()
    }
    pub fn rate_delivered(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rate_delivered) }.ok()
    }
    pub fn rate_interval_us(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rate_interval_us) }.ok()
    }
    pub fn packets_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.packets_out) }.ok()
    }
    pub fn retrans_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.retrans_out) }.ok()
    }
    pub fn total_retrans(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.total_retrans) }.ok()
    }
    pub fn segs_in(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.segs_in) }.ok()
    }
    pub fn data_segs_in(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_segs_in) }.ok()
    }
    pub fn segs_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.segs_out) }.ok()
    }
    pub fn data_segs_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_segs_out) }.ok()
    }
    pub fn lost_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.lost_out) }.ok()
    }
    pub fn sacked_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.sacked_out) }.ok()
    }
    pub fn bytes_received(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.bytes_received) }.ok()
    }
    pub fn bytes_acked(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.bytes_acked) }.ok()
    }
    pub fn dsack_dups(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.dsack_dups) }.ok()
    }
    pub fn delivered(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.delivered) }.ok()
    }
    pub fn delivered_ce(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.delivered_ce) }.ok()
    }
    pub fn icsk_retransmits(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.icsk_retransmits) }.ok()
    }
}
impl bpf_sock_tuple {
    pub fn ipv4(&self) -> Option<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ipv4) }.ok()
    }
    pub fn ipv6(&self) -> Option<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ipv6) }.ok()
    }
}
impl bpf_sock_tuple__bindgen_ty_1 {
    pub fn ipv4(&self) -> Option<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.ipv4) }.ok()
    }
    pub fn ipv6(&self) -> Option<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2> {
        unsafe { crate::bpf_probe_read(&self.ipv6) }.ok()
    }
}
impl bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
    pub fn saddr(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.saddr) }.ok()
    }
    pub fn daddr(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.daddr) }.ok()
    }
    pub fn sport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.sport) }.ok()
    }
    pub fn dport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.dport) }.ok()
    }
}
impl bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2 {
    pub fn saddr(&self) -> Option<[__be32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.saddr) }.ok()
    }
    pub fn daddr(&self) -> Option<[__be32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.daddr) }.ok()
    }
    pub fn sport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.sport) }.ok()
    }
    pub fn dport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.dport) }.ok()
    }
}
impl bpf_xdp_sock {
    pub fn queue_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.queue_id) }.ok()
    }
}
impl xdp_md {
    pub fn data(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data) }.ok()
    }
    pub fn data_end(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_end) }.ok()
    }
    pub fn data_meta(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_meta) }.ok()
    }
    pub fn ingress_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ingress_ifindex) }.ok()
    }
    pub fn rx_queue_index(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rx_queue_index) }.ok()
    }
    pub fn egress_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.egress_ifindex) }.ok()
    }
}
impl bpf_devmap_val {
    pub fn ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ifindex) }.ok()
    }
    pub fn bpf_prog(&self) -> Option<bpf_devmap_val__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.bpf_prog) }.ok()
    }
}
impl bpf_devmap_val__bindgen_ty_1 {
    pub fn fd(&self) -> Option<::aya_bpf_cty::c_int> {
        unsafe { crate::bpf_probe_read(&self.fd) }.ok()
    }
    pub fn id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.id) }.ok()
    }
}
impl bpf_cpumap_val {
    pub fn qsize(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.qsize) }.ok()
    }
    pub fn bpf_prog(&self) -> Option<bpf_cpumap_val__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.bpf_prog) }.ok()
    }
}
impl bpf_cpumap_val__bindgen_ty_1 {
    pub fn fd(&self) -> Option<::aya_bpf_cty::c_int> {
        unsafe { crate::bpf_probe_read(&self.fd) }.ok()
    }
    pub fn id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.id) }.ok()
    }
}
impl sk_msg_md {
    pub fn data(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.data) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn data_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.data_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn remote_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ip4) }.ok()
    }
    pub fn local_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_ip4) }.ok()
    }
    pub fn remote_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ip6) }.ok()
    }
    pub fn local_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.local_ip6) }.ok()
    }
    pub fn remote_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_port) }.ok()
    }
    pub fn local_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_port) }.ok()
    }
    pub fn size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.size) }.ok()
    }
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_msg_md__bindgen_ty_1 {
    pub fn data(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.data) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_msg_md__bindgen_ty_2 {
    pub fn data_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.data_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_msg_md__bindgen_ty_3 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_reuseport_md {
    pub fn data(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.data) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn data_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.data_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.len) }.ok()
    }
    pub fn eth_protocol(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.eth_protocol) }.ok()
    }
    pub fn ip_protocol(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ip_protocol) }.ok()
    }
    pub fn bind_inany(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.bind_inany) }.ok()
    }
    pub fn hash(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.hash) }.ok()
    }
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn migrating_sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.migrating_sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_reuseport_md__bindgen_ty_1 {
    pub fn data(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.data) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_reuseport_md__bindgen_ty_2 {
    pub fn data_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.data_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_reuseport_md__bindgen_ty_3 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl sk_reuseport_md__bindgen_ty_4 {
    pub fn migrating_sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.migrating_sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_prog_info {
    pub fn type_(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_) }.ok()
    }
    pub fn id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.id) }.ok()
    }
    pub fn tag(&self) -> Option<[__u8; 8usize]> {
        unsafe { crate::bpf_probe_read(&self.tag) }.ok()
    }
    pub fn jited_prog_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.jited_prog_len) }.ok()
    }
    pub fn xlated_prog_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.xlated_prog_len) }.ok()
    }
    pub fn jited_prog_insns(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.jited_prog_insns) }.ok()
    }
    pub fn xlated_prog_insns(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.xlated_prog_insns) }.ok()
    }
    pub fn load_time(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.load_time) }.ok()
    }
    pub fn created_by_uid(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.created_by_uid) }.ok()
    }
    pub fn nr_map_ids(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_map_ids) }.ok()
    }
    pub fn map_ids(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.map_ids) }.ok()
    }
    pub fn name(&self) -> Option<[::aya_bpf_cty::c_char; 16usize]> {
        unsafe { crate::bpf_probe_read(&self.name) }.ok()
    }
    pub fn ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ifindex) }.ok()
    }
    pub fn netns_dev(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.netns_dev) }.ok()
    }
    pub fn netns_ino(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.netns_ino) }.ok()
    }
    pub fn nr_jited_ksyms(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_jited_ksyms) }.ok()
    }
    pub fn nr_jited_func_lens(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_jited_func_lens) }.ok()
    }
    pub fn jited_ksyms(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.jited_ksyms) }.ok()
    }
    pub fn jited_func_lens(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.jited_func_lens) }.ok()
    }
    pub fn btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_id) }.ok()
    }
    pub fn func_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.func_info_rec_size) }.ok()
    }
    pub fn func_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.func_info) }.ok()
    }
    pub fn nr_func_info(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_func_info) }.ok()
    }
    pub fn nr_line_info(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_line_info) }.ok()
    }
    pub fn line_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.line_info) }.ok()
    }
    pub fn jited_line_info(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.jited_line_info) }.ok()
    }
    pub fn nr_jited_line_info(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_jited_line_info) }.ok()
    }
    pub fn line_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.line_info_rec_size) }.ok()
    }
    pub fn jited_line_info_rec_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.jited_line_info_rec_size) }.ok()
    }
    pub fn nr_prog_tags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nr_prog_tags) }.ok()
    }
    pub fn prog_tags(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.prog_tags) }.ok()
    }
    pub fn run_time_ns(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.run_time_ns) }.ok()
    }
    pub fn run_cnt(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.run_cnt) }.ok()
    }
    pub fn recursion_misses(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.recursion_misses) }.ok()
    }
    pub fn verified_insns(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.verified_insns) }.ok()
    }
}
impl bpf_map_info {
    pub fn type_(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_) }.ok()
    }
    pub fn id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.id) }.ok()
    }
    pub fn key_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.key_size) }.ok()
    }
    pub fn value_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.value_size) }.ok()
    }
    pub fn max_entries(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.max_entries) }.ok()
    }
    pub fn map_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_flags) }.ok()
    }
    pub fn name(&self) -> Option<[::aya_bpf_cty::c_char; 16usize]> {
        unsafe { crate::bpf_probe_read(&self.name) }.ok()
    }
    pub fn ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ifindex) }.ok()
    }
    pub fn btf_vmlinux_value_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_vmlinux_value_type_id) }.ok()
    }
    pub fn netns_dev(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.netns_dev) }.ok()
    }
    pub fn netns_ino(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.netns_ino) }.ok()
    }
    pub fn btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_id) }.ok()
    }
    pub fn btf_key_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_key_type_id) }.ok()
    }
    pub fn btf_value_type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_value_type_id) }.ok()
    }
    pub fn map_extra(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.map_extra) }.ok()
    }
}
impl bpf_btf_info {
    pub fn btf(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.btf) }.ok()
    }
    pub fn btf_size(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.btf_size) }.ok()
    }
    pub fn id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.id) }.ok()
    }
    pub fn name(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.name) }.ok()
    }
    pub fn name_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.name_len) }.ok()
    }
    pub fn kernel_btf(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.kernel_btf) }.ok()
    }
}
impl bpf_link_info {
    pub fn type_(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_) }.ok()
    }
    pub fn id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.id) }.ok()
    }
    pub fn prog_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.prog_id) }.ok()
    }
    pub fn raw_tracepoint(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.raw_tracepoint) }.ok()
    }
    pub fn tracing(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_2> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.tracing) }.ok()
    }
    pub fn cgroup(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_3> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.cgroup) }.ok()
    }
    pub fn iter(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_4> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.iter) }.ok()
    }
    pub fn netns(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_5> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.netns) }.ok()
    }
    pub fn xdp(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_6> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.xdp) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1 {
    pub fn raw_tracepoint(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.raw_tracepoint) }.ok()
    }
    pub fn tracing(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_2> {
        unsafe { crate::bpf_probe_read(&self.tracing) }.ok()
    }
    pub fn cgroup(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_3> {
        unsafe { crate::bpf_probe_read(&self.cgroup) }.ok()
    }
    pub fn iter(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_4> {
        unsafe { crate::bpf_probe_read(&self.iter) }.ok()
    }
    pub fn netns(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_5> {
        unsafe { crate::bpf_probe_read(&self.netns) }.ok()
    }
    pub fn xdp(&self) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_6> {
        unsafe { crate::bpf_probe_read(&self.xdp) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_1 {
    pub fn tp_name(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.tp_name) }.ok()
    }
    pub fn tp_name_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.tp_name_len) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_2 {
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
    pub fn target_obj_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_obj_id) }.ok()
    }
    pub fn target_btf_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_btf_id) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_3 {
    pub fn cgroup_id(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.cgroup_id) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_4 {
    pub fn target_name(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.target_name) }.ok()
    }
    pub fn target_name_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.target_name_len) }.ok()
    }
    pub fn map(
        &self,
    ) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.map) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1 {
    pub fn map(
        &self,
    ) -> Option<bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1> {
        unsafe { crate::bpf_probe_read(&self.map) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1 {
    pub fn map_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.map_id) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_5 {
    pub fn netns_ino(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.netns_ino) }.ok()
    }
    pub fn attach_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.attach_type) }.ok()
    }
}
impl bpf_link_info__bindgen_ty_1__bindgen_ty_6 {
    pub fn ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ifindex) }.ok()
    }
}
impl bpf_sock_addr {
    pub fn user_family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.user_family) }.ok()
    }
    pub fn user_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.user_ip4) }.ok()
    }
    pub fn user_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.user_ip6) }.ok()
    }
    pub fn user_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.user_port) }.ok()
    }
    pub fn family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn type_(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_) }.ok()
    }
    pub fn protocol(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.protocol) }.ok()
    }
    pub fn msg_src_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.msg_src_ip4) }.ok()
    }
    pub fn msg_src_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.msg_src_ip6) }.ok()
    }
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_sock_addr__bindgen_ty_1 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_sock_ops {
    pub fn op(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.op) }.ok()
    }
    pub fn args(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.args) }.ok()
    }
    pub fn reply(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.reply) }.ok()
    }
    pub fn replylong(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.replylong) }.ok()
    }
    pub fn family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn remote_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ip4) }.ok()
    }
    pub fn local_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_ip4) }.ok()
    }
    pub fn remote_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ip6) }.ok()
    }
    pub fn local_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.local_ip6) }.ok()
    }
    pub fn remote_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_port) }.ok()
    }
    pub fn local_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_port) }.ok()
    }
    pub fn is_fullsock(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.is_fullsock) }.ok()
    }
    pub fn snd_cwnd(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_cwnd) }.ok()
    }
    pub fn srtt_us(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.srtt_us) }.ok()
    }
    pub fn bpf_sock_ops_cb_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.bpf_sock_ops_cb_flags) }.ok()
    }
    pub fn state(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.state) }.ok()
    }
    pub fn rtt_min(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rtt_min) }.ok()
    }
    pub fn snd_ssthresh(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_ssthresh) }.ok()
    }
    pub fn rcv_nxt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rcv_nxt) }.ok()
    }
    pub fn snd_nxt(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_nxt) }.ok()
    }
    pub fn snd_una(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.snd_una) }.ok()
    }
    pub fn mss_cache(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.mss_cache) }.ok()
    }
    pub fn ecn_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ecn_flags) }.ok()
    }
    pub fn rate_delivered(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rate_delivered) }.ok()
    }
    pub fn rate_interval_us(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rate_interval_us) }.ok()
    }
    pub fn packets_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.packets_out) }.ok()
    }
    pub fn retrans_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.retrans_out) }.ok()
    }
    pub fn total_retrans(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.total_retrans) }.ok()
    }
    pub fn segs_in(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.segs_in) }.ok()
    }
    pub fn data_segs_in(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_segs_in) }.ok()
    }
    pub fn segs_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.segs_out) }.ok()
    }
    pub fn data_segs_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.data_segs_out) }.ok()
    }
    pub fn lost_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.lost_out) }.ok()
    }
    pub fn sacked_out(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.sacked_out) }.ok()
    }
    pub fn sk_txhash(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.sk_txhash) }.ok()
    }
    pub fn bytes_received(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.bytes_received) }.ok()
    }
    pub fn bytes_acked(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.bytes_acked) }.ok()
    }
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn skb_data(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.skb_data) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn skb_data_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.skb_data_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn skb_len(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.skb_len) }.ok()
    }
    pub fn skb_tcp_flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.skb_tcp_flags) }.ok()
    }
}
impl bpf_sock_ops__bindgen_ty_1 {
    pub fn args(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.args) }.ok()
    }
    pub fn reply(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.reply) }.ok()
    }
    pub fn replylong(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.replylong) }.ok()
    }
}
impl bpf_sock_ops__bindgen_ty_2 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_sock_ops__bindgen_ty_3 {
    pub fn skb_data(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.skb_data) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_sock_ops__bindgen_ty_4 {
    pub fn skb_data_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.skb_data_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_perf_event_value {
    pub fn counter(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.counter) }.ok()
    }
    pub fn enabled(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.enabled) }.ok()
    }
    pub fn running(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.running) }.ok()
    }
}
impl bpf_cgroup_dev_ctx {
    pub fn access_type(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.access_type) }.ok()
    }
    pub fn major(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.major) }.ok()
    }
    pub fn minor(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.minor) }.ok()
    }
}
impl bpf_raw_tracepoint_args {
    pub fn args(&self) -> Option<__IncompleteArrayField<__u64>> {
        unsafe { crate::bpf_probe_read(&self.args) }.ok()
    }
}
impl bpf_fib_lookup {
    pub fn family(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn l4_protocol(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.l4_protocol) }.ok()
    }
    pub fn sport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.sport) }.ok()
    }
    pub fn dport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.dport) }.ok()
    }
    pub fn tot_len(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.tot_len) }.ok()
    }
    pub fn mtu_result(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.mtu_result) }.ok()
    }
    pub fn ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ifindex) }.ok()
    }
    pub fn tos(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.tos) }.ok()
    }
    pub fn flowinfo(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.flowinfo) }.ok()
    }
    pub fn rt_metric(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.rt_metric) }.ok()
    }
    pub fn ipv4_src(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.ipv4_src) }.ok()
    }
    pub fn ipv6_src(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.ipv6_src) }.ok()
    }
    pub fn ipv4_dst(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.ipv4_dst) }.ok()
    }
    pub fn ipv6_dst(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_4.ipv6_dst) }.ok()
    }
    pub fn h_vlan_proto(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.h_vlan_proto) }.ok()
    }
    pub fn h_vlan_TCI(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.h_vlan_TCI) }.ok()
    }
    pub fn smac(&self) -> Option<[__u8; 6usize]> {
        unsafe { crate::bpf_probe_read(&self.smac) }.ok()
    }
    pub fn dmac(&self) -> Option<[__u8; 6usize]> {
        unsafe { crate::bpf_probe_read(&self.dmac) }.ok()
    }
}
impl bpf_fib_lookup__bindgen_ty_1 {
    pub fn tot_len(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.tot_len) }.ok()
    }
    pub fn mtu_result(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.mtu_result) }.ok()
    }
}
impl bpf_fib_lookup__bindgen_ty_2 {
    pub fn tos(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.tos) }.ok()
    }
    pub fn flowinfo(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.flowinfo) }.ok()
    }
    pub fn rt_metric(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.rt_metric) }.ok()
    }
}
impl bpf_fib_lookup__bindgen_ty_3 {
    pub fn ipv4_src(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.ipv4_src) }.ok()
    }
    pub fn ipv6_src(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.ipv6_src) }.ok()
    }
}
impl bpf_fib_lookup__bindgen_ty_4 {
    pub fn ipv4_dst(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.ipv4_dst) }.ok()
    }
    pub fn ipv6_dst(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.ipv6_dst) }.ok()
    }
}
impl bpf_redir_neigh {
    pub fn nh_family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.nh_family) }.ok()
    }
    pub fn ipv4_nh(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ipv4_nh) }.ok()
    }
    pub fn ipv6_nh(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ipv6_nh) }.ok()
    }
}
impl bpf_redir_neigh__bindgen_ty_1 {
    pub fn ipv4_nh(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.ipv4_nh) }.ok()
    }
    pub fn ipv6_nh(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.ipv6_nh) }.ok()
    }
}
impl bpf_flow_keys {
    pub fn nhoff(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.nhoff) }.ok()
    }
    pub fn thoff(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.thoff) }.ok()
    }
    pub fn addr_proto(&self) -> Option<__u16> {
        unsafe { crate::bpf_probe_read(&self.addr_proto) }.ok()
    }
    pub fn is_frag(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.is_frag) }.ok()
    }
    pub fn is_first_frag(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.is_first_frag) }.ok()
    }
    pub fn is_encap(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.is_encap) }.ok()
    }
    pub fn ip_proto(&self) -> Option<__u8> {
        unsafe { crate::bpf_probe_read(&self.ip_proto) }.ok()
    }
    pub fn n_proto(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.n_proto) }.ok()
    }
    pub fn sport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.sport) }.ok()
    }
    pub fn dport(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.dport) }.ok()
    }
    pub fn ipv4_src(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.__bindgen_anon_1.ipv4_src) }.ok()
    }
    pub fn ipv4_dst(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.__bindgen_anon_1.ipv4_dst) }.ok()
    }
    pub fn ipv6_src(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.__bindgen_anon_2.ipv6_src) }.ok()
    }
    pub fn ipv6_dst(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.__bindgen_anon_2.ipv6_dst) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
    pub fn flow_label(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.flow_label) }.ok()
    }
}
impl bpf_flow_keys__bindgen_ty_1 {
    pub fn ipv4_src(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ipv4_src) }.ok()
    }
    pub fn ipv4_dst(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.ipv4_dst) }.ok()
    }
    pub fn ipv6_src(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.ipv6_src) }.ok()
    }
    pub fn ipv6_dst(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.ipv6_dst) }.ok()
    }
}
impl bpf_flow_keys__bindgen_ty_1__bindgen_ty_1 {
    pub fn ipv4_src(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.ipv4_src) }.ok()
    }
    pub fn ipv4_dst(&self) -> Option<__be32> {
        unsafe { crate::bpf_probe_read(&self.ipv4_dst) }.ok()
    }
}
impl bpf_flow_keys__bindgen_ty_1__bindgen_ty_2 {
    pub fn ipv6_src(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.ipv6_src) }.ok()
    }
    pub fn ipv6_dst(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.ipv6_dst) }.ok()
    }
}
impl bpf_func_info {
    pub fn insn_off(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.insn_off) }.ok()
    }
    pub fn type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_id) }.ok()
    }
}
impl bpf_line_info {
    pub fn insn_off(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.insn_off) }.ok()
    }
    pub fn file_name_off(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.file_name_off) }.ok()
    }
    pub fn line_off(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.line_off) }.ok()
    }
    pub fn line_col(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.line_col) }.ok()
    }
}
impl bpf_spin_lock {
    pub fn val(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.val) }.ok()
    }
}
impl bpf_timer {}
impl bpf_sysctl {
    pub fn write(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.write) }.ok()
    }
    pub fn file_pos(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.file_pos) }.ok()
    }
}
impl bpf_sockopt {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn optval(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_2.optval) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn optval_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_3.optval_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn level(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.level) }.ok()
    }
    pub fn optname(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.optname) }.ok()
    }
    pub fn optlen(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.optlen) }.ok()
    }
    pub fn retval(&self) -> Option<__s32> {
        unsafe { crate::bpf_probe_read(&self.retval) }.ok()
    }
}
impl bpf_sockopt__bindgen_ty_1 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_sockopt__bindgen_ty_2 {
    pub fn optval(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.optval) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_sockopt__bindgen_ty_3 {
    pub fn optval_end(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.optval_end) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl bpf_pidns_info {
    pub fn pid(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.pid) }.ok()
    }
    pub fn tgid(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.tgid) }.ok()
    }
}
impl bpf_sk_lookup {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v =
            unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.__bindgen_anon_1.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn cookie(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.cookie) }.ok()
    }
    pub fn family(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.family) }.ok()
    }
    pub fn protocol(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.protocol) }.ok()
    }
    pub fn remote_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ip4) }.ok()
    }
    pub fn remote_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ip6) }.ok()
    }
    pub fn remote_port(&self) -> Option<__be16> {
        unsafe { crate::bpf_probe_read(&self.remote_port) }.ok()
    }
    pub fn local_ip4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_ip4) }.ok()
    }
    pub fn local_ip6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.local_ip6) }.ok()
    }
    pub fn local_port(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.local_port) }.ok()
    }
    pub fn ingress_ifindex(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.ingress_ifindex) }.ok()
    }
}
impl bpf_sk_lookup__bindgen_ty_1 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.__bindgen_anon_1.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn cookie(&self) -> Option<__u64> {
        unsafe { crate::bpf_probe_read(&self.cookie) }.ok()
    }
}
impl bpf_sk_lookup__bindgen_ty_1__bindgen_ty_1 {
    pub fn sk(&self) -> Option<*mut bpf_sock> {
        let v = unsafe { crate::bpf_probe_read(&self.sk) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
}
impl btf_ptr {
    pub fn ptr(&self) -> Option<*mut ::aya_bpf_cty::c_void> {
        let v = unsafe { crate::bpf_probe_read(&self.ptr) }.ok()?;
        if v.is_null() {
            None
        } else {
            Some(v)
        }
    }
    pub fn type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_id) }.ok()
    }
    pub fn flags(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.flags) }.ok()
    }
}
impl bpf_core_relo {
    pub fn insn_off(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.insn_off) }.ok()
    }
    pub fn type_id(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.type_id) }.ok()
    }
    pub fn access_str_off(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.access_str_off) }.ok()
    }
    pub fn kind(&self) -> Option<bpf_core_relo_kind::Type> {
        unsafe { crate::bpf_probe_read(&self.kind) }.ok()
    }
}
impl sockaddr {
    pub fn sa_family(&self) -> Option<sa_family_t> {
        unsafe { crate::bpf_probe_read(&self.sa_family) }.ok()
    }
    pub fn sa_data(&self) -> Option<[::aya_bpf_cty::c_char; 14usize]> {
        unsafe { crate::bpf_probe_read(&self.sa_data) }.ok()
    }
}
impl bpf_perf_event_data {}
impl linux_binprm {}
impl pt_regs {}
impl tcphdr {}
impl seq_file {}
impl tcp6_sock {}
impl tcp_sock {}
impl tcp_timewait_sock {}
impl tcp_request_sock {}
impl udp6_sock {}
impl unix_sock {}
impl task_struct {}
impl path {}
impl inode {}
impl socket {}
impl file {}
