use super::bindings::*;
impl<Storage> __BindgenBitfieldUnit<Storage> {}
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
}
impl bpf_tunnel_key__bindgen_ty_1 {
    pub fn remote_ipv4(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.remote_ipv4) }.ok()
    }
    pub fn remote_ipv6(&self) -> Option<[__u32; 4usize]> {
        unsafe { crate::bpf_probe_read(&self.remote_ipv6) }.ok()
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
    pub fn dst_port(&self) -> Option<__u32> {
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
impl bpf_spin_lock {
    pub fn val(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.val) }.ok()
    }
}
impl bpf_sysctl {
    pub fn write(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.write) }.ok()
    }
    pub fn file_pos(&self) -> Option<__u32> {
        unsafe { crate::bpf_probe_read(&self.file_pos) }.ok()
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
impl pt_regs {
    pub fn r15(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r15) }.ok()
    }
    pub fn r14(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r14) }.ok()
    }
    pub fn r13(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r13) }.ok()
    }
    pub fn r12(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r12) }.ok()
    }
    pub fn rbp(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rbp) }.ok()
    }
    pub fn rbx(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rbx) }.ok()
    }
    pub fn r11(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r11) }.ok()
    }
    pub fn r10(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r10) }.ok()
    }
    pub fn r9(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r9) }.ok()
    }
    pub fn r8(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.r8) }.ok()
    }
    pub fn rax(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rax) }.ok()
    }
    pub fn rcx(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rcx) }.ok()
    }
    pub fn rdx(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rdx) }.ok()
    }
    pub fn rsi(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rsi) }.ok()
    }
    pub fn rdi(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rdi) }.ok()
    }
    pub fn orig_rax(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.orig_rax) }.ok()
    }
    pub fn rip(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rip) }.ok()
    }
    pub fn cs(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.cs) }.ok()
    }
    pub fn eflags(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.eflags) }.ok()
    }
    pub fn rsp(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.rsp) }.ok()
    }
    pub fn ss(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { crate::bpf_probe_read(&self.ss) }.ok()
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
impl tcphdr {}
impl seq_file {}
impl tcp6_sock {}
impl tcp_sock {}
impl tcp_timewait_sock {}
impl tcp_request_sock {}
impl udp6_sock {}
impl task_struct {}
impl path {}
impl inode {}
impl socket {}
impl file {}
