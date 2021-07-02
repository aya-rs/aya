use super::bindings::*;
pub unsafe fn bpf_map_lookup_elem(
    map: *mut ::aya_bpf_cty::c_void,
    key: *const ::aya_bpf_cty::c_void,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: *const ::aya_bpf_cty::c_void,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(1usize);
    fun(map, key)
}
pub unsafe fn bpf_map_update_elem(
    map: *mut ::aya_bpf_cty::c_void,
    key: *const ::aya_bpf_cty::c_void,
    value: *const ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: *const ::aya_bpf_cty::c_void,
        value: *const ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(2usize);
    fun(map, key, value, flags)
}
pub unsafe fn bpf_map_delete_elem(
    map: *mut ::aya_bpf_cty::c_void,
    key: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(3usize);
    fun(map, key)
}
pub unsafe fn bpf_probe_read(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(4usize);
    fun(dst, size, unsafe_ptr)
}
pub unsafe fn bpf_ktime_get_ns() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(5usize);
    fun()
}
pub unsafe fn bpf_get_prandom_u32() -> __u32 {
    let fun: unsafe extern "C" fn() -> __u32 = ::core::mem::transmute(7usize);
    fun()
}
pub unsafe fn bpf_get_smp_processor_id() -> __u32 {
    let fun: unsafe extern "C" fn() -> __u32 = ::core::mem::transmute(8usize);
    fun()
}
pub unsafe fn bpf_skb_store_bytes(
    skb: *mut __sk_buff,
    offset: __u32,
    from: *const ::aya_bpf_cty::c_void,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: *const ::aya_bpf_cty::c_void,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(9usize);
    fun(skb, offset, from, len, flags)
}
pub unsafe fn bpf_l3_csum_replace(
    skb: *mut __sk_buff,
    offset: __u32,
    from: __u64,
    to: __u64,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: __u64,
        to: __u64,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(10usize);
    fun(skb, offset, from, to, size)
}
pub unsafe fn bpf_l4_csum_replace(
    skb: *mut __sk_buff,
    offset: __u32,
    from: __u64,
    to: __u64,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: __u64,
        to: __u64,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(11usize);
    fun(skb, offset, from, to, flags)
}
pub unsafe fn bpf_tail_call(
    ctx: *mut ::aya_bpf_cty::c_void,
    prog_array_map: *mut ::aya_bpf_cty::c_void,
    index: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        prog_array_map: *mut ::aya_bpf_cty::c_void,
        index: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(12usize);
    fun(ctx, prog_array_map, index)
}
pub unsafe fn bpf_clone_redirect(
    skb: *mut __sk_buff,
    ifindex: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        ifindex: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(13usize);
    fun(skb, ifindex, flags)
}
pub unsafe fn bpf_get_current_pid_tgid() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(14usize);
    fun()
}
pub unsafe fn bpf_get_current_uid_gid() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(15usize);
    fun()
}
pub unsafe fn bpf_get_current_comm(
    buf: *mut ::aya_bpf_cty::c_void,
    size_of_buf: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        buf: *mut ::aya_bpf_cty::c_void,
        size_of_buf: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(16usize);
    fun(buf, size_of_buf)
}
pub unsafe fn bpf_get_cgroup_classid(skb: *mut __sk_buff) -> __u32 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(17usize);
    fun(skb)
}
pub unsafe fn bpf_skb_vlan_push(
    skb: *mut __sk_buff,
    vlan_proto: __be16,
    vlan_tci: __u16,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        vlan_proto: __be16,
        vlan_tci: __u16,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(18usize);
    fun(skb, vlan_proto, vlan_tci)
}
pub unsafe fn bpf_skb_vlan_pop(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(19usize);
    fun(skb)
}
pub unsafe fn bpf_skb_get_tunnel_key(
    skb: *mut __sk_buff,
    key: *mut bpf_tunnel_key,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        key: *mut bpf_tunnel_key,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(20usize);
    fun(skb, key, size, flags)
}
pub unsafe fn bpf_skb_set_tunnel_key(
    skb: *mut __sk_buff,
    key: *mut bpf_tunnel_key,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        key: *mut bpf_tunnel_key,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(21usize);
    fun(skb, key, size, flags)
}
pub unsafe fn bpf_perf_event_read(map: *mut ::aya_bpf_cty::c_void, flags: __u64) -> __u64 {
    let fun: unsafe extern "C" fn(map: *mut ::aya_bpf_cty::c_void, flags: __u64) -> __u64 =
        ::core::mem::transmute(22usize);
    fun(map, flags)
}
pub unsafe fn bpf_redirect(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(23usize);
    fun(ifindex, flags)
}
pub unsafe fn bpf_get_route_realm(skb: *mut __sk_buff) -> __u32 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(24usize);
    fun(skb)
}
pub unsafe fn bpf_perf_event_output(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(25usize);
    fun(ctx, map, flags, data, size)
}
pub unsafe fn bpf_skb_load_bytes(
    skb: *const ::aya_bpf_cty::c_void,
    offset: __u32,
    to: *mut ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *const ::aya_bpf_cty::c_void,
        offset: __u32,
        to: *mut ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(26usize);
    fun(skb, offset, to, len)
}
pub unsafe fn bpf_get_stackid(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(27usize);
    fun(ctx, map, flags)
}
pub unsafe fn bpf_csum_diff(
    from: *mut __be32,
    from_size: __u32,
    to: *mut __be32,
    to_size: __u32,
    seed: __wsum,
) -> __s64 {
    let fun: unsafe extern "C" fn(
        from: *mut __be32,
        from_size: __u32,
        to: *mut __be32,
        to_size: __u32,
        seed: __wsum,
    ) -> __s64 = ::core::mem::transmute(28usize);
    fun(from, from_size, to, to_size, seed)
}
pub unsafe fn bpf_skb_get_tunnel_opt(
    skb: *mut __sk_buff,
    opt: *mut ::aya_bpf_cty::c_void,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        opt: *mut ::aya_bpf_cty::c_void,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(29usize);
    fun(skb, opt, size)
}
pub unsafe fn bpf_skb_set_tunnel_opt(
    skb: *mut __sk_buff,
    opt: *mut ::aya_bpf_cty::c_void,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        opt: *mut ::aya_bpf_cty::c_void,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(30usize);
    fun(skb, opt, size)
}
pub unsafe fn bpf_skb_change_proto(
    skb: *mut __sk_buff,
    proto: __be16,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        proto: __be16,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(31usize);
    fun(skb, proto, flags)
}
pub unsafe fn bpf_skb_change_type(skb: *mut __sk_buff, type_: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff, type_: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(32usize);
    fun(skb, type_)
}
pub unsafe fn bpf_skb_under_cgroup(
    skb: *mut __sk_buff,
    map: *mut ::aya_bpf_cty::c_void,
    index: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        map: *mut ::aya_bpf_cty::c_void,
        index: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(33usize);
    fun(skb, map, index)
}
pub unsafe fn bpf_get_hash_recalc(skb: *mut __sk_buff) -> __u32 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(34usize);
    fun(skb)
}
pub unsafe fn bpf_get_current_task() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(35usize);
    fun()
}
pub unsafe fn bpf_probe_write_user(
    dst: *mut ::aya_bpf_cty::c_void,
    src: *const ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        src: *const ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(36usize);
    fun(dst, src, len)
}
pub unsafe fn bpf_current_task_under_cgroup(
    map: *mut ::aya_bpf_cty::c_void,
    index: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        index: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(37usize);
    fun(map, index)
}
pub unsafe fn bpf_skb_change_tail(
    skb: *mut __sk_buff,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(38usize);
    fun(skb, len, flags)
}
pub unsafe fn bpf_skb_pull_data(skb: *mut __sk_buff, len: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff, len: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(39usize);
    fun(skb, len)
}
pub unsafe fn bpf_csum_update(skb: *mut __sk_buff, csum: __wsum) -> __s64 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff, csum: __wsum) -> __s64 =
        ::core::mem::transmute(40usize);
    fun(skb, csum)
}
pub unsafe fn bpf_set_hash_invalid(skb: *mut __sk_buff) {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) = ::core::mem::transmute(41usize);
    fun(skb)
}
pub unsafe fn bpf_get_numa_node_id() -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn() -> ::aya_bpf_cty::c_long = ::core::mem::transmute(42usize);
    fun()
}
pub unsafe fn bpf_skb_change_head(
    skb: *mut __sk_buff,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(43usize);
    fun(skb, len, flags)
}
pub unsafe fn bpf_xdp_adjust_head(
    xdp_md: *mut xdp_md,
    delta: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        xdp_md: *mut xdp_md,
        delta: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(44usize);
    fun(xdp_md, delta)
}
pub unsafe fn bpf_probe_read_str(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(45usize);
    fun(dst, size, unsafe_ptr)
}
pub unsafe fn bpf_get_socket_cookie(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 {
    let fun: unsafe extern "C" fn(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 =
        ::core::mem::transmute(46usize);
    fun(ctx)
}
pub unsafe fn bpf_get_socket_uid(skb: *mut __sk_buff) -> __u32 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(47usize);
    fun(skb)
}
pub unsafe fn bpf_set_hash(skb: *mut __sk_buff, hash: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff, hash: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(48usize);
    fun(skb, hash)
}
pub unsafe fn bpf_setsockopt(
    bpf_socket: *mut ::aya_bpf_cty::c_void,
    level: ::aya_bpf_cty::c_int,
    optname: ::aya_bpf_cty::c_int,
    optval: *mut ::aya_bpf_cty::c_void,
    optlen: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        bpf_socket: *mut ::aya_bpf_cty::c_void,
        level: ::aya_bpf_cty::c_int,
        optname: ::aya_bpf_cty::c_int,
        optval: *mut ::aya_bpf_cty::c_void,
        optlen: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(49usize);
    fun(bpf_socket, level, optname, optval, optlen)
}
pub unsafe fn bpf_skb_adjust_room(
    skb: *mut __sk_buff,
    len_diff: __s32,
    mode: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        len_diff: __s32,
        mode: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(50usize);
    fun(skb, len_diff, mode, flags)
}
pub unsafe fn bpf_redirect_map(
    map: *mut ::aya_bpf_cty::c_void,
    key: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(51usize);
    fun(map, key, flags)
}
pub unsafe fn bpf_sk_redirect_map(
    skb: *mut __sk_buff,
    map: *mut ::aya_bpf_cty::c_void,
    key: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        map: *mut ::aya_bpf_cty::c_void,
        key: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(52usize);
    fun(skb, map, key, flags)
}
pub unsafe fn bpf_sock_map_update(
    skops: *mut bpf_sock_ops,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(53usize);
    fun(skops, map, key, flags)
}
pub unsafe fn bpf_xdp_adjust_meta(
    xdp_md: *mut xdp_md,
    delta: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        xdp_md: *mut xdp_md,
        delta: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(54usize);
    fun(xdp_md, delta)
}
pub unsafe fn bpf_perf_event_read_value(
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    buf: *mut bpf_perf_event_value,
    buf_size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        buf: *mut bpf_perf_event_value,
        buf_size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(55usize);
    fun(map, flags, buf, buf_size)
}
pub unsafe fn bpf_perf_prog_read_value(
    ctx: *mut bpf_perf_event_data,
    buf: *mut bpf_perf_event_value,
    buf_size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_perf_event_data,
        buf: *mut bpf_perf_event_value,
        buf_size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(56usize);
    fun(ctx, buf, buf_size)
}
pub unsafe fn bpf_getsockopt(
    bpf_socket: *mut ::aya_bpf_cty::c_void,
    level: ::aya_bpf_cty::c_int,
    optname: ::aya_bpf_cty::c_int,
    optval: *mut ::aya_bpf_cty::c_void,
    optlen: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        bpf_socket: *mut ::aya_bpf_cty::c_void,
        level: ::aya_bpf_cty::c_int,
        optname: ::aya_bpf_cty::c_int,
        optval: *mut ::aya_bpf_cty::c_void,
        optlen: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(57usize);
    fun(bpf_socket, level, optname, optval, optlen)
}
pub unsafe fn bpf_override_return(regs: *mut pt_regs, rc: __u64) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(regs: *mut pt_regs, rc: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(58usize);
    fun(regs, rc)
}
pub unsafe fn bpf_sock_ops_cb_flags_set(
    bpf_sock: *mut bpf_sock_ops,
    argval: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        bpf_sock: *mut bpf_sock_ops,
        argval: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(59usize);
    fun(bpf_sock, argval)
}
pub unsafe fn bpf_msg_redirect_map(
    msg: *mut sk_msg_md,
    map: *mut ::aya_bpf_cty::c_void,
    key: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        map: *mut ::aya_bpf_cty::c_void,
        key: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(60usize);
    fun(msg, map, key, flags)
}
pub unsafe fn bpf_msg_apply_bytes(msg: *mut sk_msg_md, bytes: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(msg: *mut sk_msg_md, bytes: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(61usize);
    fun(msg, bytes)
}
pub unsafe fn bpf_msg_cork_bytes(msg: *mut sk_msg_md, bytes: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(msg: *mut sk_msg_md, bytes: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(62usize);
    fun(msg, bytes)
}
pub unsafe fn bpf_msg_pull_data(
    msg: *mut sk_msg_md,
    start: __u32,
    end: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        start: __u32,
        end: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(63usize);
    fun(msg, start, end, flags)
}
pub unsafe fn bpf_bind(
    ctx: *mut bpf_sock_addr,
    addr: *mut sockaddr,
    addr_len: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_sock_addr,
        addr: *mut sockaddr,
        addr_len: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(64usize);
    fun(ctx, addr, addr_len)
}
pub unsafe fn bpf_xdp_adjust_tail(
    xdp_md: *mut xdp_md,
    delta: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        xdp_md: *mut xdp_md,
        delta: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(65usize);
    fun(xdp_md, delta)
}
pub unsafe fn bpf_skb_get_xfrm_state(
    skb: *mut __sk_buff,
    index: __u32,
    xfrm_state: *mut bpf_xfrm_state,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        index: __u32,
        xfrm_state: *mut bpf_xfrm_state,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(66usize);
    fun(skb, index, xfrm_state, size, flags)
}
pub unsafe fn bpf_get_stack(
    ctx: *mut ::aya_bpf_cty::c_void,
    buf: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        buf: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(67usize);
    fun(ctx, buf, size, flags)
}
pub unsafe fn bpf_skb_load_bytes_relative(
    skb: *const ::aya_bpf_cty::c_void,
    offset: __u32,
    to: *mut ::aya_bpf_cty::c_void,
    len: __u32,
    start_header: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *const ::aya_bpf_cty::c_void,
        offset: __u32,
        to: *mut ::aya_bpf_cty::c_void,
        len: __u32,
        start_header: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(68usize);
    fun(skb, offset, to, len, start_header)
}
pub unsafe fn bpf_fib_lookup(
    ctx: *mut ::aya_bpf_cty::c_void,
    params: *mut bpf_fib_lookup,
    plen: ::aya_bpf_cty::c_int,
    flags: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        params: *mut bpf_fib_lookup,
        plen: ::aya_bpf_cty::c_int,
        flags: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(69usize);
    fun(ctx, params, plen, flags)
}
pub unsafe fn bpf_sock_hash_update(
    skops: *mut bpf_sock_ops,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(70usize);
    fun(skops, map, key, flags)
}
pub unsafe fn bpf_msg_redirect_hash(
    msg: *mut sk_msg_md,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(71usize);
    fun(msg, map, key, flags)
}
pub unsafe fn bpf_sk_redirect_hash(
    skb: *mut __sk_buff,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(72usize);
    fun(skb, map, key, flags)
}
pub unsafe fn bpf_lwt_push_encap(
    skb: *mut __sk_buff,
    type_: __u32,
    hdr: *mut ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        type_: __u32,
        hdr: *mut ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(73usize);
    fun(skb, type_, hdr, len)
}
pub unsafe fn bpf_lwt_seg6_store_bytes(
    skb: *mut __sk_buff,
    offset: __u32,
    from: *const ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: *const ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(74usize);
    fun(skb, offset, from, len)
}
pub unsafe fn bpf_lwt_seg6_adjust_srh(
    skb: *mut __sk_buff,
    offset: __u32,
    delta: __s32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        delta: __s32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(75usize);
    fun(skb, offset, delta)
}
pub unsafe fn bpf_lwt_seg6_action(
    skb: *mut __sk_buff,
    action: __u32,
    param: *mut ::aya_bpf_cty::c_void,
    param_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        action: __u32,
        param: *mut ::aya_bpf_cty::c_void,
        param_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(76usize);
    fun(skb, action, param, param_len)
}
pub unsafe fn bpf_rc_repeat(ctx: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(ctx: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(77usize);
    fun(ctx)
}
pub unsafe fn bpf_rc_keydown(
    ctx: *mut ::aya_bpf_cty::c_void,
    protocol: __u32,
    scancode: __u64,
    toggle: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        protocol: __u32,
        scancode: __u64,
        toggle: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(78usize);
    fun(ctx, protocol, scancode, toggle)
}
pub unsafe fn bpf_skb_cgroup_id(skb: *mut __sk_buff) -> __u64 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u64 = ::core::mem::transmute(79usize);
    fun(skb)
}
pub unsafe fn bpf_get_current_cgroup_id() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(80usize);
    fun()
}
pub unsafe fn bpf_get_local_storage(
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(81usize);
    fun(map, flags)
}
pub unsafe fn bpf_sk_select_reuseport(
    reuse: *mut sk_reuseport_md,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        reuse: *mut sk_reuseport_md,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(82usize);
    fun(reuse, map, key, flags)
}
pub unsafe fn bpf_skb_ancestor_cgroup_id(
    skb: *mut __sk_buff,
    ancestor_level: ::aya_bpf_cty::c_int,
) -> __u64 {
    let fun: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        ancestor_level: ::aya_bpf_cty::c_int,
    ) -> __u64 = ::core::mem::transmute(83usize);
    fun(skb, ancestor_level)
}
pub unsafe fn bpf_sk_lookup_tcp(
    ctx: *mut ::aya_bpf_cty::c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_size: __u32,
    netns: __u64,
    flags: __u64,
) -> *mut bpf_sock {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        tuple: *mut bpf_sock_tuple,
        tuple_size: __u32,
        netns: __u64,
        flags: __u64,
    ) -> *mut bpf_sock = ::core::mem::transmute(84usize);
    fun(ctx, tuple, tuple_size, netns, flags)
}
pub unsafe fn bpf_sk_lookup_udp(
    ctx: *mut ::aya_bpf_cty::c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_size: __u32,
    netns: __u64,
    flags: __u64,
) -> *mut bpf_sock {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        tuple: *mut bpf_sock_tuple,
        tuple_size: __u32,
        netns: __u64,
        flags: __u64,
    ) -> *mut bpf_sock = ::core::mem::transmute(85usize);
    fun(ctx, tuple, tuple_size, netns, flags)
}
pub unsafe fn bpf_sk_release(sock: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(sock: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(86usize);
    fun(sock)
}
pub unsafe fn bpf_map_push_elem(
    map: *mut ::aya_bpf_cty::c_void,
    value: *const ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        value: *const ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(87usize);
    fun(map, value, flags)
}
pub unsafe fn bpf_map_pop_elem(
    map: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(88usize);
    fun(map, value)
}
pub unsafe fn bpf_map_peek_elem(
    map: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(89usize);
    fun(map, value)
}
pub unsafe fn bpf_msg_push_data(
    msg: *mut sk_msg_md,
    start: __u32,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        start: __u32,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(90usize);
    fun(msg, start, len, flags)
}
pub unsafe fn bpf_msg_pop_data(
    msg: *mut sk_msg_md,
    start: __u32,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        start: __u32,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(91usize);
    fun(msg, start, len, flags)
}
pub unsafe fn bpf_rc_pointer_rel(
    ctx: *mut ::aya_bpf_cty::c_void,
    rel_x: __s32,
    rel_y: __s32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        rel_x: __s32,
        rel_y: __s32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(92usize);
    fun(ctx, rel_x, rel_y)
}
pub unsafe fn bpf_spin_lock(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(93usize);
    fun(lock)
}
pub unsafe fn bpf_spin_unlock(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(94usize);
    fun(lock)
}
pub unsafe fn bpf_sk_fullsock(sk: *mut bpf_sock) -> *mut bpf_sock {
    let fun: unsafe extern "C" fn(sk: *mut bpf_sock) -> *mut bpf_sock =
        ::core::mem::transmute(95usize);
    fun(sk)
}
pub unsafe fn bpf_tcp_sock(sk: *mut bpf_sock) -> *mut bpf_tcp_sock {
    let fun: unsafe extern "C" fn(sk: *mut bpf_sock) -> *mut bpf_tcp_sock =
        ::core::mem::transmute(96usize);
    fun(sk)
}
pub unsafe fn bpf_skb_ecn_set_ce(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(97usize);
    fun(skb)
}
pub unsafe fn bpf_get_listener_sock(sk: *mut bpf_sock) -> *mut bpf_sock {
    let fun: unsafe extern "C" fn(sk: *mut bpf_sock) -> *mut bpf_sock =
        ::core::mem::transmute(98usize);
    fun(sk)
}
pub unsafe fn bpf_skc_lookup_tcp(
    ctx: *mut ::aya_bpf_cty::c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_size: __u32,
    netns: __u64,
    flags: __u64,
) -> *mut bpf_sock {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        tuple: *mut bpf_sock_tuple,
        tuple_size: __u32,
        netns: __u64,
        flags: __u64,
    ) -> *mut bpf_sock = ::core::mem::transmute(99usize);
    fun(ctx, tuple, tuple_size, netns, flags)
}
pub unsafe fn bpf_tcp_check_syncookie(
    sk: *mut ::aya_bpf_cty::c_void,
    iph: *mut ::aya_bpf_cty::c_void,
    iph_len: __u32,
    th: *mut tcphdr,
    th_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        sk: *mut ::aya_bpf_cty::c_void,
        iph: *mut ::aya_bpf_cty::c_void,
        iph_len: __u32,
        th: *mut tcphdr,
        th_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(100usize);
    fun(sk, iph, iph_len, th, th_len)
}
pub unsafe fn bpf_sysctl_get_name(
    ctx: *mut bpf_sysctl,
    buf: *mut ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *mut ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(101usize);
    fun(ctx, buf, buf_len, flags)
}
pub unsafe fn bpf_sysctl_get_current_value(
    ctx: *mut bpf_sysctl,
    buf: *mut ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *mut ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(102usize);
    fun(ctx, buf, buf_len)
}
pub unsafe fn bpf_sysctl_get_new_value(
    ctx: *mut bpf_sysctl,
    buf: *mut ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *mut ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(103usize);
    fun(ctx, buf, buf_len)
}
pub unsafe fn bpf_sysctl_set_new_value(
    ctx: *mut bpf_sysctl,
    buf: *const ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *const ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(104usize);
    fun(ctx, buf, buf_len)
}
pub unsafe fn bpf_strtol(
    buf: *const ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
    flags: __u64,
    res: *mut ::aya_bpf_cty::c_long,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        buf: *const ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
        flags: __u64,
        res: *mut ::aya_bpf_cty::c_long,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(105usize);
    fun(buf, buf_len, flags, res)
}
pub unsafe fn bpf_strtoul(
    buf: *const ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
    flags: __u64,
    res: *mut ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        buf: *const ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
        flags: __u64,
        res: *mut ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(106usize);
    fun(buf, buf_len, flags, res)
}
pub unsafe fn bpf_sk_storage_get(
    map: *mut ::aya_bpf_cty::c_void,
    sk: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        sk: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(107usize);
    fun(map, sk, value, flags)
}
pub unsafe fn bpf_sk_storage_delete(
    map: *mut ::aya_bpf_cty::c_void,
    sk: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        sk: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(108usize);
    fun(map, sk)
}
pub unsafe fn bpf_send_signal(sig: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(sig: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(109usize);
    fun(sig)
}
pub unsafe fn bpf_tcp_gen_syncookie(
    sk: *mut ::aya_bpf_cty::c_void,
    iph: *mut ::aya_bpf_cty::c_void,
    iph_len: __u32,
    th: *mut tcphdr,
    th_len: __u32,
) -> __s64 {
    let fun: unsafe extern "C" fn(
        sk: *mut ::aya_bpf_cty::c_void,
        iph: *mut ::aya_bpf_cty::c_void,
        iph_len: __u32,
        th: *mut tcphdr,
        th_len: __u32,
    ) -> __s64 = ::core::mem::transmute(110usize);
    fun(sk, iph, iph_len, th, th_len)
}
pub unsafe fn bpf_skb_output(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(111usize);
    fun(ctx, map, flags, data, size)
}
pub unsafe fn bpf_probe_read_user(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(112usize);
    fun(dst, size, unsafe_ptr)
}
pub unsafe fn bpf_probe_read_kernel(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(113usize);
    fun(dst, size, unsafe_ptr)
}
pub unsafe fn bpf_probe_read_user_str(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(114usize);
    fun(dst, size, unsafe_ptr)
}
pub unsafe fn bpf_probe_read_kernel_str(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(115usize);
    fun(dst, size, unsafe_ptr)
}
pub unsafe fn bpf_tcp_send_ack(
    tp: *mut ::aya_bpf_cty::c_void,
    rcv_nxt: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        tp: *mut ::aya_bpf_cty::c_void,
        rcv_nxt: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(116usize);
    fun(tp, rcv_nxt)
}
pub unsafe fn bpf_send_signal_thread(sig: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(sig: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(117usize);
    fun(sig)
}
pub unsafe fn bpf_jiffies64() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(118usize);
    fun()
}
pub unsafe fn bpf_read_branch_records(
    ctx: *mut bpf_perf_event_data,
    buf: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut bpf_perf_event_data,
        buf: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(119usize);
    fun(ctx, buf, size, flags)
}
pub unsafe fn bpf_get_ns_current_pid_tgid(
    dev: __u64,
    ino: __u64,
    nsdata: *mut bpf_pidns_info,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dev: __u64,
        ino: __u64,
        nsdata: *mut bpf_pidns_info,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(120usize);
    fun(dev, ino, nsdata, size)
}
pub unsafe fn bpf_xdp_output(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(121usize);
    fun(ctx, map, flags, data, size)
}
pub unsafe fn bpf_get_netns_cookie(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 {
    let fun: unsafe extern "C" fn(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 =
        ::core::mem::transmute(122usize);
    fun(ctx)
}
pub unsafe fn bpf_get_current_ancestor_cgroup_id(ancestor_level: ::aya_bpf_cty::c_int) -> __u64 {
    let fun: unsafe extern "C" fn(ancestor_level: ::aya_bpf_cty::c_int) -> __u64 =
        ::core::mem::transmute(123usize);
    fun(ancestor_level)
}
pub unsafe fn bpf_sk_assign(
    ctx: *mut ::aya_bpf_cty::c_void,
    sk: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        sk: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(124usize);
    fun(ctx, sk, flags)
}
pub unsafe fn bpf_ktime_get_boot_ns() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(125usize);
    fun()
}
pub unsafe fn bpf_seq_printf(
    m: *mut seq_file,
    fmt: *const ::aya_bpf_cty::c_char,
    fmt_size: __u32,
    data: *const ::aya_bpf_cty::c_void,
    data_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        m: *mut seq_file,
        fmt: *const ::aya_bpf_cty::c_char,
        fmt_size: __u32,
        data: *const ::aya_bpf_cty::c_void,
        data_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(126usize);
    fun(m, fmt, fmt_size, data, data_len)
}
pub unsafe fn bpf_seq_write(
    m: *mut seq_file,
    data: *const ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        m: *mut seq_file,
        data: *const ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(127usize);
    fun(m, data, len)
}
pub unsafe fn bpf_sk_cgroup_id(sk: *mut ::aya_bpf_cty::c_void) -> __u64 {
    let fun: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> __u64 =
        ::core::mem::transmute(128usize);
    fun(sk)
}
pub unsafe fn bpf_sk_ancestor_cgroup_id(
    sk: *mut ::aya_bpf_cty::c_void,
    ancestor_level: ::aya_bpf_cty::c_int,
) -> __u64 {
    let fun: unsafe extern "C" fn(
        sk: *mut ::aya_bpf_cty::c_void,
        ancestor_level: ::aya_bpf_cty::c_int,
    ) -> __u64 = ::core::mem::transmute(129usize);
    fun(sk, ancestor_level)
}
pub unsafe fn bpf_ringbuf_output(
    ringbuf: *mut ::aya_bpf_cty::c_void,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ringbuf: *mut ::aya_bpf_cty::c_void,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(130usize);
    fun(ringbuf, data, size, flags)
}
pub unsafe fn bpf_ringbuf_reserve(
    ringbuf: *mut ::aya_bpf_cty::c_void,
    size: __u64,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        ringbuf: *mut ::aya_bpf_cty::c_void,
        size: __u64,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(131usize);
    fun(ringbuf, size, flags)
}
pub unsafe fn bpf_ringbuf_submit(data: *mut ::aya_bpf_cty::c_void, flags: __u64) {
    let fun: unsafe extern "C" fn(data: *mut ::aya_bpf_cty::c_void, flags: __u64) =
        ::core::mem::transmute(132usize);
    fun(data, flags)
}
pub unsafe fn bpf_ringbuf_discard(data: *mut ::aya_bpf_cty::c_void, flags: __u64) {
    let fun: unsafe extern "C" fn(data: *mut ::aya_bpf_cty::c_void, flags: __u64) =
        ::core::mem::transmute(133usize);
    fun(data, flags)
}
pub unsafe fn bpf_ringbuf_query(ringbuf: *mut ::aya_bpf_cty::c_void, flags: __u64) -> __u64 {
    let fun: unsafe extern "C" fn(ringbuf: *mut ::aya_bpf_cty::c_void, flags: __u64) -> __u64 =
        ::core::mem::transmute(134usize);
    fun(ringbuf, flags)
}
pub unsafe fn bpf_csum_level(skb: *mut __sk_buff, level: __u64) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff, level: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(135usize);
    fun(skb, level)
}
pub unsafe fn bpf_skc_to_tcp6_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp6_sock {
    let fun: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp6_sock =
        ::core::mem::transmute(136usize);
    fun(sk)
}
pub unsafe fn bpf_skc_to_tcp_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_sock {
    let fun: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_sock =
        ::core::mem::transmute(137usize);
    fun(sk)
}
pub unsafe fn bpf_skc_to_tcp_timewait_sock(
    sk: *mut ::aya_bpf_cty::c_void,
) -> *mut tcp_timewait_sock {
    let fun: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_timewait_sock =
        ::core::mem::transmute(138usize);
    fun(sk)
}
pub unsafe fn bpf_skc_to_tcp_request_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_request_sock {
    let fun: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_request_sock =
        ::core::mem::transmute(139usize);
    fun(sk)
}
pub unsafe fn bpf_skc_to_udp6_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut udp6_sock {
    let fun: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut udp6_sock =
        ::core::mem::transmute(140usize);
    fun(sk)
}
pub unsafe fn bpf_get_task_stack(
    task: *mut task_struct,
    buf: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        task: *mut task_struct,
        buf: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(141usize);
    fun(task, buf, size, flags)
}
pub unsafe fn bpf_load_hdr_opt(
    skops: *mut bpf_sock_ops,
    searchby_res: *mut ::aya_bpf_cty::c_void,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        searchby_res: *mut ::aya_bpf_cty::c_void,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(142usize);
    fun(skops, searchby_res, len, flags)
}
pub unsafe fn bpf_store_hdr_opt(
    skops: *mut bpf_sock_ops,
    from: *const ::aya_bpf_cty::c_void,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        from: *const ::aya_bpf_cty::c_void,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(143usize);
    fun(skops, from, len, flags)
}
pub unsafe fn bpf_reserve_hdr_opt(
    skops: *mut bpf_sock_ops,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(144usize);
    fun(skops, len, flags)
}
pub unsafe fn bpf_inode_storage_get(
    map: *mut ::aya_bpf_cty::c_void,
    inode: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        inode: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(145usize);
    fun(map, inode, value, flags)
}
pub unsafe fn bpf_inode_storage_delete(
    map: *mut ::aya_bpf_cty::c_void,
    inode: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_int {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        inode: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_int = ::core::mem::transmute(146usize);
    fun(map, inode)
}
pub unsafe fn bpf_d_path(
    path: *mut path,
    buf: *mut ::aya_bpf_cty::c_char,
    sz: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        path: *mut path,
        buf: *mut ::aya_bpf_cty::c_char,
        sz: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(147usize);
    fun(path, buf, sz)
}
pub unsafe fn bpf_copy_from_user(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    user_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        user_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(148usize);
    fun(dst, size, user_ptr)
}
pub unsafe fn bpf_snprintf_btf(
    str_: *mut ::aya_bpf_cty::c_char,
    str_size: __u32,
    ptr: *mut btf_ptr,
    btf_ptr_size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        str_: *mut ::aya_bpf_cty::c_char,
        str_size: __u32,
        ptr: *mut btf_ptr,
        btf_ptr_size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(149usize);
    fun(str_, str_size, ptr, btf_ptr_size, flags)
}
pub unsafe fn bpf_seq_printf_btf(
    m: *mut seq_file,
    ptr: *mut btf_ptr,
    ptr_size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        m: *mut seq_file,
        ptr: *mut btf_ptr,
        ptr_size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(150usize);
    fun(m, ptr, ptr_size, flags)
}
pub unsafe fn bpf_skb_cgroup_classid(skb: *mut __sk_buff) -> __u64 {
    let fun: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u64 = ::core::mem::transmute(151usize);
    fun(skb)
}
pub unsafe fn bpf_redirect_neigh(
    ifindex: __u32,
    params: *mut bpf_redir_neigh,
    plen: ::aya_bpf_cty::c_int,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ifindex: __u32,
        params: *mut bpf_redir_neigh,
        plen: ::aya_bpf_cty::c_int,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(152usize);
    fun(ifindex, params, plen, flags)
}
pub unsafe fn bpf_per_cpu_ptr(
    percpu_ptr: *const ::aya_bpf_cty::c_void,
    cpu: __u32,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        percpu_ptr: *const ::aya_bpf_cty::c_void,
        cpu: __u32,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(153usize);
    fun(percpu_ptr, cpu)
}
pub unsafe fn bpf_this_cpu_ptr(
    percpu_ptr: *const ::aya_bpf_cty::c_void,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        percpu_ptr: *const ::aya_bpf_cty::c_void,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(154usize);
    fun(percpu_ptr)
}
pub unsafe fn bpf_redirect_peer(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(155usize);
    fun(ifindex, flags)
}
pub unsafe fn bpf_task_storage_get(
    map: *mut ::aya_bpf_cty::c_void,
    task: *mut task_struct,
    value: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        task: *mut task_struct,
        value: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(156usize);
    fun(map, task, value, flags)
}
pub unsafe fn bpf_task_storage_delete(
    map: *mut ::aya_bpf_cty::c_void,
    task: *mut task_struct,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        task: *mut task_struct,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(157usize);
    fun(map, task)
}
pub unsafe fn bpf_get_current_task_btf() -> *mut task_struct {
    let fun: unsafe extern "C" fn() -> *mut task_struct = ::core::mem::transmute(158usize);
    fun()
}
pub unsafe fn bpf_bprm_opts_set(bprm: *mut linux_binprm, flags: __u64) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(bprm: *mut linux_binprm, flags: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(159usize);
    fun(bprm, flags)
}
pub unsafe fn bpf_ktime_get_coarse_ns() -> __u64 {
    let fun: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(160usize);
    fun()
}
pub unsafe fn bpf_ima_inode_hash(
    inode: *mut inode,
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        inode: *mut inode,
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(161usize);
    fun(inode, dst, size)
}
pub unsafe fn bpf_sock_from_file(file: *mut file) -> *mut socket {
    let fun: unsafe extern "C" fn(file: *mut file) -> *mut socket =
        ::core::mem::transmute(162usize);
    fun(file)
}
pub unsafe fn bpf_check_mtu(
    ctx: *mut ::aya_bpf_cty::c_void,
    ifindex: __u32,
    mtu_len: *mut __u32,
    len_diff: __s32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        ifindex: __u32,
        mtu_len: *mut __u32,
        len_diff: __s32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(163usize);
    fun(ctx, ifindex, mtu_len, len_diff, flags)
}
pub unsafe fn bpf_for_each_map_elem(
    map: *mut ::aya_bpf_cty::c_void,
    callback_fn: *mut ::aya_bpf_cty::c_void,
    callback_ctx: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        callback_fn: *mut ::aya_bpf_cty::c_void,
        callback_ctx: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(164usize);
    fun(map, callback_fn, callback_ctx, flags)
}
pub unsafe fn bpf_snprintf(
    str_: *mut ::aya_bpf_cty::c_char,
    str_size: __u32,
    fmt: *const ::aya_bpf_cty::c_char,
    data: *mut __u64,
    data_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        str_: *mut ::aya_bpf_cty::c_char,
        str_size: __u32,
        fmt: *const ::aya_bpf_cty::c_char,
        data: *mut __u64,
        data_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(165usize);
    fun(str_, str_size, fmt, data, data_len)
}
pub unsafe fn bpf_sys_bpf(
    cmd: __u32,
    attr: *mut ::aya_bpf_cty::c_void,
    attr_size: __u32,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        cmd: __u32,
        attr: *mut ::aya_bpf_cty::c_void,
        attr_size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(166usize);
    fun(cmd, attr, attr_size)
}
pub unsafe fn bpf_btf_find_by_name_kind(
    name: *mut ::aya_bpf_cty::c_char,
    name_sz: ::aya_bpf_cty::c_int,
    kind: __u32,
    flags: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(
        name: *mut ::aya_bpf_cty::c_char,
        name_sz: ::aya_bpf_cty::c_int,
        kind: __u32,
        flags: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(167usize);
    fun(name, name_sz, kind, flags)
}
pub unsafe fn bpf_sys_close(fd: __u32) -> ::aya_bpf_cty::c_long {
    let fun: unsafe extern "C" fn(fd: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(168usize);
    fun(fd)
}
