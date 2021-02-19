use crate::bpf::generated::bindings::*;
#[inline(always)]
pub unsafe extern "C" fn bpf_map_lookup_elem(
    map: *mut ::aya_bpf_cty::c_void,
    key: *const ::aya_bpf_cty::c_void,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: *const ::aya_bpf_cty::c_void,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(1usize);
    f(map, key)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_map_update_elem(
    map: *mut ::aya_bpf_cty::c_void,
    key: *const ::aya_bpf_cty::c_void,
    value: *const ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: *const ::aya_bpf_cty::c_void,
        value: *const ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(2usize);
    f(map, key, value, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_map_delete_elem(
    map: *mut ::aya_bpf_cty::c_void,
    key: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(3usize);
    f(map, key)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_read(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(4usize);
    f(dst, size, unsafe_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ktime_get_ns() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(5usize);
    f()
} /* # [inline (always)] pub unsafe extern "C" fn bpf_trace_printk (fmt : * const :: aya_bpf_cty :: c_char , fmt_size : __u32 , ...) -> :: aya_bpf_cty :: c_long{ let f : unsafe extern "C" fn (fmt : * const :: aya_bpf_cty :: c_char , fmt_size : __u32 , ...) -> :: aya_bpf_cty :: c_long = :: core :: mem :: transmute (6usize) ; f (fmt , fmt_size) } */
#[inline(always)]
pub unsafe extern "C" fn bpf_get_prandom_u32() -> __u32 {
    let f: unsafe extern "C" fn() -> __u32 = ::core::mem::transmute(7usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_smp_processor_id() -> __u32 {
    let f: unsafe extern "C" fn() -> __u32 = ::core::mem::transmute(8usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_store_bytes(
    skb: *mut __sk_buff,
    offset: __u32,
    from: *const ::aya_bpf_cty::c_void,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: *const ::aya_bpf_cty::c_void,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(9usize);
    f(skb, offset, from, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_l3_csum_replace(
    skb: *mut __sk_buff,
    offset: __u32,
    from: __u64,
    to: __u64,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: __u64,
        to: __u64,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(10usize);
    f(skb, offset, from, to, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_l4_csum_replace(
    skb: *mut __sk_buff,
    offset: __u32,
    from: __u64,
    to: __u64,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: __u64,
        to: __u64,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(11usize);
    f(skb, offset, from, to, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_tail_call(
    ctx: *mut ::aya_bpf_cty::c_void,
    prog_array_map: *mut ::aya_bpf_cty::c_void,
    index: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        prog_array_map: *mut ::aya_bpf_cty::c_void,
        index: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(12usize);
    f(ctx, prog_array_map, index)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_clone_redirect(
    skb: *mut __sk_buff,
    ifindex: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        ifindex: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(13usize);
    f(skb, ifindex, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_pid_tgid() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(14usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_uid_gid() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(15usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_comm(
    buf: *mut ::aya_bpf_cty::c_void,
    size_of_buf: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        buf: *mut ::aya_bpf_cty::c_void,
        size_of_buf: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(16usize);
    f(buf, size_of_buf)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_cgroup_classid(skb: *mut __sk_buff) -> __u32 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(17usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_vlan_push(
    skb: *mut __sk_buff,
    vlan_proto: __be16,
    vlan_tci: __u16,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        vlan_proto: __be16,
        vlan_tci: __u16,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(18usize);
    f(skb, vlan_proto, vlan_tci)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_vlan_pop(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(19usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_get_tunnel_key(
    skb: *mut __sk_buff,
    key: *mut bpf_tunnel_key,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        key: *mut bpf_tunnel_key,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(20usize);
    f(skb, key, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_set_tunnel_key(
    skb: *mut __sk_buff,
    key: *mut bpf_tunnel_key,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        key: *mut bpf_tunnel_key,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(21usize);
    f(skb, key, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_perf_event_read(
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> __u64 {
    let f: unsafe extern "C" fn(map: *mut ::aya_bpf_cty::c_void, flags: __u64) -> __u64 =
        ::core::mem::transmute(22usize);
    f(map, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_redirect(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(23usize);
    f(ifindex, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_route_realm(skb: *mut __sk_buff) -> __u32 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(24usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_perf_event_output(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(25usize);
    f(ctx, map, flags, data, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_load_bytes(
    skb: *const ::aya_bpf_cty::c_void,
    offset: __u32,
    to: *mut ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *const ::aya_bpf_cty::c_void,
        offset: __u32,
        to: *mut ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(26usize);
    f(skb, offset, to, len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_stackid(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(27usize);
    f(ctx, map, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_csum_diff(
    from: *mut __be32,
    from_size: __u32,
    to: *mut __be32,
    to_size: __u32,
    seed: __wsum,
) -> __s64 {
    let f: unsafe extern "C" fn(
        from: *mut __be32,
        from_size: __u32,
        to: *mut __be32,
        to_size: __u32,
        seed: __wsum,
    ) -> __s64 = ::core::mem::transmute(28usize);
    f(from, from_size, to, to_size, seed)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_get_tunnel_opt(
    skb: *mut __sk_buff,
    opt: *mut ::aya_bpf_cty::c_void,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        opt: *mut ::aya_bpf_cty::c_void,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(29usize);
    f(skb, opt, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_set_tunnel_opt(
    skb: *mut __sk_buff,
    opt: *mut ::aya_bpf_cty::c_void,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        opt: *mut ::aya_bpf_cty::c_void,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(30usize);
    f(skb, opt, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_change_proto(
    skb: *mut __sk_buff,
    proto: __be16,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        proto: __be16,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(31usize);
    f(skb, proto, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_change_type(
    skb: *mut __sk_buff,
    type_: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff, type_: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(32usize);
    f(skb, type_)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_under_cgroup(
    skb: *mut __sk_buff,
    map: *mut ::aya_bpf_cty::c_void,
    index: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        map: *mut ::aya_bpf_cty::c_void,
        index: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(33usize);
    f(skb, map, index)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_hash_recalc(skb: *mut __sk_buff) -> __u32 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(34usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_task() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(35usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_write_user(
    dst: *mut ::aya_bpf_cty::c_void,
    src: *const ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        src: *const ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(36usize);
    f(dst, src, len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_current_task_under_cgroup(
    map: *mut ::aya_bpf_cty::c_void,
    index: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        index: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(37usize);
    f(map, index)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_change_tail(
    skb: *mut __sk_buff,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(38usize);
    f(skb, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_pull_data(
    skb: *mut __sk_buff,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff, len: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(39usize);
    f(skb, len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_csum_update(skb: *mut __sk_buff, csum: __wsum) -> __s64 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff, csum: __wsum) -> __s64 =
        ::core::mem::transmute(40usize);
    f(skb, csum)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_set_hash_invalid(skb: *mut __sk_buff) {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) = ::core::mem::transmute(41usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_numa_node_id() -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn() -> ::aya_bpf_cty::c_long = ::core::mem::transmute(42usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_change_head(
    skb: *mut __sk_buff,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(43usize);
    f(skb, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_xdp_adjust_head(
    xdp_md: *mut xdp_md,
    delta: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        xdp_md: *mut xdp_md,
        delta: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(44usize);
    f(xdp_md, delta)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_read_str(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(45usize);
    f(dst, size, unsafe_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_socket_cookie(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 {
    let f: unsafe extern "C" fn(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 =
        ::core::mem::transmute(46usize);
    f(ctx)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_socket_uid(skb: *mut __sk_buff) -> __u32 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u32 = ::core::mem::transmute(47usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_set_hash(skb: *mut __sk_buff, hash: __u32) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff, hash: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(48usize);
    f(skb, hash)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_setsockopt(
    bpf_socket: *mut ::aya_bpf_cty::c_void,
    level: ::aya_bpf_cty::c_int,
    optname: ::aya_bpf_cty::c_int,
    optval: *mut ::aya_bpf_cty::c_void,
    optlen: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        bpf_socket: *mut ::aya_bpf_cty::c_void,
        level: ::aya_bpf_cty::c_int,
        optname: ::aya_bpf_cty::c_int,
        optval: *mut ::aya_bpf_cty::c_void,
        optlen: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(49usize);
    f(bpf_socket, level, optname, optval, optlen)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_adjust_room(
    skb: *mut __sk_buff,
    len_diff: __s32,
    mode: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        len_diff: __s32,
        mode: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(50usize);
    f(skb, len_diff, mode, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_redirect_map(
    map: *mut ::aya_bpf_cty::c_void,
    key: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        key: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(51usize);
    f(map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_redirect_map(
    skb: *mut __sk_buff,
    map: *mut ::aya_bpf_cty::c_void,
    key: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        map: *mut ::aya_bpf_cty::c_void,
        key: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(52usize);
    f(skb, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sock_map_update(
    skops: *mut bpf_sock_ops,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(53usize);
    f(skops, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_xdp_adjust_meta(
    xdp_md: *mut xdp_md,
    delta: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        xdp_md: *mut xdp_md,
        delta: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(54usize);
    f(xdp_md, delta)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_perf_event_read_value(
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    buf: *mut bpf_perf_event_value,
    buf_size: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        buf: *mut bpf_perf_event_value,
        buf_size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(55usize);
    f(map, flags, buf, buf_size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_perf_prog_read_value(
    ctx: *mut bpf_perf_event_data,
    buf: *mut bpf_perf_event_value,
    buf_size: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_perf_event_data,
        buf: *mut bpf_perf_event_value,
        buf_size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(56usize);
    f(ctx, buf, buf_size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_getsockopt(
    bpf_socket: *mut ::aya_bpf_cty::c_void,
    level: ::aya_bpf_cty::c_int,
    optname: ::aya_bpf_cty::c_int,
    optval: *mut ::aya_bpf_cty::c_void,
    optlen: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        bpf_socket: *mut ::aya_bpf_cty::c_void,
        level: ::aya_bpf_cty::c_int,
        optname: ::aya_bpf_cty::c_int,
        optval: *mut ::aya_bpf_cty::c_void,
        optlen: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(57usize);
    f(bpf_socket, level, optname, optval, optlen)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_override_return(
    regs: *mut pt_regs,
    rc: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(regs: *mut pt_regs, rc: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(58usize);
    f(regs, rc)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sock_ops_cb_flags_set(
    bpf_sock: *mut bpf_sock_ops,
    argval: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        bpf_sock: *mut bpf_sock_ops,
        argval: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(59usize);
    f(bpf_sock, argval)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_redirect_map(
    msg: *mut sk_msg_md,
    map: *mut ::aya_bpf_cty::c_void,
    key: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        map: *mut ::aya_bpf_cty::c_void,
        key: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(60usize);
    f(msg, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_apply_bytes(
    msg: *mut sk_msg_md,
    bytes: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(msg: *mut sk_msg_md, bytes: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(61usize);
    f(msg, bytes)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_cork_bytes(
    msg: *mut sk_msg_md,
    bytes: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(msg: *mut sk_msg_md, bytes: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(62usize);
    f(msg, bytes)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_pull_data(
    msg: *mut sk_msg_md,
    start: __u32,
    end: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        start: __u32,
        end: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(63usize);
    f(msg, start, end, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_bind(
    ctx: *mut bpf_sock_addr,
    addr: *mut sockaddr,
    addr_len: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_sock_addr,
        addr: *mut sockaddr,
        addr_len: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(64usize);
    f(ctx, addr, addr_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_xdp_adjust_tail(
    xdp_md: *mut xdp_md,
    delta: ::aya_bpf_cty::c_int,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        xdp_md: *mut xdp_md,
        delta: ::aya_bpf_cty::c_int,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(65usize);
    f(xdp_md, delta)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_get_xfrm_state(
    skb: *mut __sk_buff,
    index: __u32,
    xfrm_state: *mut bpf_xfrm_state,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        index: __u32,
        xfrm_state: *mut bpf_xfrm_state,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(66usize);
    f(skb, index, xfrm_state, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_stack(
    ctx: *mut ::aya_bpf_cty::c_void,
    buf: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        buf: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(67usize);
    f(ctx, buf, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_load_bytes_relative(
    skb: *const ::aya_bpf_cty::c_void,
    offset: __u32,
    to: *mut ::aya_bpf_cty::c_void,
    len: __u32,
    start_header: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *const ::aya_bpf_cty::c_void,
        offset: __u32,
        to: *mut ::aya_bpf_cty::c_void,
        len: __u32,
        start_header: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(68usize);
    f(skb, offset, to, len, start_header)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_fib_lookup(
    ctx: *mut ::aya_bpf_cty::c_void,
    params: *mut bpf_fib_lookup,
    plen: ::aya_bpf_cty::c_int,
    flags: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        params: *mut bpf_fib_lookup,
        plen: ::aya_bpf_cty::c_int,
        flags: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(69usize);
    f(ctx, params, plen, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sock_hash_update(
    skops: *mut bpf_sock_ops,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(70usize);
    f(skops, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_redirect_hash(
    msg: *mut sk_msg_md,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(71usize);
    f(msg, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_redirect_hash(
    skb: *mut __sk_buff,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(72usize);
    f(skb, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_lwt_push_encap(
    skb: *mut __sk_buff,
    type_: __u32,
    hdr: *mut ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        type_: __u32,
        hdr: *mut ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(73usize);
    f(skb, type_, hdr, len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_lwt_seg6_store_bytes(
    skb: *mut __sk_buff,
    offset: __u32,
    from: *const ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        from: *const ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(74usize);
    f(skb, offset, from, len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_lwt_seg6_adjust_srh(
    skb: *mut __sk_buff,
    offset: __u32,
    delta: __s32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        offset: __u32,
        delta: __s32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(75usize);
    f(skb, offset, delta)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_lwt_seg6_action(
    skb: *mut __sk_buff,
    action: __u32,
    param: *mut ::aya_bpf_cty::c_void,
    param_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        action: __u32,
        param: *mut ::aya_bpf_cty::c_void,
        param_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(76usize);
    f(skb, action, param, param_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_rc_repeat(ctx: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(ctx: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(77usize);
    f(ctx)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_rc_keydown(
    ctx: *mut ::aya_bpf_cty::c_void,
    protocol: __u32,
    scancode: __u64,
    toggle: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        protocol: __u32,
        scancode: __u64,
        toggle: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(78usize);
    f(ctx, protocol, scancode, toggle)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_cgroup_id(skb: *mut __sk_buff) -> __u64 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u64 = ::core::mem::transmute(79usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_cgroup_id() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(80usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_local_storage(
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(81usize);
    f(map, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_select_reuseport(
    reuse: *mut sk_reuseport_md,
    map: *mut ::aya_bpf_cty::c_void,
    key: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        reuse: *mut sk_reuseport_md,
        map: *mut ::aya_bpf_cty::c_void,
        key: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(82usize);
    f(reuse, map, key, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_ancestor_cgroup_id(
    skb: *mut __sk_buff,
    ancestor_level: ::aya_bpf_cty::c_int,
) -> __u64 {
    let f: unsafe extern "C" fn(
        skb: *mut __sk_buff,
        ancestor_level: ::aya_bpf_cty::c_int,
    ) -> __u64 = ::core::mem::transmute(83usize);
    f(skb, ancestor_level)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_lookup_tcp(
    ctx: *mut ::aya_bpf_cty::c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_size: __u32,
    netns: __u64,
    flags: __u64,
) -> *mut bpf_sock {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        tuple: *mut bpf_sock_tuple,
        tuple_size: __u32,
        netns: __u64,
        flags: __u64,
    ) -> *mut bpf_sock = ::core::mem::transmute(84usize);
    f(ctx, tuple, tuple_size, netns, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_lookup_udp(
    ctx: *mut ::aya_bpf_cty::c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_size: __u32,
    netns: __u64,
    flags: __u64,
) -> *mut bpf_sock {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        tuple: *mut bpf_sock_tuple,
        tuple_size: __u32,
        netns: __u64,
        flags: __u64,
    ) -> *mut bpf_sock = ::core::mem::transmute(85usize);
    f(ctx, tuple, tuple_size, netns, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_release(sock: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(sock: *mut ::aya_bpf_cty::c_void) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(86usize);
    f(sock)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_map_push_elem(
    map: *mut ::aya_bpf_cty::c_void,
    value: *const ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        value: *const ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(87usize);
    f(map, value, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_map_pop_elem(
    map: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(88usize);
    f(map, value)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_map_peek_elem(
    map: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(89usize);
    f(map, value)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_push_data(
    msg: *mut sk_msg_md,
    start: __u32,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        start: __u32,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(90usize);
    f(msg, start, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_msg_pop_data(
    msg: *mut sk_msg_md,
    start: __u32,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        msg: *mut sk_msg_md,
        start: __u32,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(91usize);
    f(msg, start, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_rc_pointer_rel(
    ctx: *mut ::aya_bpf_cty::c_void,
    rel_x: __s32,
    rel_y: __s32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        rel_x: __s32,
        rel_y: __s32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(92usize);
    f(ctx, rel_x, rel_y)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_spin_lock(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(93usize);
    f(lock)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_spin_unlock(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(lock: *mut bpf_spin_lock) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(94usize);
    f(lock)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_fullsock(sk: *mut bpf_sock) -> *mut bpf_sock {
    let f: unsafe extern "C" fn(sk: *mut bpf_sock) -> *mut bpf_sock =
        ::core::mem::transmute(95usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_tcp_sock(sk: *mut bpf_sock) -> *mut bpf_tcp_sock {
    let f: unsafe extern "C" fn(sk: *mut bpf_sock) -> *mut bpf_tcp_sock =
        ::core::mem::transmute(96usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_ecn_set_ce(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(97usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_listener_sock(sk: *mut bpf_sock) -> *mut bpf_sock {
    let f: unsafe extern "C" fn(sk: *mut bpf_sock) -> *mut bpf_sock =
        ::core::mem::transmute(98usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skc_lookup_tcp(
    ctx: *mut ::aya_bpf_cty::c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_size: __u32,
    netns: __u64,
    flags: __u64,
) -> *mut bpf_sock {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        tuple: *mut bpf_sock_tuple,
        tuple_size: __u32,
        netns: __u64,
        flags: __u64,
    ) -> *mut bpf_sock = ::core::mem::transmute(99usize);
    f(ctx, tuple, tuple_size, netns, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_tcp_check_syncookie(
    sk: *mut ::aya_bpf_cty::c_void,
    iph: *mut ::aya_bpf_cty::c_void,
    iph_len: __u32,
    th: *mut tcphdr,
    th_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        sk: *mut ::aya_bpf_cty::c_void,
        iph: *mut ::aya_bpf_cty::c_void,
        iph_len: __u32,
        th: *mut tcphdr,
        th_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(100usize);
    f(sk, iph, iph_len, th, th_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sysctl_get_name(
    ctx: *mut bpf_sysctl,
    buf: *mut ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *mut ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(101usize);
    f(ctx, buf, buf_len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sysctl_get_current_value(
    ctx: *mut bpf_sysctl,
    buf: *mut ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *mut ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(102usize);
    f(ctx, buf, buf_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sysctl_get_new_value(
    ctx: *mut bpf_sysctl,
    buf: *mut ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *mut ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(103usize);
    f(ctx, buf, buf_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sysctl_set_new_value(
    ctx: *mut bpf_sysctl,
    buf: *const ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_sysctl,
        buf: *const ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(104usize);
    f(ctx, buf, buf_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_strtol(
    buf: *const ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
    flags: __u64,
    res: *mut ::aya_bpf_cty::c_long,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        buf: *const ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
        flags: __u64,
        res: *mut ::aya_bpf_cty::c_long,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(105usize);
    f(buf, buf_len, flags, res)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_strtoul(
    buf: *const ::aya_bpf_cty::c_char,
    buf_len: ::aya_bpf_cty::c_ulong,
    flags: __u64,
    res: *mut ::aya_bpf_cty::c_ulong,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        buf: *const ::aya_bpf_cty::c_char,
        buf_len: ::aya_bpf_cty::c_ulong,
        flags: __u64,
        res: *mut ::aya_bpf_cty::c_ulong,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(106usize);
    f(buf, buf_len, flags, res)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_storage_get(
    map: *mut ::aya_bpf_cty::c_void,
    sk: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        sk: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(107usize);
    f(map, sk, value, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_storage_delete(
    map: *mut ::aya_bpf_cty::c_void,
    sk: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        sk: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(108usize);
    f(map, sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_send_signal(sig: __u32) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(sig: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(109usize);
    f(sig)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_tcp_gen_syncookie(
    sk: *mut ::aya_bpf_cty::c_void,
    iph: *mut ::aya_bpf_cty::c_void,
    iph_len: __u32,
    th: *mut tcphdr,
    th_len: __u32,
) -> __s64 {
    let f: unsafe extern "C" fn(
        sk: *mut ::aya_bpf_cty::c_void,
        iph: *mut ::aya_bpf_cty::c_void,
        iph_len: __u32,
        th: *mut tcphdr,
        th_len: __u32,
    ) -> __s64 = ::core::mem::transmute(110usize);
    f(sk, iph, iph_len, th, th_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_output(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(111usize);
    f(ctx, map, flags, data, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_read_user(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(112usize);
    f(dst, size, unsafe_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_read_kernel(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(113usize);
    f(dst, size, unsafe_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_read_user_str(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(114usize);
    f(dst, size, unsafe_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_probe_read_kernel_str(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    unsafe_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        unsafe_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(115usize);
    f(dst, size, unsafe_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_tcp_send_ack(
    tp: *mut ::aya_bpf_cty::c_void,
    rcv_nxt: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        tp: *mut ::aya_bpf_cty::c_void,
        rcv_nxt: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(116usize);
    f(tp, rcv_nxt)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_send_signal_thread(sig: __u32) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(sig: __u32) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(117usize);
    f(sig)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_jiffies64() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(118usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_read_branch_records(
    ctx: *mut bpf_perf_event_data,
    buf: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut bpf_perf_event_data,
        buf: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(119usize);
    f(ctx, buf, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_ns_current_pid_tgid(
    dev: __u64,
    ino: __u64,
    nsdata: *mut bpf_pidns_info,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dev: __u64,
        ino: __u64,
        nsdata: *mut bpf_pidns_info,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(120usize);
    f(dev, ino, nsdata, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_xdp_output(
    ctx: *mut ::aya_bpf_cty::c_void,
    map: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        map: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(121usize);
    f(ctx, map, flags, data, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_netns_cookie(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 {
    let f: unsafe extern "C" fn(ctx: *mut ::aya_bpf_cty::c_void) -> __u64 =
        ::core::mem::transmute(122usize);
    f(ctx)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_ancestor_cgroup_id(
    ancestor_level: ::aya_bpf_cty::c_int,
) -> __u64 {
    let f: unsafe extern "C" fn(ancestor_level: ::aya_bpf_cty::c_int) -> __u64 =
        ::core::mem::transmute(123usize);
    f(ancestor_level)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_assign(
    ctx: *mut ::aya_bpf_cty::c_void,
    sk: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ctx: *mut ::aya_bpf_cty::c_void,
        sk: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(124usize);
    f(ctx, sk, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ktime_get_boot_ns() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(125usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_seq_printf(
    m: *mut seq_file,
    fmt: *const ::aya_bpf_cty::c_char,
    fmt_size: __u32,
    data: *const ::aya_bpf_cty::c_void,
    data_len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        m: *mut seq_file,
        fmt: *const ::aya_bpf_cty::c_char,
        fmt_size: __u32,
        data: *const ::aya_bpf_cty::c_void,
        data_len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(126usize);
    f(m, fmt, fmt_size, data, data_len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_seq_write(
    m: *mut seq_file,
    data: *const ::aya_bpf_cty::c_void,
    len: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        m: *mut seq_file,
        data: *const ::aya_bpf_cty::c_void,
        len: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(127usize);
    f(m, data, len)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_cgroup_id(sk: *mut ::aya_bpf_cty::c_void) -> __u64 {
    let f: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> __u64 =
        ::core::mem::transmute(128usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sk_ancestor_cgroup_id(
    sk: *mut ::aya_bpf_cty::c_void,
    ancestor_level: ::aya_bpf_cty::c_int,
) -> __u64 {
    let f: unsafe extern "C" fn(
        sk: *mut ::aya_bpf_cty::c_void,
        ancestor_level: ::aya_bpf_cty::c_int,
    ) -> __u64 = ::core::mem::transmute(129usize);
    f(sk, ancestor_level)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ringbuf_output(
    ringbuf: *mut ::aya_bpf_cty::c_void,
    data: *mut ::aya_bpf_cty::c_void,
    size: __u64,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ringbuf: *mut ::aya_bpf_cty::c_void,
        data: *mut ::aya_bpf_cty::c_void,
        size: __u64,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(130usize);
    f(ringbuf, data, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ringbuf_reserve(
    ringbuf: *mut ::aya_bpf_cty::c_void,
    size: __u64,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        ringbuf: *mut ::aya_bpf_cty::c_void,
        size: __u64,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(131usize);
    f(ringbuf, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ringbuf_submit(data: *mut ::aya_bpf_cty::c_void, flags: __u64) {
    let f: unsafe extern "C" fn(data: *mut ::aya_bpf_cty::c_void, flags: __u64) =
        ::core::mem::transmute(132usize);
    f(data, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ringbuf_discard(data: *mut ::aya_bpf_cty::c_void, flags: __u64) {
    let f: unsafe extern "C" fn(data: *mut ::aya_bpf_cty::c_void, flags: __u64) =
        ::core::mem::transmute(133usize);
    f(data, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ringbuf_query(
    ringbuf: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> __u64 {
    let f: unsafe extern "C" fn(ringbuf: *mut ::aya_bpf_cty::c_void, flags: __u64) -> __u64 =
        ::core::mem::transmute(134usize);
    f(ringbuf, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_csum_level(
    skb: *mut __sk_buff,
    level: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff, level: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(135usize);
    f(skb, level)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skc_to_tcp6_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp6_sock {
    let f: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp6_sock =
        ::core::mem::transmute(136usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skc_to_tcp_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_sock {
    let f: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_sock =
        ::core::mem::transmute(137usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skc_to_tcp_timewait_sock(
    sk: *mut ::aya_bpf_cty::c_void,
) -> *mut tcp_timewait_sock {
    let f: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_timewait_sock =
        ::core::mem::transmute(138usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skc_to_tcp_request_sock(
    sk: *mut ::aya_bpf_cty::c_void,
) -> *mut tcp_request_sock {
    let f: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut tcp_request_sock =
        ::core::mem::transmute(139usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skc_to_udp6_sock(sk: *mut ::aya_bpf_cty::c_void) -> *mut udp6_sock {
    let f: unsafe extern "C" fn(sk: *mut ::aya_bpf_cty::c_void) -> *mut udp6_sock =
        ::core::mem::transmute(140usize);
    f(sk)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_task_stack(
    task: *mut task_struct,
    buf: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        task: *mut task_struct,
        buf: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(141usize);
    f(task, buf, size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_load_hdr_opt(
    skops: *mut bpf_sock_ops,
    searchby_res: *mut ::aya_bpf_cty::c_void,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        searchby_res: *mut ::aya_bpf_cty::c_void,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(142usize);
    f(skops, searchby_res, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_store_hdr_opt(
    skops: *mut bpf_sock_ops,
    from: *const ::aya_bpf_cty::c_void,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        from: *const ::aya_bpf_cty::c_void,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(143usize);
    f(skops, from, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_reserve_hdr_opt(
    skops: *mut bpf_sock_ops,
    len: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        skops: *mut bpf_sock_ops,
        len: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(144usize);
    f(skops, len, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_inode_storage_get(
    map: *mut ::aya_bpf_cty::c_void,
    inode: *mut ::aya_bpf_cty::c_void,
    value: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        inode: *mut ::aya_bpf_cty::c_void,
        value: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(145usize);
    f(map, inode, value, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_inode_storage_delete(
    map: *mut ::aya_bpf_cty::c_void,
    inode: *mut ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_int {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        inode: *mut ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_int = ::core::mem::transmute(146usize);
    f(map, inode)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_d_path(
    path: *mut path,
    buf: *mut ::aya_bpf_cty::c_char,
    sz: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        path: *mut path,
        buf: *mut ::aya_bpf_cty::c_char,
        sz: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(147usize);
    f(path, buf, sz)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_copy_from_user(
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
    user_ptr: *const ::aya_bpf_cty::c_void,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
        user_ptr: *const ::aya_bpf_cty::c_void,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(148usize);
    f(dst, size, user_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_snprintf_btf(
    str_: *mut ::aya_bpf_cty::c_char,
    str_size: __u32,
    ptr: *mut btf_ptr,
    btf_ptr_size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        str_: *mut ::aya_bpf_cty::c_char,
        str_size: __u32,
        ptr: *mut btf_ptr,
        btf_ptr_size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(149usize);
    f(str_, str_size, ptr, btf_ptr_size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_seq_printf_btf(
    m: *mut seq_file,
    ptr: *mut btf_ptr,
    ptr_size: __u32,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        m: *mut seq_file,
        ptr: *mut btf_ptr,
        ptr_size: __u32,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(150usize);
    f(m, ptr, ptr_size, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_skb_cgroup_classid(skb: *mut __sk_buff) -> __u64 {
    let f: unsafe extern "C" fn(skb: *mut __sk_buff) -> __u64 = ::core::mem::transmute(151usize);
    f(skb)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_redirect_neigh(
    ifindex: __u32,
    params: *mut bpf_redir_neigh,
    plen: ::aya_bpf_cty::c_int,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        ifindex: __u32,
        params: *mut bpf_redir_neigh,
        plen: ::aya_bpf_cty::c_int,
        flags: __u64,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(152usize);
    f(ifindex, params, plen, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_per_cpu_ptr(
    percpu_ptr: *const ::aya_bpf_cty::c_void,
    cpu: __u32,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        percpu_ptr: *const ::aya_bpf_cty::c_void,
        cpu: __u32,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(153usize);
    f(percpu_ptr, cpu)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_this_cpu_ptr(
    percpu_ptr: *const ::aya_bpf_cty::c_void,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        percpu_ptr: *const ::aya_bpf_cty::c_void,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(154usize);
    f(percpu_ptr)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_redirect_peer(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(ifindex: __u32, flags: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(155usize);
    f(ifindex, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_task_storage_get(
    map: *mut ::aya_bpf_cty::c_void,
    task: *mut task_struct,
    value: *mut ::aya_bpf_cty::c_void,
    flags: __u64,
) -> *mut ::aya_bpf_cty::c_void {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        task: *mut task_struct,
        value: *mut ::aya_bpf_cty::c_void,
        flags: __u64,
    ) -> *mut ::aya_bpf_cty::c_void = ::core::mem::transmute(156usize);
    f(map, task, value, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_task_storage_delete(
    map: *mut ::aya_bpf_cty::c_void,
    task: *mut task_struct,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        map: *mut ::aya_bpf_cty::c_void,
        task: *mut task_struct,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(157usize);
    f(map, task)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_get_current_task_btf() -> *mut task_struct {
    let f: unsafe extern "C" fn() -> *mut task_struct = ::core::mem::transmute(158usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_bprm_opts_set(
    bprm: *mut linux_binprm,
    flags: __u64,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(bprm: *mut linux_binprm, flags: __u64) -> ::aya_bpf_cty::c_long =
        ::core::mem::transmute(159usize);
    f(bprm, flags)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ktime_get_coarse_ns() -> __u64 {
    let f: unsafe extern "C" fn() -> __u64 = ::core::mem::transmute(160usize);
    f()
}
#[inline(always)]
pub unsafe extern "C" fn bpf_ima_inode_hash(
    inode: *mut inode,
    dst: *mut ::aya_bpf_cty::c_void,
    size: __u32,
) -> ::aya_bpf_cty::c_long {
    let f: unsafe extern "C" fn(
        inode: *mut inode,
        dst: *mut ::aya_bpf_cty::c_void,
        size: __u32,
    ) -> ::aya_bpf_cty::c_long = ::core::mem::transmute(161usize);
    f(inode, dst, size)
}
#[inline(always)]
pub unsafe extern "C" fn bpf_sock_from_file(file: *mut file) -> *mut socket {
    let f: unsafe extern "C" fn(file: *mut file) -> *mut socket = ::core::mem::transmute(162usize);
    f(file)
}
