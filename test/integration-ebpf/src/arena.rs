#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]
#![expect(internal_features, reason = "atomic_xadd is unstable")]
#![expect(unstable_features, reason = "atomic_xadd is unstable")]
#![feature(core_intrinsics)]

use aya_ebpf::{
    arena::ArenaPtr,
    btf_maps::Arena,
    macros::{btf_map, map, uprobe},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::arena::{Node, Root};

#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static ARENA: Arena<4> = Arena::new();

/// Bootstrap: userspace stores the root object's user-space address here.
/// The arena's user mapping lives at an arbitrary base address, so pointer
/// chains must be anchored at an address provided by userspace.
#[map]
static ROOT_PTR: Array<u64> = Array::with_max_entries(1, 0);

const MAX_LIST_NODES: usize = 3;

#[uprobe]
fn arena_test(_ctx: ProbeContext) {
    let Some(root_va) = ROOT_PTR.get(0) else {
        return;
    };
    let root: ArenaPtr<Root> = ARENA.ptr_from_user_va(*root_va);
    // SAFETY: userspace initializes aligned Root and Node values before the
    // probe runs and does not access them again until the probe returns.
    let mut r = unsafe { root.read() };
    r.counter += 1;

    // Walk the linked list built by userspace, summing and doubling each
    // node's value. Every `next` is loaded from arena memory as a plain
    // integer and re-blessed by ArenaPtr on the following dereference.
    let mut sum = 0u64;
    let mut node = ArenaPtr::<Node>::from_user_va(r.head);
    for _ in 0..MAX_LIST_NODES {
        if node.is_null() {
            break;
        }
        // SAFETY: the list consists of initialized, aligned Node values and
        // userspace does not access it while the probe is running.
        let mut n = unsafe { node.read() };
        sum += n.value;
        n.value *= 2;
        unsafe {
            node.write(n);
        }
        node = ArenaPtr::from_user_va(n.next);
    }
    r.sum = sum;
    unsafe {
        root.write(r);
    }
}

#[uprobe]
fn arena_atomic(_ctx: ProbeContext) {
    let Some(counter_va) = ROOT_PTR.get(0) else {
        return;
    };
    let counter = ARENA.ptr_from_user_va::<u64>(*counter_va);

    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            counter.as_ptr(),
            1,
        );
    }
}
