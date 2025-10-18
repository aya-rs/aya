# Examples

```rust,no_run
use aya_ebpf::{
    maps::LruHashMap,
    macros::{map, tracepoint},
    programs::TracePointContext,
    EbpfContext as _,
};

/// A hash map that counts syscalls issued by different processes.
#[map]
static COUNTER: LruHashMap<
    // PID.
    u32,
    // Count of syscalls issued by the given process.
    u32,

> = LruHashMap::with_max_entries(
    // Maximum number of elements. Reaching this capacity triggers eviction of
    // the least used elements.
    10,
    // Optional flags.
    0
);

/// A simple program attached to the `sys_enter` tracepoint that counts
/// syscalls.
#[tracepoint]
fn sys_enter(ctx: TracePointContext) {
    let pid = ctx.pid();

    if let Some(mut count) = COUNTER.get_ptr_mut(pid) {
        unsafe { *count += 1 };
    } else {
        COUNTER.insert(
            pid,
            // New value.
            1,
            // Optional flags.
            0
        );
    }
}
```
