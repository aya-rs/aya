# Breaking Changes

This document contains a list of breaking changes in each version and some notes
to help migrate between versions. It is compiled manually from the commit
history and changelog. We also tag PRs on github with a [breaking change] label.

[breaking change]: (https://github.com/aya-rs/aya/issues?q=label%3A%22breaking+change%22)

## Summary

- [v0.13.0](#v0130)
  - MSRV has been bumped to 1.85.0.

- [v0.12.0](#v0120)
  - In `aya::Bpf::programs`, `name` uses the function name from the ELF file.
  - Maps API has been reworked.
  - `aya::ProgramFd` trait has been removed.
  - `aya::BpfLoader::set_global` signature has changed.
  - MSRV has been bumped to 1.66.0.
  - BTF types have moved to the `aya-obj` crate.
  - `aya::PerfEvent::attach` and `detach` signatures have changed.

## v0.13.0

### MSRV has been bumped to 1.85.0

The minimum supported Rust version has been bumped to 1.85.0. This is due to
the move to edition 2024 which was first available in this version.

To migrate you will need to ensure that you are using rustc 1.85.0 or later.

## v0.12.0

### In `aya::Bpf::programs`, `name` uses the function name from the ELF file

In previous versions, the `name` parameter of `aya::Bpf::programs` was
derived from the ELF section name. If you were using `aya-bpf`, this was sensible
since our macros took care of appending the function name to the section name,
resulting in a section name like `kprobe/my_function`. However, loading this
program using libbpf > 1.0 would fail due the section name not following the
newly enforced [naming convention].

Likewise, loading eBPF programs written in C using Aya was also problematic.
Given the following C program:

```c
SEC("kprobe")
int my_function(struct pt_regs *ctx) {
    return 0;
}
```

Loading this program using Aya would require the following:

```rust
let bpf = Bpf::load(&program)?;
let my_function = bpf.program("kprobe")?;
```

This was not intuitive and was a frequent source of confusion.

To solve this, Aya was changed to resolve function names from the ELF files
symbol table. Therefore, if your function is defined as:

```rust
#[kprobe]
fn my_function(_ctx: KprobeContext) -> i32 {
    0
}
```

Or in C:

```c
SEC("kprobe")
int my_function(struct pt_regs *ctx) {
    return 0;
}
```

Then you should load it using:

```rust
let bpf = Bpf::load(&program)?;
let my_function = bpf.program("my_function")?;
```

Migration is straightforward. Simply replace the `name` parameter in
`Bpf::programs` with the function name from the ELF file.

If you are using `aya-bpf`, you should update to the latest (git)
version and recompile your programs. The name argument inside our macros
has been deprecated and should therefore be removed.

Given the following:

```rust
#[kprobe(name="another_name")]
fn some_name(_ctx: KprobeContext) -> i32 {
    0
}
```

You would update it to:

```rust
#[kprobe]
fn another_name(_ctx: KprobeContext) -> i32 {
    0
}
```

Note here that changing the exported function name is not supported anymore.

[naming convention]: https://docs.kernel.org/bpf/libbpf/program_types.html

### Maps API has been reworked

In v0.11.0 and earlier `aya::Bpf::map_mut` and `aya::Bpf::map` were used to
access maps. These functions returned a `Result` that contained a `MapRef` or
`MapRefMut` respectively.

Since the `OwnedFd` and `BorrowedFd` types were added to the Rust standard
library, we've been able to better reason around File descriptor ownership
and therefore the `MapRef` and `MapRefMut` types have been removed.

These APIs now return `Option<&Map>` or `Option<&mut Map>` respectively.
Additionally a new `aya::Bpf::take_map` method has been added to take ownership
of a map - a common requirement when working with maps using async.

### `aya::ProgramFd` trait has been removed

The `ProgramFd` trait has been removed. This trait was used to provide a
means of retrieving the file descriptor of a program. As with the maps API,
the `OwnedFd` and `BorrowedFd` types have made this trait redundant.

To migrate, you can remove any imports of the `ProgramFd` trait from your code
since `aya::Bpf::program::fd()` is available to retrieve the file descriptor.
The `fd()` method returns an `Result<ProgramFd, ProgramError>`, which differs
from the previous API that returned an `Option` so you will now have the ability
to handle errors more effectively.

### `aya::BpfLoader::set_global` signature has changed

The `value` in `set_global` was previously required to implement `aya::Pod`.
The constraint has now been changed to be `Into<aya::GlobalData>` which
includes both `aya::Pod` types and slices of `aya::Pod` types.

Additionally, a new argument `must_exist` has been added. If the `must_exist`
argument is true, BpfLoader::load will fail with
`aya::ParseError::SymbolNotFound` if the loaded object code does not contain
the variable.

### MSRV has been bumped to 1.66.0

The minimum supported Rust version has been bumped to 1.66.0. This is due to
the use of the `std::os::fd` module which was stabilized in this version.

To migrate you will need to ensure that you are using rustc 1.66.0 or later.

### BTF types have moved to the `aya-obj` crate

The BTF types have been moved to the `aya-obj` crate. This is to allow the
BTF and ELF parsing code to be used independently of `aya`.

To migrate, if you were using `aya::Btf::from_sys_fs` or `aya::Btf::parse_file`,
you should use `aya_obj::Btf::from_sys_fs` or `aya_obj::Btf::parse_file`.

### `aya::PerfEvent::attach` and `detach` signatures have changed

The `attach` method has been changed to take an additional boolean argument
called `inherit`. Where the `scope` argument determines which processes are
sampled, if `inherit` is true, any new processes spawned by those processes
will also automatically get sampled.

Also of note is that both `attach` and `detach` deal with a new type called
`PerfEventLinkId` where previously they used `PerfEventId`. This change was
required to support the more modern attachment method for perf event programs.
