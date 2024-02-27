# Breaking Changes

This document contains a list of breaking changes in each version and some notes
to help migrate between versions. It is compiled manually from the commit
history and changelog. We also tag PRs on github with a [breaking change] label.

[breaking change]: (https://github.com/aya-rs/aya/issues?q=label%3A%22breaking+change%22)

## Summary

- [v0.12.0](#v0120)
  - In `aya::Bpf::programs`, `name` uses the function name from the ELF file.

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
