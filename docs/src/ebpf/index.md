# eBPF Program Constraints

The eBPF Virtual Machine, where our eBPF programs will be run, is a constrained runtime environment:

- There is only 512 bytes of stack (or 256 bytes if we are using tail calls).
- There is no access to heap space and data must instead be written to maps.

Even applications written in C are restricted to a subset of language features:
- no loops
- no global variables
- no variadic functions
- no floating-point numbers
- no passing structures as function arguments

While these limitations do not map 1:1 with Rust, we are still constrained:

- We may not use the standard library. We use `core` instead.
- `core::fmt` may not be used and neither can traits that rely on it, for example `Display` and `Debug`
- As there is no heap, we cannot use `alloc` or `collections`.
- We must not `panic` as the eBPF VM does not support stack unwinding, or the `abort` instruction.
- There is no `main` function

Alongside this, a lot of the code that we write is `unsafe`, as we are reading directly from kernel memory.