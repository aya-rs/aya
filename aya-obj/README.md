# aya-obj - an eBPF object file loading library

## Overview

eBPF programs written with [libbpf] or [aya-bpf] are usually compiled
into an ELF object file, using various section to store information
about the eBPF programs.

`aya-obj` is a library that loads, parses and processes such eBPF
object files.

[libbpf]: https://github.com/libbpf/libbpf
[aya-bpf]: https://github.com/aya-rs/aya

## Example

This example loads a simple eBPF program and runs it with [rbpf].

```rust
use aya_bpf::Object;

// Parse the object file
let bytes = std::fs::read("program.o").unwrap();
let mut object = Object::parse(bytes).unwrap();
// Relocate the programs
object.relocate_calls().unwrap();
object.relocate_maps(std::iter::empty()).unwrap();

// Run with rbpf
let program = object.programs.iter().next().unwrap().1;
let instructions = &program.function.instructions;
let data = unsafe {
    from_raw_parts(
        instructions.as_ptr() as *const u8,
        instructions.len() * size_of::<bpf_insn>(),
    )
};
let vm = rbpf::EbpfVmNoData::new(Some(data)).unwrap();
let _return = vm.execute_program().unwrap();
```

[rbpf]: https://github.com/qmonnet/rbpf
