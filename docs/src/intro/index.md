# Introduction

Welcome to Building eBPF Programs with Aya: An introductory book about using the Rust
Programming Language and Aya library to build extended Berkley Packet Filter (eBPF)
programs.

## Who Aya Is For

Rust is proving to be a popular systems programming language because of its
safety features and excellent C interoperability. The safety features are less
important in the context of eBPF as programs often need to read kernel memory, which
is considered unsafe. However, what Rust combined with Aya does offer is a fast and 
efficient development experience:

- Cargo for project scaffolding, build, test and debugging
- Generation of Rust bindings to Kernel Headers with Compile-Once, Run-Everywhere (CO-RE) support
- Easy code sharing between user-space and eBPF programs
- Fast compile times
- No runtime dependency on LLVM or BCC

## Scope

The goals of this book are:

* Get developers up to speed with eBPF Rust development. i.e. How to set
  up a development environment.

* Share *current* best practices about using Rust for eBPF


## Who This Book is For

This book caters towards people with either some eBPF or some Rust background. For those without any prior knowledge we suggest you read the "Assumptions and Prerequisites" section first. You can check out the "Other Resources" section to find resources on topics you might want to read up on.

### Assumptions and Prerequisites

* You are comfortable using the Rust Programming Language, and have written,
  run, and debugged Rust applications on a desktop environment. You should also
  be familiar with the idioms of the [2018 edition] as this book targets
  Rust 2018.

[2018 edition]: https://doc.rust-lang.org/edition-guide/

* You are familiar with the core concepts of eBPF

### Other Resources

If you are unfamiliar with anything mentioned above or if you want more information about a specific topic mentioned in this book you might find some of these resources helpful.

| Topic        | Resource | Description |
|--------------|----------|-------------|
| Rust         | [Rust Book](https://doc.rust-lang.org/book/) | If you are not yet comfortable with Rust, we highly suggest reading this book. |
| eBPF         | [Cilium BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/) | If you are not yet comfortable with eBPF, this guide is excellent. |

## How to Use This Book

This book generally assumes that you’re reading it front-to-back. Later
chapters build on concepts in earlier chapters, and earlier chapters may
not dig into details on a topic, revisiting the topic in a later chapter.

## Source Code

The source files from which this book is generated can be found on [GitHub][github].

[github]: https://github.com/alessandrod/aya