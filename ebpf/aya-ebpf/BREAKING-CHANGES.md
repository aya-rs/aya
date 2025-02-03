# Breaking Changes

This document contains a list of breaking changes in each version and some notes
to help migrate between versions. It is compiled manually from the commit
history and changelog. We also tag PRs on github with a [breaking change] label.

[breaking change]: (https://github.com/aya-rs/aya/issues?q=label%3A%22breaking+change%22)

## Summary

- [unreleased](#unreleased)
  - `aya-ebpf::cty` has been removed. Please use `core::ffi` instead.

## Unreleased

### `aya-ebpf::cty` has been removed. Please use `core::ffi` instead

`aya-ebpf::cty` was a re-export of a crate called `aya-ebpf-cty`.
This crate, which itself was a fork of the `cty` crate, was used to provide
c types for use in bindgen.

Since `core::ffi` contains all of the types we need, there is no longer any
need for `aya-ebpf::cty`. If you were using `aya-ebpf::cty`, you can simply
replace it with `core::ffi`.
