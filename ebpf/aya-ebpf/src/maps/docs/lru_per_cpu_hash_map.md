<!-- This is a Rust docstring which should not start with a top-level heading.
-->
<!-- markdownlint-disable MD041 -->

Similar to [`LruHashMap`] but each CPU holds a separate value for a given
key. Typically used to minimize lock contention in eBPF programs.

# Minimum kernel version

The minimum kernel version required to use this feature is 4.10.
