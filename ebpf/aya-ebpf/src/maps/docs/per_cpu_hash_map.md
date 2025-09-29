Similar to [`HashMap`] but each CPU holds a separate value for a given key.
Typically used to minimize lock contention in eBPF programs.

# Minimum kernel version

The minimum kernel version required to use this feature is 4.6.
