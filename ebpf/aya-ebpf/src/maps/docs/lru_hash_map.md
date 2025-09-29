An LRU hash map that can be shared between eBPF programs and user space.
When it reaches the capacity `M`, the least used element is evicted.

# Minimum kernel version

The minimum kernel version required to use this feature is 4.10.
