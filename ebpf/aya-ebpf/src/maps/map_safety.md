# Safety

The pointer returned by a BPF map lookup is only stable until an update or
a delete. In the kernel’s default *preallocated* mode (no `BPF_F_NO_PREALLOC`),
deleted elements are immediately recycled onto a per-CPU freelist and may be
reused by another update before an RCU grace period elapses. Readers can
therefore observe aliasing (values changing underneath them) or, in rare cases,
false-positive lookups when an old and new key overlap. This behavior was
reported on [LKML in 2018][lkml-2018].

Using `BPF_F_NO_PREALLOC` historically forced RCU-delayed freeing, but since
the switch to `bpf_mem_alloc`, both prealloc and no-prealloc modes may recycle
elements quickly; the main distinction now is
[memory vs. allocation overhead][htab-atomic-overwrite].

The [official kernel docs][kernel-doc-map-hash] describe `BPF_F_NO_PREALLOC` as
a *memory-usage knob*, not a safety guarantee.

Patches in 2020 mitigated some issues (e.g.
[zero-filling reused per-CPU slots][zero-filling]) but did not eliminate reuse
races.

A 2023 patch by Alexei proposed a fallback scheme to
[delay reuse via RCU grace periods in certain conditions][reuse-delay] (rather
than always reusing immediately). However, this approach is not universally
applied, and immediate reuse is still considered a “known quirk” in many cases.

[lkml-2018]: https://lore.kernel.org/lkml/CAG48ez1-WZH55+Wa2vgwZY_hpZJfnDxMzxGLtuN1hG1z6hKf5Q@mail.gmail.com/T/
[htab-atomic-overwrite]: https://lore.kernel.org/bpf/20250204082848.13471-2-hotforest@gmail.com/T/
[kernel-doc-map-hash]: https://www.kernel.org/doc/html/v6.10/bpf/map_hash.html
[zero-filling]: https://lore.kernel.org/all/20201104112332.15191-1-david.verbeiren@tessares.net/
[reuse-delay]: https://lore.kernel.org/bpf/20230706033447.54696-13-alexei.starovoitov@gmail.com/
