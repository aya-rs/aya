# Integration VM kernel configuration

`aya_aarch64.config` and `aya_x86_64.config` are KCONFIG_ALLCONFIG request
fragments for the Linux 6.18.2 integration VM kernels declared in
`MODULE.bazel`. `linux.bzl` resolves each fragment from `allnoconfig` with the
integrity-pinned Linux source archive.

The fragments contain requested values, not complete Linux `.config` files.
Linux Kconfig adds defaults and values derived through dependencies, `select`,
and `imply`. Keep an assignment in a fragment when an integration VM requires
the value or when the assignment intentionally pins a Kconfig default. Do not
copy generated values from a resolved `.config` into a fragment.

## Reproduce the resolved configurations

From the repository root, resolve the aarch64 fragment with:

```console
$ bazel build --lockfile_mode=error \
    @aya_aarch64_kernel//:config
```

Resolve the x86_64 fragment with:

```console
$ bazel build --lockfile_mode=error \
    @aya_x86_64_kernel//:config
```

After changing either fragment, rebuild both resolved configurations and run:

```console
$ bazel test --config=remote --lockfile_mode=error \
    //test/integration-test:vm_aarch64 \
    //test/integration-test:vm_x86_64
```
