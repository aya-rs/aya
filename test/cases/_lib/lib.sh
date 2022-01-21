#!/bin/sh

# Source the main regression test library if present
[ -f "${RT_LIB}" ] && . "${RT_LIB}"

# Temporary directory for tests to use.
AYA_TMPDIR="${RT_PROJECT_ROOT}/_tmp"

# Directory for VM images
AYA_IMGDIR="${RT_PROJECT_ROOT}/_images"

# Test Architecture
if [ -z "${AYA_TEST_ARCH}" ]; then
    AYA_TEST_ARCH="$(uname -m)"
fi

# Test Image
if [ -z "${AYA_TEST_IMAGE}" ]; then
    AYA_TEST_IMAGE="fedora35"
fi

case "${AYA_TEST_IMAGE}" in
    fedora*) AYA_SSH_USER="fedora";;
    centos*) AYA_SSH_USER="centos";;
esac

# compiles the ebpf program by using rust-script to create a temporary
# cargo project in $(pwd)/ebpf. caller must add rm -rf ebpf to the clean_up
# functionAYA_TEST_ARCH
compile_ebpf() {
    file=$(basename "$1")
    dir=$(dirname "$1")
    base=$(echo "${file}" | cut -f1 -d '.')

    rm -rf "${dir}/ebpf"

    rust-script --pkg-path "${dir}/ebpf" --gen-pkg-only "$1"
    artifact=$(sed -n 's/^name = \"\(.*\)\"/\1/p' "${dir}/ebpf/Cargo.toml" | head -n1)

    mkdir -p "${dir}/.cargo"
    cat > "${dir}/.cargo/config.toml" << EOF
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]
EOF
    cat >> "${dir}/ebpf/Cargo.toml" << EOF
[workspace]
members = []
EOF
    # overwrite the rs file as rust-script adds a main fn
    cp "$1" "${dir}/ebpf/${file}"
    cargo build -q --manifest-path "${dir}/ebpf/Cargo.toml"
    mv "${dir}/ebpf/target/bpfel-unknown-none/debug/${artifact}" "${dir}/${base}.o"
    rm -rf "${dir}/.cargo"
    rm -rf "${dir}/ebpf"
}

# compile a C BPF file
compile_c_ebpf() {
    file=$(basename "$1")
    dir=$(dirname "$1")
    base=$(echo "${file}" | cut -f1 -d '.')

    rust-script "${RT_PROJECT_ROOT}/_lib/compile-ebpf.ers" "${1}" "${dir}/${base}.o"
    rm -rf "${dir}/include"
}

# compiles the userspace program by using rust-script to create a temporary
# cargo project in $(pwd)/user. caller must add rm -rf ebpf to the clean_up
# function. this is required since the binary produced has to be run with
# sudo to load an eBPF program
compile_user() {
    file=$(basename "$1")
    dir=$(dirname "$1")
    base=$(echo "${file}" | cut -f1 -d '.')

    rm -rf "${dir}/user"

    rust-script --pkg-path "${dir}/user" --gen-pkg-only "$1"
    artifact=$(sed -n 's/^name = \"\(.*\)\"/\1/p' "${dir}/user/Cargo.toml" | head -n1)
    cat >> "${dir}/user/Cargo.toml" << EOF
[workspace]
members = []
EOF
    cargo build -q --release --manifest-path "${dir}/user/Cargo.toml" --target=x86_64-unknown-linux-musl
    mv "${dir}/user/target/x86_64-unknown-linux-musl/release/${artifact}" "${dir}/${base}"
    rm -rf "${dir}/user"
}

download_images() {
    mkdir -p "${AYA_IMGDIR}"
    case $1 in
        fedora35)
            if [ ! -f "${AYA_IMGDIR}/fedora35.${AYA_TEST_ARCH}.qcow2" ]; then
                IMAGE="Fedora-Cloud-Base-35-1.2.${AYA_TEST_ARCH}.qcow2"
                IMAGE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/35/Cloud/${AYA_TEST_ARCH}/images"
                echo "Downloading: ${IMAGE}, this may take a while..."
                curl -o "${AYA_IMGDIR}/fedora35.${AYA_TEST_ARCH}.qcow2" -sSL "${IMAGE_URL}/${IMAGE}"
            fi
            ;;
        centos8)
            if [ ! -f "${AYA_IMGDIR}/centos8.${AYA_TEST_ARCH}.qcow2" ]; then
                IMAGE="CentOS-8-GenericCloud-8.4.2105-20210603.0.${AYA_TEST_ARCH}.qcow2"
                IMAGE_URL="https://cloud.centos.org/centos/8/${AYA_TEST_ARCH}/images"
                echo "Downloading: ${IMAGE}, this may take a while..."
                curl -o "${AYA_IMGDIR}/centos8.${AYA_TEST_ARCH}.qcow2" -sSL "${IMAGE_URL}/${IMAGE}"
            fi
            ;;
        *)
            echo "$1 is not a recognized image name"
            return 1
            ;;
    esac
}

start_vm() {
    download_images "${AYA_TEST_IMAGE}"
    # prepare config
    cat > "${AYA_TMPDIR}/metadata.yaml" <<EOF
instance-id: iid-local01
local-hostname: test
EOF

    if [ ! -f "${AYA_TMPDIR}/test_rsa" ]; then
        ssh-keygen -t rsa -b 4096 -f "${AYA_TMPDIR}/test_rsa" -N "" -C "" -q
        pub_key=$(cat "${AYA_TMPDIR}/test_rsa.pub")
        cat > "${AYA_TMPDIR}/user-data.yaml" <<EOF
#cloud-config
ssh_authorized_keys:
  - ${pub_key}
EOF
    fi

    if [ ! -f "${AYA_TMPDIR}/ssh_config" ]; then
        cat > "${AYA_TMPDIR}/ssh_config" <<EOF
StrictHostKeyChecking=no
UserKnownHostsFile=/dev/null
GlobalKnownHostsFile=/dev/null
EOF
    fi

    cloud-localds "${AYA_TMPDIR}/seed.img" "${AYA_TMPDIR}/user-data.yaml" "${AYA_TMPDIR}/metadata.yaml"

    case "${AYA_TEST_ARCH}" in
        x86_64)
            QEMU=qemu-system-x86_64
            machine="q35"
            cpu="qemu64"
            if [ "$(uname -m)" = "${AYA_TEST_ARCH}" ]; then
                if [ -c /dev/kvm ]; then
                    machine="${machine},accel=kvm"
                    cpu="host"
                elif [ "$(uname -s)" = "Darwin" ]; then
                    machine="${machine},accel=hvf"
                    cpu="host"
                fi
            fi
            ;;
        aarch64)
            QEMU=qemu-system-aarch64
            machine="virt"
            cpu="cortex-a57"
            if [ "$(uname -m)" = "${AYA_TEST_ARCH}" ]; then
                if [ -c /dev/kvm ]; then
                    machine="${machine},accel=kvm"
                    cpu="host"
                elif [ "$(uname -s)" = "Darwin" ]; then
                    machine="${machine},accel=hvf"
                    cpu="host"
                fi
            fi
            ;;
        *)
            echo "${AYA_TEST_ARCH} is not supported"
            return 1
        ;;
    esac

    qemu-img create -F qcow2 -f qcow2 -o backing_file="${AYA_IMGDIR}/${AYA_TEST_IMAGE}.${AYA_TEST_ARCH}.qcow2" "${AYA_TMPDIR}/vm.qcow2" || return 1
    $QEMU \
        -machine "${machine}" \
        -cpu "${cpu}" \
        -m 2G \
        -display none \
        -monitor none \
        -daemonize \
        -pidfile "${AYA_TMPDIR}/vm.pid" \
        -device virtio-net-pci,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::2222-:22 \
        -drive if=virtio,format=qcow2,file="${AYA_TMPDIR}/vm.qcow2" \
        -drive if=virtio,format=raw,file="${AYA_TMPDIR}/seed.img" || return 1

    trap cleanup_vm EXIT
    echo "Waiting for SSH on port 2222..."
    retry=0
    max_retries=300
    while ! ssh -q -F "${AYA_TMPDIR}/ssh_config" -o ConnectTimeout=1 -i "${AYA_TMPDIR}/test_rsa" ${AYA_SSH_USER}@localhost -p 2222 echo "Hello VM"; do
        retry=$((retry+1))
        if [ ${retry} -gt ${max_retries} ]; then
            echo "Unable to connect to VM"
            return 1
        fi
        sleep 1
    done

    echo "VM launched, installing dependencies"
    exec_vm sudo dnf install -qy bpftool
}

scp_vm() {
    local=$1
    scp -q -F "${AYA_TMPDIR}/ssh_config" \
        -i "${AYA_TMPDIR}/test_rsa" \
        -P 2222 "${local}" \
        "${AYA_SSH_USER}@localhost:${local}"
}

exec_vm() {
    ssh -q -F "${AYA_TMPDIR}/ssh_config" \
        -i "${AYA_TMPDIR}/test_rsa" \
        -p 2222 \
        ${AYA_SSH_USER}@localhost \
        "$@"
}

stop_vm() {
    if [ -f "${AYA_TMPDIR}/vm.pid" ]; then
        echo "Stopping VM forcefully"
        kill -9 "$(cat "${AYA_TMPDIR}/vm.pid")"
        rm "${AYA_TMPDIR}/vm.pid"
    fi
    rm -f "${AYA_TMPDIR}/vm.qcow2"
}

cleanup_vm() {
    if [ "$?" != "0" ]; then
        stop_vm
    fi
}
