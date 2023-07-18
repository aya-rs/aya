#!/bin/sh

set -e

if [ "$(uname -s)" = "Darwin" ]; then
    export PATH="$(dirname $(brew list gnu-getopt | grep "bin/getopt$")):$PATH"
fi

AYA_SOURCE_DIR="$(realpath $(dirname $0)/..)"

# Temporary directory for tests to use.
AYA_TMPDIR="${AYA_SOURCE_DIR}/.tmp"

# Directory for VM images
AYA_IMGDIR=${AYA_TMPDIR}

if [ -z "${AYA_BUILD_TARGET}" ]; then
    AYA_BUILD_TARGET=$(rustc -vV | sed -n 's|host: ||p')
fi

AYA_HOST_ARCH=$(uname -m)
if [ "${AYA_HOST_ARCH}" = "arm64" ]; then
    AYA_HOST_ARCH="aarch64"
fi

if [ -z "${AYA_GUEST_ARCH}" ]; then
    AYA_GUEST_ARCH="${AYA_HOST_ARCH}"
fi

if [ "${AYA_GUEST_ARCH}" = "aarch64" ]; then
    if [ -z "${AARCH64_UEFI}" ]; then
        AARCH64_UEFI="$(brew list qemu -1 -v | grep edk2-aarch64-code.fd)"
    fi
fi

if [ -z "$AYA_MUSL_TARGET" ]; then
    AYA_MUSL_TARGET=${AYA_GUEST_ARCH}-unknown-linux-musl
fi

# Test Image
if [ -z "${AYA_TEST_IMAGE}" ]; then
    AYA_TEST_IMAGE="fedora38"
fi

case "${AYA_TEST_IMAGE}" in
    fedora*) AYA_SSH_USER="fedora";;
    centos*) AYA_SSH_USER="centos";;
esac

download_images() {
    mkdir -p "${AYA_IMGDIR}"
    case $1 in
        fedora37)
            if [ ! -f "${AYA_IMGDIR}/fedora37.${AYA_GUEST_ARCH}.qcow2" ]; then
                IMAGE="Fedora-Cloud-Base-37-1.7.${AYA_GUEST_ARCH}.qcow2"
                IMAGE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/37/Cloud/${AYA_GUEST_ARCH}/images"
                echo "Downloading: ${IMAGE}, this may take a while..."
                curl -o "${AYA_IMGDIR}/fedora37.${AYA_GUEST_ARCH}.qcow2" -sSL "${IMAGE_URL}/${IMAGE}"
            fi
            ;;
        fedora38)
            if [ ! -f "${AYA_IMGDIR}/fedora38.${AYA_GUEST_ARCH}.qcow2" ]; then
                IMAGE="Fedora-Cloud-Base-38_Beta-1.3.${AYA_GUEST_ARCH}.qcow2"
                IMAGE_URL="https://fr2.rpmfind.net/linux/fedora/linux/releases/test/38_Beta/Cloud/${AYA_GUEST_ARCH}/images"
                echo "Downloading: ${IMAGE}, this may take a while..."
                curl -o "${AYA_IMGDIR}/fedora38.${AYA_GUEST_ARCH}.qcow2" -sSL "${IMAGE_URL}/${IMAGE}"
            fi
            ;;
        centos8)
            if [ ! -f "${AYA_IMGDIR}/centos8.${AYA_GUEST_ARCH}.qcow2" ]; then
                IMAGE="CentOS-8-GenericCloud-8.4.2105-20210603.0.${AYA_GUEST_ARCH}.qcow2"
                IMAGE_URL="https://cloud.centos.org/centos/8/${AYA_GUEST_ARCH}/images"
                echo "Downloading: ${IMAGE}, this may take a while..."
                curl -o "${AYA_IMGDIR}/centos8.${AYA_GUEST_ARCH}.qcow2" -sSL "${IMAGE_URL}/${IMAGE}"
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
    fi

    if [ ! -f "${AYA_TMPDIR}/ssh_config" ]; then
        cat > "${AYA_TMPDIR}/ssh_config" <<EOF
StrictHostKeyChecking=no
UserKnownHostsFile=/dev/null
GlobalKnownHostsFile=/dev/null
EOF
    fi

    cat > "${AYA_TMPDIR}/user-data.yaml" <<EOF
#cloud-config
ssh_authorized_keys:
  - ${pub_key}
EOF

    $AYA_SOURCE_DIR/test/cloud-localds "${AYA_TMPDIR}/seed.img" "${AYA_TMPDIR}/user-data.yaml" "${AYA_TMPDIR}/metadata.yaml"
    case "${AYA_GUEST_ARCH}" in
        x86_64)
            QEMU=qemu-system-x86_64
            machine="q35"
            cpu="qemu64"
            nr_cpus="$(nproc --all)"
            if [ "${AYA_HOST_ARCH}" = "${AYA_GUEST_ARCH}" ]; then
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
            uefi="-drive file=${AARCH64_UEFI},if=pflash,format=raw,readonly=on"
            if [ "${AYA_HOST_ARCH}" = "${AYA_GUEST_ARCH}" ]; then
                if [ -c /dev/kvm ]; then
                    machine="${machine},accel=kvm"
                    cpu="host"
                    nr_cpus="$(nproc --all)"
                elif [ "$(uname -s)" = "Darwin" ]; then
                    machine="${machine},accel=hvf,highmem=off"
                    cpu="cortex-a72"
                    # nrpoc --all on apple silicon returns the two extra fancy
                    # cores and then qemu complains that nr_cpus > actual_cores
                    nr_cpus=8
                fi
            fi
            ;;
        *)
            echo "${AYA_GUEST_ARCH} is not supported"
            return 1
        ;;
    esac

    if [ ! -f "${AYA_IMGDIR}/vm.qcow2" ]; then
        echo "Creating VM image"
        qemu-img create -F qcow2 -f qcow2 -o backing_file="${AYA_IMGDIR}/${AYA_TEST_IMAGE}.${AYA_GUEST_ARCH}.qcow2" "${AYA_IMGDIR}/vm.qcow2" || return 1
        CACHED_VM=0
    else
        echo "Reusing existing VM image"
        CACHED_VM=1
    fi
    $QEMU \
        -machine "${machine}" \
        -cpu "${cpu}" \
        -m 3G \
        -smp "${nr_cpus}" \
        -display none \
        -monitor none \
        -daemonize \
        -pidfile "${AYA_TMPDIR}/vm.pid" \
        -device virtio-net-pci,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::2222-:22 \
        $uefi \
        -drive if=virtio,format=qcow2,file="${AYA_IMGDIR}/vm.qcow2" \
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

    echo "VM launched"
    exec_vm uname -a
    echo "Enabling testing repositories"
    exec_vm sudo dnf config-manager --set-enabled updates-testing
    exec_vm sudo dnf config-manager --set-enabled updates-testing-modular
    echo "Installing dependencies"
    exec_vm sudo dnf install -qy bpftool llvm llvm-devel clang clang-devel zlib-devel git
    exec_vm 'curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
        -y --profile minimal --default-toolchain nightly --component rust-src --component clippy'
    exec_vm 'echo source ~/.cargo/env >> ~/.bashrc'
}

scp_vm() {
    local=$1
    remote=$(basename "$1")
    scp -q -F "${AYA_TMPDIR}/ssh_config" \
        -i "${AYA_TMPDIR}/test_rsa" \
        -P 2222 "${local}" \
        "${AYA_SSH_USER}@localhost:${remote}"
}

rsync_vm() {
    rsync -a -e "ssh -p 2222 -F ${AYA_TMPDIR}/ssh_config -i ${AYA_TMPDIR}/test_rsa" $1 $AYA_SSH_USER@localhost:
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
}

cleanup_vm() {
    stop_vm
    if [ "$?" != "0" ]; then
        rm -f "${AYA_IMGDIR}/vm.qcow2"
    fi
}

start_vm
trap cleanup_vm EXIT

# make sure we always use fresh sources (also see comment at the end)
exec_vm "rm -rf aya/*"
rsync_vm "--exclude=target --exclude=.tmp $AYA_SOURCE_DIR"

exec_vm "cd aya; cargo xtask integration-test"

# we rm and sync but it doesn't seem to work reliably - I guess we could sleep a
# few seconds after but ain't nobody got time for that. Instead we also rm
# before rsyncing.
exec_vm "rm -rf aya/*; sync"
