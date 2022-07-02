#!/bin/sh

set -e

# Temporary directory for tests to use.
AYA_TMPDIR="$(pwd)/.tmp"

# Directory for VM images
AYA_IMGDIR=${AYA_TMPDIR}

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
    remote=$(basename "$1")
    scp -q -F "${AYA_TMPDIR}/ssh_config" \
        -i "${AYA_TMPDIR}/test_rsa" \
        -P 2222 "${local}" \
        "${AYA_SSH_USER}@localhost:${remote}"
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

if [ -z "$1" ]; then
    echo "path to libbpf required"
    exit 1
fi

start_vm
trap stop_vm EXIT

cargo xtask build-integration-test --musl --libbpf-dir "$1"
scp_vm ../target/x86_64-unknown-linux-musl/debug/integration-test
exec_vm sudo ./integration-test
