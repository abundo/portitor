#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# A QEMU virtual machine for trying the installer ISO:
#
#   iso/vm.sh install ISO    fresh 8 GB disk, install from ISO, power off at the end
#   iso/vm.sh run            boot the installed disk
#
# NIC 1 (52:54:00:00:00:01) is the WAN, NIC 2 (52:54:00:00:00:02) the LAN
# 192.168.1.0/24, whose QEMU router 192.168.1.2 also reaches the Internet.
# The GUI (192.168.1.1:443) is forwarded to https://127.0.0.1:$VM_GUI_PORT.
# The serial console goes to stdio, or to $VM_SERIAL: a file, or unix:PATH for
# a socket to drive it from a script. An ISO
# from `iso/build.sh --test` installs and sets itself up without questions.
# The QEMU guest agent is on build/vm/qga.sock (try: socat - unix:build/vm/qga.sock,
# then {"execute":"guest-ping"}).
#
# VM_UEFI=1 boots with OVMF instead of the BIOS.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=build/vm
DISK=$DIR/disk.qcow2
GUI_PORT=${VM_GUI_PORT:-28443}

args=(
	-machine q35,accel=kvm:tcg -cpu max -m 2048 -smp 2
	-drive "file=$DISK,if=virtio,format=qcow2"
	-nic "user,model=virtio-net-pci,mac=52:54:00:00:00:01"
	-nic "user,model=virtio-net-pci,mac=52:54:00:00:00:02,net=192.168.1.0/24,host=192.168.1.2,hostfwd=tcp:127.0.0.1:$GUI_PORT-192.168.1.1:443"
	-display none
	-device virtio-serial
	-chardev "socket,path=$DIR/qga.sock,server=on,wait=off,id=qga0"
	-device "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
)
if [[ ${VM_SERIAL:-} == unix:* ]]; then
	args+=(-serial "$VM_SERIAL,server=on,wait=off")
elif [[ -n ${VM_SERIAL:-} ]]; then
	args+=(-serial "file:$VM_SERIAL")
else
	args+=(-serial mon:stdio)
fi
if [[ -n ${VM_UEFI:-} ]]; then
	for fw in /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/qemu/OVMF.fd; do
		[[ -f $fw ]] && { args+=(-bios "$fw"); break; }
	done
fi

case ${1:-} in
install)
	iso=${2:?usage: iso/vm.sh install ISO}
	mkdir -p "$DIR"
	rm -f "$DISK"
	qemu-img create -q -f qcow2 "$DISK" 8G
	exec qemu-system-x86_64 "${args[@]}" -cdrom "$iso" -boot once=d -no-reboot
	;;
run)
	[[ -f $DISK ]] || { echo "no $DISK; run iso/vm.sh install ISO first" >&2; exit 1; }
	echo "GUI: https://127.0.0.1:$GUI_PORT/" >&2
	exec qemu-system-x86_64 "${args[@]}"
	;;
*)
	sed -n '5,19p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
