#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Builds the Portitor installer ISO (amd64): Debian 13's netinst ISO with
# a preseed (preseed.cfg), Portitor as a release archive, and the first-boot
# setup (portitor-setup.py). See docs/appliance.md.
#
#   iso/build.sh                     Portitor from this tree (make release)
#   iso/build.sh --release v1.2.0    Portitor from a GitHub release
#   iso/build.sh --debian-iso FILE   use this netinst ISO (else downloaded)
#   iso/build.sh -o FILE             output (default build/portitor-<version>-amd64.iso)
#   iso/build.sh --test              unattended, for iso/vm.sh: erases /dev/vda without
#                                    asking, serial console, first-boot answers from
#                                    iso/test.answers (never for real hardware)
#
# Needs xorriso, curl, sha256sum; --source also go and npm. --release uses gh
# when it is logged in (a private repository), else curl.
set -euo pipefail

cd "$(dirname "$0")/.."
DEBIAN_URL=${DEBIAN_URL:-https://cdimage.debian.org/debian-cd/current/amd64/iso-cd}
REPO=${GITHUB_REPO:-abundo/portitor}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/portitor-iso
ARCH=amd64

release="" debian_iso="" out="" test=""
while (($#)); do
	case $1 in
	--source) release="" ;;
	--release) release=${2:?--release needs a tag}; shift ;;
	--debian-iso) debian_iso=${2:?}; shift ;;
	-o) out=${2:?}; shift ;;
	--test) test=1 ;;
	-h | --help) sed -n '5,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

log() { printf '\033[1m==> %s\033[0m\n' "$*"; }
for t in xorriso curl sha256sum; do
	command -v "$t" >/dev/null || { echo "$t is required" >&2; exit 1; }
done
mkdir -p "$CACHE" build
work=$(mktemp -d build/iso.XXXXXX)
trap 'rm -rf "$work"' EXIT

# ----- Debian netinst -----
if [[ -z $debian_iso ]]; then
	log "Looking up the Debian netinst ISO"
	curl -fsSL "$DEBIAN_URL/SHA256SUMS" -o "$work/SHA256SUMS"
	line=$(grep -E " debian-13\.[0-9.]+-$ARCH-netinst\.iso$" "$work/SHA256SUMS" | head -n 1) ||
		{ echo "no Debian 13 netinst ISO in $DEBIAN_URL (set DEBIAN_URL)" >&2; exit 1; }
	sum=${line%% *} name=${line##* }
	debian_iso=$CACHE/$name
	if [[ ! -f $debian_iso ]] || [[ $(sha256sum "$debian_iso" | cut -d' ' -f1) != "$sum" ]]; then
		log "Downloading $name"
		curl -fL --progress-bar "$DEBIAN_URL/$name" -o "$debian_iso.partial"
		mv "$debian_iso.partial" "$debian_iso"
	fi
	[[ $(sha256sum "$debian_iso" | cut -d' ' -f1) == "$sum" ]] || { echo "checksum mismatch: $debian_iso" >&2; exit 1; }
	log "$name: sha256 ok"
fi

# ----- Portitor -----
payload=$work/portitor
mkdir -p "$payload"
if [[ -n $release ]]; then
	version=${release#v}
	archive=portitor_${version}_linux_$ARCH.tar.gz
	sums=portitor_${version}_checksums.txt
	log "Downloading $archive"
	# gh works for a private repository too (GH_TOKEN, GITHUB_TOKEN or
	# `gh auth login`); plain curl only for a public one.
	if command -v gh >/dev/null && { [[ -n ${GH_TOKEN:-}${GITHUB_TOKEN:-} ]] || gh auth status >/dev/null 2>&1; }; then
		gh release download "v$version" -R "$REPO" -p "$archive" -p "$sums" -D "$work"
	else
		base=https://github.com/$REPO/releases/download/v$version
		curl -fsSL "$base/$sums" -o "$work/$sums"
		curl -fL --progress-bar "$base/$archive" -o "$work/$archive"
	fi
	mv "$work/$archive" "$payload/portitor.tar.gz"
	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$work/$sums")
	[[ -n $want && $(sha256sum "$payload/portitor.tar.gz" | cut -d' ' -f1) == "$want" ]] ||
		{ echo "checksum mismatch: $archive" >&2; exit 1; }
	version=v$version
else
	log "Building Portitor (make release)"
	CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH make -s release
	version=$(build/portitor-agent --version | awk '{ print $NF }')
	stage=$work/release
	mkdir -p "$stage"
	cp build/portitor-web build/portitor-agent install.py LICENSE README.md "$stage/"
	cp -r deploy "$stage/"
	tar -czf "$payload/portitor.tar.gz" -C "$stage" .
fi
cp iso/late.sh iso/target.sh iso/portitor-setup.py iso/portitor-firstboot.service "$payload/"
cp iso/preseed.cfg iso/grub.cfg iso/isolinux.cfg "$work/"
if [[ -n $test ]]; then
	log "Test ISO: unattended, erases /dev/vda"
	cp iso/test.answers "$payload/firstboot.answers"
	cat >>"$work/preseed.cfg" <<'PRESEED'

# --test: no questions at all.
d-i partman-auto/disk string /dev/vda
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
PRESEED
	# The installer and the installed system (what follows ---) on the
	# serial console, and no waiting in the boot menus.
	serial=console=ttyS0,115200n8
	sed -i "s/--- quiet/$serial --- $serial/; s/timeout=10/timeout=1/" "$work/grub.cfg"
	sed -i "s/--- quiet/$serial --- $serial/; s/timeout 100/timeout 10/" "$work/isolinux.cfg"
	version=$version-test
fi

# ----- ISO -----
out=${out:-build/portitor-$version-$ARCH.iso}
log "Writing $out"
rm -f "$out"
# The boot images and their El Torito/EFI setup are kept as they are
# (replay); only the boot menus change.
if ! xorriso -indev "$debian_iso" -outdev "$out" \
	-map "$work/preseed.cfg" /preseed.cfg \
	-map "$payload" /portitor \
	-map "$work/grub.cfg" /boot/grub/grub.cfg \
	-map "$work/isolinux.cfg" /isolinux/isolinux.cfg \
	-map iso/portitor.txt /isolinux/portitor.txt \
	-boot_image any replay >"$work/xorriso.log" 2>&1; then
	cat "$work/xorriso.log" >&2
	exit 1
fi
log "Done: $out ($(du -h "$out" | cut -f1))"
