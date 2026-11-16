#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Builds the Portitor installer ISO (amd64): Debian 13's netinst ISO with
# a preseed (preseed.cfg), Portitor as a release archive, the first-boot
# setup (portitor-setup.py) and a package repository (packages.txt and
# everything they need), so that the installation needs no network.
# See docs/appliance.md.
#
#   iso/build.sh                     Portitor from this tree (make release)
#   iso/build.sh --release v1.2.0    Portitor from a GitHub release
#   iso/build.sh --debian-iso FILE   use this netinst ISO (else downloaded)
#   iso/build.sh --refresh-packages  download the packages again (else kept in the
#                                    cache while iso/packages.txt is unchanged)
#   iso/build.sh -o FILE             output (default build/portitor-<version>-amd64.iso)
#   iso/build.sh --test              unattended, for iso/vm.sh: erases /dev/vda without
#                                    asking, serial console, first-boot answers from
#                                    iso/test.answers (never for real hardware)
#   iso/build.sh --answers FILE      --test with these first-boot answers
#
# Needs xorriso, curl, sha256sum and podman (or docker, for the packages);
# --source also go and npm. --release uses gh when it is logged in (a private
# repository), else curl.
set -euo pipefail

cd "$(dirname "$0")/.."
DEBIAN_URL=${DEBIAN_URL:-https://cdimage.debian.org/debian-cd/current/amd64/iso-cd}
REPO=${GITHUB_REPO:-abundo/portitor}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/portitor-iso
ARCH=amd64

release="" debian_iso="" out="" test="" refresh="" answers=iso/test.answers
while (($#)); do
	case $1 in
	--source) release="" ;;
	--release) release=${2:?--release needs a tag}; shift ;;
	--debian-iso) debian_iso=${2:?}; shift ;;
	--refresh-packages) refresh=1 ;;
	-o) out=${2:?}; shift ;;
	--test) test=1 ;;
	--answers) answers=${2:?--answers needs a file}; test=1; shift ;;
	-h | --help) sed -n '5,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# ----- Packages -----
# What the installed system has beyond the installer's base: iso/packages.txt
# with everything it depends on, as a flat apt repository on the ISO. The list
# is resolved as on an empty system (no dpkg status), in a Debian 13 container
# with ISC's BIND repository (as install.py adds it), so the repository is
# complete whatever the base ISO holds. Kept in the cache while packages.txt
# and the key are unchanged; --refresh-packages downloads again (security
# updates since).
ctr=$(command -v podman || command -v docker || true)
[[ -n $ctr ]] || { echo "podman or docker is required (for the packages)" >&2; exit 1; }
key=$(cat iso/packages.txt deploy/apt/isc-bind.asc | sha256sum | cut -c1-16)
repo=$CACHE/repo-$key
if [[ -n $refresh || ! -f $repo/Release ]]; then
	log "Downloading the packages (iso/packages.txt and their dependencies)"
	rm -rf "$repo" "$repo.partial"
	mkdir -p "$repo.partial"
	"$ctr" run --rm --platform linux/amd64 --security-opt label=disable \
		-v "$PWD/iso/packages.txt:/packages.txt:ro" \
		-v "$PWD/deploy/apt/isc-bind.asc:/isc-bind.asc:ro" \
		-v "$repo.partial:/out" \
		docker.io/library/debian:trixie bash -eu -c '
export DEBIAN_FRONTEND=noninteractive
# The image deletes downloaded packages; here they are the product.
rm -f /etc/apt/apt.conf.d/docker-clean
echo "APT::Keep-Downloaded-Packages \"true\";" >/etc/apt/apt.conf.d/99keep
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates apt-utils
install -m 0644 /isc-bind.asc /usr/share/keyrings/isc-bind.asc
echo "deb [signed-by=/usr/share/keyrings/isc-bind.asc] https://bind.debian.net/bind trixie main" \
	>/etc/apt/sources.list.d/isc-bind.list
apt-get update -q
apt-get clean
pkgs=$(sed "s/#.*//" /packages.txt | tr -s "[:space:]" " ")
apt-get install -y -q --no-install-recommends --download-only -o Dir::State::status=/dev/null $pkgs
cp /var/cache/apt/archives/*.deb /out/
cd /out
apt-ftparchive packages . >Packages
gzip -9kf Packages
apt-ftparchive release . >Release
' || { rm -rf "$repo.partial"; exit 1; }
	mv "$repo.partial" "$repo"
	# Older repositories of the cache are of no use.
	find "$CACHE" -maxdepth 1 -name 'repo-*' ! -name "repo-$key" -exec rm -rf {} +
fi
log "Packages: $(ls "$repo"/*.deb | wc -l) files, $(du -sh "$repo" | cut -f1)"

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
	# install.py (in target.sh) needs these; v0.1.0's archive lacked the configs.
	# (Listed once: grep -q on tar's output would fail it with SIGPIPE.)
	members=$(tar -tzf "$payload/portitor.tar.gz")
	for f in install.py portitor-web portitor-agent deploy/agent.yaml deploy/web.yaml; do
		grep -qxE "(\./)?$f" <<<"$members" ||
			{ echo "$archive does not contain $f" >&2; exit 1; }
	done
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
cp iso/late.sh iso/target.sh iso/packages.txt iso/portitor-setup.py iso/portitor-setup.bash iso/portitor-firstboot.service \
	iso/portitor-recover.sh iso/portitor-recovery.service iso/portitor-issue.sh iso/portitor-issue.service iso/42_portitor_recovery "$payload/"
# The setup shows the release's version at the bottom right.
sed -i "s/^SETUP_VERSION = .*/SETUP_VERSION = \"$version\"/" "$payload/portitor-setup.py"
cp iso/preseed.cfg iso/grub.cfg iso/isolinux.cfg "$work/"
if [[ -n $test ]]; then
	log "Test ISO: unattended, erases /dev/vda"
	cp "$answers" "$payload/firstboot.answers"
	cat >>"$work/preseed.cfg" <<'PRESEED'

# --test: no questions at all.
d-i partman-auto/disk string /dev/vda
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
PRESEED
	# The installer and the installed system (what follows ---) on the
	# serial console, and no waiting in the boot menus. (Every installed system
	# has ttyS0 as a console too, target.sh; this one names it last, so it is
	# /dev/console and gets systemd's boot messages.)
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
	-map "$repo" /portitor/repo \
	-map "$work/grub.cfg" /boot/grub/grub.cfg \
	-map "$work/isolinux.cfg" /isolinux/isolinux.cfg \
	-map iso/portitor.txt /isolinux/portitor.txt \
	-boot_image any replay >"$work/xorriso.log" 2>&1; then
	cat "$work/xorriso.log" >&2
	exit 1
fi
log "Done: $out ($(du -h "$out" | cut -f1))"
