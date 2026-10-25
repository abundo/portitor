// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
)

func TestParseMeminfo(t *testing.T) {
	var h agentapi.HostStatus
	parseMeminfo([]byte("MemTotal:        4028392 kB\nMemFree:          212000 kB\nMemAvailable:    2014196 kB\nSwapTotal:        999420 kB\nSwapFree:         999000 kB\n"), &h)
	if h.MemTotal != 4028392*1024 || h.MemAvailable != 2014196*1024 || h.SwapTotal != 999420*1024 || h.SwapFree != 999000*1024 {
		t.Fatalf("got %+v", h)
	}
}

func TestParseCPUTimes(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	busy, total := parseCPUTimes([]byte("cpu  100 5 50 800 20 3 2 1 40 0\ncpu0 1 2 3 4 5 6 7 8 9 10\nbtime 1700000000\n"))
	if busy != 161 || total != 981 {
		t.Fatalf("busy %d total %d", busy, total)
	}
	if b, tt := parseCPUTimes([]byte("intr 1 2\n")); b != 0 || tt != 0 {
		t.Fatalf("no cpu line: %d %d", b, tt)
	}
}

func TestParseLoadavg(t *testing.T) {
	if l := parseLoadavg([]byte("0.52 0.31 0.20 2/312 12345\n")); l != [3]float64{0.52, 0.31, 0.20} {
		t.Fatalf("got %v", l)
	}
}

func TestDiskMounts(t *testing.T) {
	mounts := `sysfs /sys sysfs rw 0 0
/dev/sda2 / ext4 rw,relatime 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 /boot/efi vfat rw 0 0
/dev/sdb1 /srv/my\040data xfs rw 0 0
/dev/sda2 /var/lib/portitor ext4 rw 0 0
/dev/mapper/vg-var /var btrfs rw 0 0
/dev/mapper/vg-var /var/log btrfs rw,subvol=log 0 0
`
	got := diskMounts([]byte(mounts))
	want := []string{"/", "/boot/efi", "/srv/my data", "/var"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
