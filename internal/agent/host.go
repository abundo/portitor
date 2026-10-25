// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"bytes"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/agentapi"
)

// diskFS are the filesystem types the dashboard shows the use of.
var diskFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"vfat": true, "f2fs": true, "zfs": true, "jfs": true, "reiserfs": true,
}

// hostStatus reads the host's memory, CPU times, load, uptime and disk
// use. What can't be read is left zero.
func hostStatus() *agentapi.HostStatus {
	h := &agentapi.HostStatus{CPUs: runtime.NumCPU(), Disks: []agentapi.DiskStatus{}}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		parseMeminfo(data, h)
	}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		h.CPUBusy, h.CPUTotal = parseCPUTimes(data)
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		h.Load = parseLoadavg(data)
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			up, _ := strconv.ParseFloat(f[0], 64)
			h.Uptime = int64(up)
		}
	}
	if data, err := os.ReadFile("/proc/self/mounts"); err == nil {
		for _, m := range diskMounts(data) {
			var fs unix.Statfs_t
			if unix.Statfs(m, &fs) != nil || fs.Blocks == 0 {
				continue
			}
			bs := uint64(fs.Bsize)
			h.Disks = append(h.Disks, agentapi.DiskStatus{Mount: m, Total: fs.Blocks * bs,
				Free: fs.Bavail * bs, Used: (fs.Blocks - fs.Bfree) * bs})
		}
	}
	return h
}

// parseMeminfo sets the memory fields from /proc/meminfo (kB).
func parseMeminfo(data []byte, h *agentapi.HostStatus) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		n *= 1024
		switch f[0] {
		case "MemTotal:":
			h.MemTotal = n
		case "MemAvailable:":
			h.MemAvailable = n
		case "SwapTotal:":
			h.SwapTotal = n
		case "SwapFree:":
			h.SwapFree = n
		}
	}
}

// parseCPUTimes sums the "cpu" line of /proc/stat: busy is every column
// but idle (4th) and iowait (5th); guest time is already in user and nice,
// so the guest columns are left out of both.
func parseCPUTimes(data []byte) (busy, total uint64) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		for i, v := range f[1:] {
			if i >= 8 {
				break
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return 0, 0
			}
			total += n
			if i != 3 && i != 4 {
				busy += n
			}
		}
		return busy, total
	}
	return 0, 0
}

func parseLoadavg(data []byte) (load [3]float64) {
	f := strings.Fields(string(data))
	for i := 0; i < 3 && i < len(f); i++ {
		load[i], _ = strconv.ParseFloat(f[i], 64)
	}
	return load
}

// diskMounts lists the mount points of block-device filesystems in
// /proc/self/mounts, one per device (btrfs subvolumes share theirs), in
// their order there.
func diskMounts(data []byte) []string {
	var mounts, devs []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !diskFS[f[2]] || !strings.HasPrefix(f[0], "/dev/") || slices.Contains(devs, f[0]) {
			continue
		}
		devs = append(devs, f[0])
		mounts = append(mounts, unescapeMount(f[1]))
	}
	return mounts
}

// unescapeMount undoes the octal escapes (\040 for a space) of a mount
// point in /proc/self/mounts.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
