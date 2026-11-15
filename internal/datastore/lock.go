// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"os"
	"path/filepath"
	"syscall"
)

// LockDir takes the named lock of the files kept in dir across processes (a
// lock is not re-entrant, not even in one process: the file is opened again) (the
// daemon and the console commands run beside it), waiting for it. unlock
// gives it back. Writes that read first (the ids, the counters) hold it from
// the read to the write.
func LockDir(dir, name string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// FileStamp tells whether a file has changed since: its size and time. A
// missing file has the zero stamp.
type FileStamp struct {
	Size int64
	Time int64
}

// StampOf is the file's stamp.
func StampOf(path string) FileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return FileStamp{}
	}
	return FileStamp{Size: fi.Size(), Time: fi.ModTime().UnixNano()}
}
