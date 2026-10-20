// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package safelog

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Defaults for a RotatingFile.
const (
	DefaultMaxSize = 10 << 20
	DefaultBackups = 5
)

// RotatingFile is a log file that is renamed to path.1 when it reaches
// MaxSize, path.1 to path.2 and so on, keeping Backups old files, so the
// log uses at most about (Backups+1) × MaxSize of disk.
type RotatingFile struct {
	path    string
	maxSize int64
	backups int

	mu   sync.Mutex
	f    *os.File
	size int64
	// retryAt is when to try rotating again after it failed, for example
	// because another program holds an old file open on Windows.
	retryAt time.Time
}

// OpenRotating opens (or creates) the log file at path for appending.
// Zero maxSize or backups use the defaults.
func OpenRotating(path string, maxSize int64, backups int) (*RotatingFile, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	if backups <= 0 {
		backups = DefaultBackups
	}
	r := &RotatingFile{path: path, maxSize: maxSize, backups: backups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when p would take the file past its
// maximum size.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil && r.size > 0 && r.size+int64(len(p)) > r.maxSize && !time.Now().Before(r.retryAt) {
		r.rotate()
	}
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate moves the files along. If the current file cannot be renamed, it
// is emptied instead once it reaches twice its maximum size, so the log
// stays bounded even then. r.mu is held.
func (r *RotatingFile) rotate() {
	r.f.Close()
	r.f = nil
	os.Remove(fmt.Sprintf("%s.%d", r.path, r.backups))
	for i := r.backups - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	renameErr := os.Rename(r.path, r.path+".1")
	if err := r.open(); err != nil {
		// Keep going without a file rather than failing every write;
		// the next write tries to open it again.
		return
	}
	if renameErr == nil {
		return
	}
	r.retryAt = time.Now().Add(time.Minute)
	if r.size >= 2*r.maxSize {
		// The file is written again from the start rather than truncated
		// through the open handle: on Windows a handle opened to append
		// cannot truncate.
		r.f.Close()
		r.f = nil
		msg := fmt.Sprintf("%s log rotation failed (%v), so the earlier log was discarded\n", time.Now().Format(time.RFC3339), renameErr)
		_ = os.WriteFile(r.path, []byte(msg), 0o640)
		r.open()
	}
}

// Close closes the file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
