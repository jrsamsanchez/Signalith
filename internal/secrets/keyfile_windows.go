// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secrets

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultName is the key file Signalith makes in its keys folder: the key
// protected with DPAPI for this computer (CRYPTPROTECT_LOCAL_MACHINE), so
// the service and an administrator running the CLI can both open it, while
// a copy is useless on another computer. The folder's access list allows
// only SYSTEM, Administrators and the service account.
const defaultName = "master.key.dpapi"

// defaultNote is added when describing the default key file.
const defaultNote = " (protected with Windows DPAPI for this computer)"

// dpapiEntropy is mixed into the protection, so other programs using
// DPAPI on this computer cannot open the key by accident.
var dpapiEntropy = []byte("Signalith master key v1")

func readDefault(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := dpapiUnprotect(blob)
	if err != nil {
		return nil, err
	}
	if len(raw) != keySize {
		clear(raw)
		return nil, errBadKey
	}
	return raw, nil
}

func encodeDefault(raw []byte) ([]byte, error) { return dpapiProtect(raw) }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// dpapiProtect encrypts data for this computer.
func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("nothing to protect")
	}
	name, err := windows.UTF16PtrFromString("Signalith master key")
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	err = windows.CryptProtectData(blob(data), name, blob(dpapiEntropy), 0, nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// dpapiUnprotect decrypts what dpapiProtect made on this computer.
func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("the file is empty")
	}
	var out windows.DataBlob
	err := windows.CryptUnprotectData(blob(data), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	plain := unsafe.Slice(out.Data, out.Size)
	raw := append([]byte(nil), plain...)
	clear(plain)
	return raw, nil
}
