// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package oslocal

import (
	"net/url"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var osStat = os.Stat

// diskSpace returns the bytes free to this user and the disk's size.
func diskSpace(dir string) (free, total int64, err error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	var f, t, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &f, &t, &totalFree); err != nil {
		return 0, 0, err
	}
	return int64(f), int64(t), nil
}

// winHTTPProxyInfo is WINHTTP_PROXY_INFO.
type winHTTPProxyInfo struct {
	accessType  uint32
	proxy       *uint16
	proxyBypass *uint16
}

const winHTTPAccessTypeNamedProxy = 3

// systemProxy is the machine-wide WinHTTP proxy (netsh winhttp set proxy),
// or nil when there is none.
func systemProxy() *url.URL {
	proc := windows.NewLazySystemDLL("winhttp.dll").NewProc("WinHttpGetDefaultProxyConfiguration")
	if proc.Find() != nil {
		return nil
	}
	var info winHTTPProxyInfo
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return nil
	}
	// The strings are the caller's to free.
	globalFree := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
	defer func() {
		for _, p := range []*uint16{info.proxy, info.proxyBypass} {
			if p != nil {
				globalFree.Call(uintptr(unsafe.Pointer(p)))
			}
		}
	}()
	if info.accessType != winHTTPAccessTypeNamedProxy || info.proxy == nil {
		return nil
	}
	return winHTTPProxy(windows.UTF16PtrToString(info.proxy))
}
