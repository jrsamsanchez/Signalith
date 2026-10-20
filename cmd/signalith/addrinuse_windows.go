// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"syscall"
)

// wsaeAddrInUse is WSAEADDRINUSE, Windows' "address already in use".
const wsaeAddrInUse = syscall.Errno(10048)

// addrInUse reports whether a listen error is that the address is in use.
func addrInUse(err error) bool {
	return errors.Is(err, wsaeAddrInUse) || errors.Is(err, syscall.EADDRINUSE)
}
