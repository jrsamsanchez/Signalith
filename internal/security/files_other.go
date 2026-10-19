// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package security

import "errors"

// Account is the account Signalith runs as, whose files are its own.
type Account struct {
	UID, GID int
	SID      string
}

func probePerm(string, Account) (*Perm, error) { return nil, errors.New("not supported here") }

// CurrentAccount is the account this process runs as, unknown here.
func CurrentAccount() Account { return Account{UID: -1, GID: -1} }

func isService() bool { return false }

func ownerOf(string) (Account, bool) { return Account{}, false }
