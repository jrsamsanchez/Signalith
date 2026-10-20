// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jrsamsanchez/signalith/internal/casereport"
)

const reportUsage = `Usage:
  signalith report verify file

verify checks a case report exported from a case's page, the .json or the
.html file: that its SHA-256 matches, that each piece of evidence matches
the SHA-256 taken when it was pinned, and, for the page, that nothing on it
was edited. It needs no server.

It exits 0 when the report is unchanged, 2 when it was changed, and 1 when
the file cannot be read.`

// errReportChanged is verify finding a changed report; main exits 2.
var errReportChanged = errors.New("the report was changed")

func cmdReport(args []string) error {
	if len(args) != 2 || args[0] != "verify" {
		return errors.New(reportUsage)
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	r, err := casereport.Verify(data)
	if err != nil {
		if r == nil {
			return err
		}
		fmt.Println("CHANGED:", err)
		return errReportChanged
	}
	fmt.Printf("Unchanged: case %s, made %s by %s\nSHA-256 %s\n", r.Case.ID, r.Generated.Format("2006-01-02 15:04 UTC"), r.GeneratedBy, r.SHA256)
	return nil
}
