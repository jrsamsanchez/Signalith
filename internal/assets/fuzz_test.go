// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"bytes"
	"encoding/csv"
	"reflect"
	"strings"
	"testing"
)

var csvSeeds = []string{
	assetCSV,
	identityCSV,
	"host,priority,ip\nweb1,urgent,\n,,\nweb2,high,10.0.0.300\n,low,\n",
	"hostname,owner\nx,y\n",
	"name\nBob\n",
	"identity,watchlist\nbob,maybe\n",
	"ip,owner\n10.1.1.1,x\n",
	"cidr\n10.0.0.0/8\n",
	"\ufeffhost,owner\r\nweb1,\"a, b\"\r\n",
	"identity,name,email,manager,priority,category,bunit,watchlist\n" +
		"mallory,\"=HYPERLINK(\"\"http://evil.example\"\")\",m@x.test,+1-555,low,,@IT,\n",
	"host,owner\nweb1,'=SUM(A1)\nweb2,''=x\n",
	"host,owner\nweb1,\"a\nb\"\n",
	"host , IP\n web1 | web2 , ::ffff:10.0.0.1 \n",
	"host\n\"unterminated\n",
	"",
}

// FuzzParseAssets: any file parses or is refused without a panic, and a
// list that parses comes back the same from its own download.
func FuzzParseAssets(f *testing.F) {
	for _, s := range csvSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		as, err := ParseAssets(b)
		if err != nil {
			return
		}
		out := MarshalAssets(as)
		again, err := ParseAssets(out)
		if err != nil {
			t.Fatalf("the download of %q does not parse: %v\n%s", b, err, out)
		}
		if !reflect.DeepEqual(as, again) {
			t.Fatalf("round trip of %q:\n got %#v\nwant %#v", b, again, as)
		}
		checkSafe(t, out)
	})
}

// FuzzParseIdentities is FuzzParseAssets for the identity list.
func FuzzParseIdentities(f *testing.F) {
	for _, s := range csvSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ids, err := ParseIdentities(b)
		if err != nil {
			return
		}
		out := MarshalIdentities(ids)
		again, err := ParseIdentities(out)
		if err != nil {
			t.Fatalf("the download of %q does not parse: %v\n%s", b, err, out)
		}
		if !reflect.DeepEqual(ids, again) {
			t.Fatalf("round trip of %q:\n got %#v\nwant %#v", b, again, ids)
		}
		checkSafe(t, out)
	})
}

// FuzzSafeCell: a safe cell never starts a formula, and reading it back
// gives the value unchanged.
func FuzzSafeCell(f *testing.F) {
	for _, s := range []string{"", "x", "=1+1", "+1-555", "-x", "@IT", "\tx", "\rx", "'=x", "''=x", "'", "'x", "10.0.0.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c := SafeCell(s)
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			t.Fatalf("SafeCell(%q) = %q starts a formula", s, c)
		}
		if got := unquoteCell(c); got != s {
			t.Fatalf("unquoteCell(SafeCell(%q)) = %q", s, got)
		}
	})
}

// checkSafe fails when a cell of a download would start a formula.
func checkSafe(t *testing.T, out []byte) {
	t.Helper()
	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		t.Fatalf("download is not CSV: %v\n%s", err, out)
	}
	for _, rec := range recs {
		for _, c := range rec {
			if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
				t.Fatalf("cell %q starts a formula:\n%s", c, out)
			}
		}
	}
}
