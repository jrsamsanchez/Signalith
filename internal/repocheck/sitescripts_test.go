// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// goatcounterSHA256 is the SHA-256 of public/count.js in GoatCounter
// v2.7.0 (zgo.at/goatcounter/v2, checked against the Go checksum
// database). The website and the docs serve this copy themselves, so a
// change on GoatCounter's host cannot run code on their pages. To update
// it, take count.js from a newer release the same way and change this
// hash and goatcounter-LICENSE.txt together.
const goatcounterSHA256 = "030ad75a7c80a04107a9b91f79e4b1572da0a583a80a9b67e111b310da11cbe9"

// goatcounterSRI is the same file's subresource integrity hash, which
// site/index.html and docs/overrides/main.html load it with.
const goatcounterSRI = "sha384-ibA+WLRCY3W4rrf/Qi6Z02iu3FWDJOW41oKXAKzGUka17bnDTswba03X3emshpZS"

// TestSiteScriptsAreSameOrigin checks that the website and the docs load
// no script from another host, and that the vendored GoatCounter script
// is the pinned one, with its licence notice beside it.
func TestSiteScriptsAreSameOrigin(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"site/assets/vendor", "docs/assets/vendor"} {
		data, err := os.ReadFile(filepath.Join(root, dir, "goatcounter-count.js"))
		if err != nil {
			t.Fatal(err)
		}
		// A checkout with CRLF line endings must still match.
		sum := sha256.Sum256([]byte(strings.ReplaceAll(string(data), "\r\n", "\n")))
		if got := hex.EncodeToString(sum[:]); got != goatcounterSHA256 {
			t.Errorf("%s/goatcounter-count.js is not the pinned GoatCounter script: sha256 %s, want %s", dir, got, goatcounterSHA256)
		}
		sri := sha512.Sum384([]byte(strings.ReplaceAll(string(data), "\r\n", "\n")))
		if got := "sha384-" + base64.StdEncoding.EncodeToString(sri[:]); got != goatcounterSRI {
			t.Errorf("%s/goatcounter-count.js: integrity %s, want %s", dir, got, goatcounterSRI)
		}
		notice, err := os.ReadFile(filepath.Join(root, dir, "goatcounter-LICENSE.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(notice), goatcounterSHA256) || !strings.Contains(string(notice), "Permission to use, copy, modify") {
			t.Errorf("%s/goatcounter-LICENSE.txt does not name the pinned hash or lacks the ISC notice", dir)
		}
	}
	src := regexp.MustCompile(`(?i)<script[^>]*\ssrc="([^"]*)"[^>]*>`)
	integrity := regexp.MustCompile(`\sintegrity="([^"]*)"`)
	for _, page := range []string{"site/index.html", "docs/overrides/main.html"} {
		data, err := os.ReadFile(filepath.Join(root, page))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range src.FindAllStringSubmatch(string(data), -1) {
			if strings.Contains(m[1], "//") {
				t.Errorf("%s loads a script from another host: %s", page, m[1])
			}
			if strings.Contains(m[1], "assets/vendor/goatcounter-count.js") {
				found = true
				// WEB-09: with the pinned script's own hash, so the
				// browser runs nothing else.
				if i := integrity.FindStringSubmatch(m[0]); i == nil || i[1] != goatcounterSRI {
					t.Errorf("%s loads the GoatCounter script without integrity=%q: %s", page, goatcounterSRI, m[0])
				}
			}
		}
		if !found {
			t.Errorf("%s does not load assets/vendor/goatcounter-count.js", page)
		}
	}
}
