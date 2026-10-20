// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// anchors lists the anchors GitHub makes for the headings of a Markdown
// file: lower case, punctuation dropped, spaces as hyphens, and a number
// added to repeats.
func anchors(t *testing.T, file string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// Git may check the docs out with CRLF line ends on Windows.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	seen := map[string]int{}
	out := map[string]bool{}
	fence := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "```") {
			fence = !fence
			continue
		}
		if fence || !strings.HasPrefix(line, "#") {
			continue
		}
		title := strings.TrimSpace(strings.TrimLeft(line, "#"))
		out[anchorOf(title, seen)] = true
	}
	return out
}

func anchorOf(title string, seen map[string]int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(title) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	a := b.String()
	if n := seen[a]; n > 0 {
		seen[a] = n + 1
		return a + "-" + strconv.Itoa(n)
	}
	seen[a] = 1
	return a
}

func docFile(name string) string {
	if name == "README.md" {
		return filepath.Join("..", "..", name)
	}
	return filepath.Join("..", "..", "docs", name)
}

func TestDocLinksExist(t *testing.T) {
	cache := map[string]map[string]bool{}
	for _, d := range AllDocs() {
		if cache[d.File] == nil {
			cache[d.File] = anchors(t, docFile(d.File))
		}
		if !cache[d.File][d.Anchor] {
			t.Errorf("%s has no section #%s", d.File, d.Anchor)
		}
	}
}

// Every check has a section of its own in docs/security.md, under the
// check's title.
func TestEveryCheckHasADocsSection(t *testing.T) {
	have := anchors(t, docFile("security.md"))
	for id, title := range Titles() {
		if a := anchorOf(title, map[string]int{}); !have[a] {
			t.Errorf("docs/security.md has no section %q (#%s) for %s", title, a, id)
		}
	}
	for _, a := range []string{"what-the-states-mean", "not-checked-here", "the-signalith-security-command"} {
		if !have[a] {
			t.Errorf("docs/security.md has no #%s", a)
		}
	}
}

func TestDocsURL(t *testing.T) {
	if got := DocsURL("v1.2.3", "https.md", "x"); got != docsBase+"v1.2.3/docs/https.md#x" {
		t.Error(got)
	}
	if got := DocsURL("dev", "README.md", "linux"); got != docsBase+"main/README.md#linux" {
		t.Error(got)
	}
	if got := DocsURL("v1.2.3-rc1", "users.md", ""); got != docsBase+"main/docs/users.md" {
		t.Error(got)
	}
}
