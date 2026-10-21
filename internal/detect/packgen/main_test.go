// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// TestUnreadFolders checks that the rules read and the folders not read
// cover a checkout's whole tree: every .yml file under a rules* folder,
// at any depth, is read or counted under its folder, and nothing else is
// counted.
func TestUnreadFolders(t *testing.T) {
	root := t.TempDir()
	files := []string{
		"rules/windows/process_creation/a.yml",
		"rules/windows/process_creation/b.yml",
		"rules/windows/builtin/security/account_management/c.yml",
		"rules/linux/builtin/d.yml",
		"rules/linux/builtin/sshd/e.yml",
		"rules-emerging-threats/2024/Exploits/CVE-1/f.yml",
		"rules-threat-hunting/windows/g.yml",
		"rules/windows/process_creation/notes.txt",
		"tests/h.yml",
		"deprecated/i.yml",
	}
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("title: x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := map[string]bool{
		"rules/windows/process_creation/a.yml":                    true,
		"rules/windows/process_creation/b.yml":                    true,
		"rules/windows/builtin/security/account_management/c.yml": true,
	}
	unread, total, err := unreadFolders(root, read)
	if err != nil {
		t.Fatal(err)
	}
	if total != 7 {
		t.Errorf("%d rules in the tree, want 7", total)
	}
	want := map[string]int{
		"rules/linux/builtin":                        1,
		"rules/linux/builtin/sshd":                   1,
		"rules-emerging-threats/2024/Exploits/CVE-1": 1,
		"rules-threat-hunting/windows":               1,
	}
	u := 0
	for d, n := range unread {
		u += n
		if want[d] != n {
			t.Errorf("%s: %d rules not read, want %d", d, n, want[d])
		}
	}
	if len(unread) != len(want) || len(read)+u != total {
		t.Errorf("read %d and not read %d (%v) do not cover the %d rules", len(read), u, unread, total)
	}
	if unreadNote("rules/linux/builtin/sshd") == "" || unreadNote("rules/linux/builtinx") != "" {
		t.Error("folder notes do not follow the folders in a noted folder")
	}
}

// TestReportAddsUp checks the SigmaHQ pack's REPORT.md: its shipped
// count is the manifest's, and the rules left out (by reason) and the
// rules of the folders not read (by folder) add up, with the shipped
// ones, to the rules of the checkout it was made from.
func TestReportAddsUp(t *testing.T) {
	dir := filepath.Join("..", "packs", "sigmahq")
	data, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var p detect.Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	summary := regexp.MustCompile(`^The checkout has (\d+) rules .*: (\d+) shipped, (\d+) left out .*, and (\d+) in (\d+) folders`)
	row := regexp.MustCompile(`^\| (\d+) \| `)
	var nums []int
	section := ""
	reasons, listed, unread, folders := 0, 0, 0, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := summary.FindStringSubmatch(line); m != nil {
			for _, s := range m[1:] {
				n, _ := strconv.Atoi(s)
				nums = append(nums, n)
			}
			continue
		}
		if strings.HasPrefix(line, "## ") {
			section = line
			continue
		}
		m := row.FindStringSubmatch(line)
		switch {
		case section == "" && m != nil:
			n, _ := strconv.Atoi(m[1])
			reasons += n
		case section == unreadHeading && m != nil:
			n, _ := strconv.Atoi(m[1])
			unread += n
			folders++
		case section != "" && section != unreadHeading && !strings.HasPrefix(section, "## Shipped") && strings.HasPrefix(line, "- "):
			listed++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(nums) != 5 {
		t.Fatalf("REPORT.md has no summary line")
	}
	total, shipped, left, notRead, nFolders := nums[0], nums[1], nums[2], nums[3], nums[4]
	if shipped != len(p.Rules) {
		t.Errorf("report says %d shipped, the manifest has %d", shipped, len(p.Rules))
	}
	if reasons != left || listed != left {
		t.Errorf("report says %d left out; its reasons count %d and list %d", left, reasons, listed)
	}
	if unread != notRead || folders != nFolders {
		t.Errorf("report says %d rules in %d folders not read; its table has %d in %d", notRead, nFolders, unread, folders)
	}
	if shipped+left+notRead != total {
		t.Errorf("%d shipped, %d left out and %d not read do not add up to the checkout's %d", shipped, left, notRead, total)
	}
}
