package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPClientSettings(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr, user, pass, ca string
		want                 string // part of the error, or the address when it works
	}{
		{"", "u", "p", "", "set the Signalith server's address"},
		{"siem.example.com:8080", "u", "p", "", "https://siem.example.com:8080"},
		{"https://siem.example.com/signalith/", "u", "p", "", "https://siem.example.com/signalith"},
		{"http://siem.example.com:8080", "u", "p", "", "plain http"},
		{"http://127.0.0.1:8080", "u", "p", "", "http://127.0.0.1:8080"},
		{"http://localhost:8080", "u", "p", "", "http://localhost:8080"},
		{"https://u:p@siem.example.com", "u", "p", "", "not in the address"},
		{"ftp://siem.example.com", "u", "p", "", "not a web address"},
		{"https://siem.example.com", "", "p", "", "set the Signalith user"},
		{"https://siem.example.com", "u", "", "", "set the Signalith user"},
		{"https://siem.example.com", "u", "p", bad, "holds no PEM certificate"},
	} {
		c, err := newMCPClient(tc.addr, tc.user, tc.pass, tc.ca)
		got := ""
		if err != nil {
			got = err.Error()
		} else {
			got = c.BaseURL.String()
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.addr, got, tc.want)
		}
	}
}
