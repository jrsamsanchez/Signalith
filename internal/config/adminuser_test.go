package config

import "testing"

func TestKeptLegacyAdmin(t *testing.T) {
	for _, c := range []struct {
		builtin, configured string
		want                bool
	}{
		{"admin", "signalithadmin", true},
		{"Admin", "SignalithAdmin", true},
		{"signalithadmin", "signalithadmin", false},
		{"admin", "admin", false},
		{"root", "signalithadmin", false},
		{"admin", "root", false},
		{"", "signalithadmin", false},
	} {
		if got := KeptLegacyAdmin(c.builtin, c.configured); got != c.want {
			t.Errorf("KeptLegacyAdmin(%q, %q) = %v, want %v", c.builtin, c.configured, got, c.want)
		}
	}
}
