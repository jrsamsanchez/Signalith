package cluster

import "testing"

func TestNewerVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b           string
		levelA, levelB int
		want           bool
	}{
		{"0.2.0", "0.1.0", 0, 0, true},
		{"0.1.0", "0.2.0", 0, 0, false},
		{"0.1.0-next+abc1234", "0.1.0", 0, 0, true},
		{"0.2.0-next+abc", "0.2.0", 0, 0, true},
		{"0.2.0", "0.2.0-next+abc", 0, 0, false},
		{"0.10.0", "0.9.1", 0, 0, true},
		{"1.10.0", "1.9.0", 0, 0, true},
		{"v1.6.0", "1.5.0", 0, 0, true},
		{"1.6.0", "1.6.0", 0, 0, false},
		{"dev", "0.1.0", 0, 0, false},
		{"dev", "dev", 0, 0, false},
		{"garbage", "0.1.0", 0, 0, false},
		{"garbage", "other", 0, 0, false},
		{"", "0.1.0", 0, 0, false},
		// Commit hashes, as CI builds name their version, are not read.
		{"9a8b7c6", "1.6.0", 0, 0, false},
		{"9a8b7c6", "1a2b3c4", 0, 0, false},
		{"1a2b3c4", "9a8b7c6", 0, 0, false},
		{"1234567", "1.6.0", 0, 0, false},
		{"1.6.0", "9a8b7c6", 0, 0, true},
		{"1.6.0x", "1.5.0", 0, 0, false},
		// A version that reads higher levels is newer, whatever its number.
		{"dev", "0.1.0", 3, 0, true},
		{"0.9.0", "0.1.0", 2, 3, false},
	} {
		if got := NewerVersion(tc.a, tc.b, tc.levelA, tc.levelB); got != tc.want {
			t.Errorf("NewerVersion(%q, %q, %d, %d) = %v", tc.a, tc.b, tc.levelA, tc.levelB, got)
		}
	}
}
