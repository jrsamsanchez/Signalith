package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestDetectionsCatchUp: detections.catch_up is 0 (off) or a duration up
// to a week; empty means 6h.
func TestDetectionsCatchUp(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  time.Duration
		bad   bool
	}{
		{"", 6 * time.Hour, false},
		{"0", 0, false},
		{"6h", 6 * time.Hour, false},
		{"168h", 168 * time.Hour, false},
		{"7d", 168 * time.Hour, false},
		{"8d", 0, true},
		{"169h", 0, true},
		{"abc", 0, true},
		{"-1h", 0, true},
	} {
		c := validConfig(t)
		c.Detections.CatchUp = tc.value
		err := c.Validate()
		if tc.bad {
			want := fmt.Sprintf("detections.catch_up %q must be 0 (off) or a duration up to 168h (7d), for example 6h", tc.value)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%q: %v", tc.value, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q refused: %v", tc.value, err)
		}
		if got := c.DetectionsCatchUp(); got != tc.want {
			t.Errorf("%q is %v, want %v", tc.value, got, tc.want)
		}
	}
}
