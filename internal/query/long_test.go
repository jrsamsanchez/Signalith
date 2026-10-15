package query

import (
	"strings"
	"testing"
)

func TestLongExpressions(t *testing.T) {
	// A long chain parses, and prints back the same.
	src := "* | where " + strings.Repeat("len(a) > 1 OR ", 999) + "len(a) > 1"
	q, err := Parse(src)
	if err != nil {
		t.Fatalf("1,000 conditions: %v", err)
	}
	if got := q.String(); got != "*\n"+src[2:] {
		t.Errorf("printed back differently: %.80q", got)
	}
	// Past the limit, parsing stops with an error instead of building
	// (and printing) a huge expression.
	src = "* | where " + strings.Repeat("len(a) > 1 OR ", 60000) + "len(a) > 1"
	if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("60,000 conditions: err = %v, want too long", err)
	}
	if _, err := Parse("* | eval x=" + strings.Repeat("a+", maxEvalNodes) + "a"); err == nil {
		t.Error("an eval past the node limit should fail")
	}
}
