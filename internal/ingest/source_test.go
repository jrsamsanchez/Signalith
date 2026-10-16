package ingest

import (
	"context"
	"testing"
	"time"
)

// TestSource: every event says where it was read from, as Splunk's source
// field does: the file, the Windows event log, the journal, or how it
// arrived; a sender's own source is kept.
func TestSource(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	ctx := WithOrigin(context.Background(), Origin{Intake: IntakeAgent})
	for _, c := range []struct {
		tag  string
		rec  map[string]any
		want string
	}{
		{"linux.auth", map[string]any{"log": "Oct 11 12:00:00 web1 sshd[1]: Accepted password for amy from 10.0.0.1 port 22 ssh2", "file": "/var/log/auth.log"}, "/var/log/auth.log"},
		{"linux.auth", map[string]any{"log": "Oct 11 12:00:00 web1 sshd[1]: Accepted password for amy from 10.0.0.1 port 22 ssh2"}, "agent"},
		{"linux.journal", map[string]any{"MESSAGE": "hello", "_HOSTNAME": "web1"}, "journald"},
		{"win.events", map[string]any{"Channel": "Security", "EventID": 4625, "Computer": "dc1", "Message": "An account failed to log on."}, "WinEventLog:Security"},
		{"app.custom", map[string]any{"msg": "hi", "source": "billing-api"}, "billing-api"},
	} {
		fb.docs = nil
		if _, err := p.Ingest(ctx, c.tag, []map[string]any{c.rec}); err != nil {
			t.Fatal(err)
		}
		if got := fb.docs[0].Doc["source"]; got != c.want {
			t.Errorf("%s %v: source = %v, want %s", c.tag, c.rec, got, c.want)
		}
	}

	fb.docs = nil
	_, err := p.IngestEvents(context.Background(), []Event{{Fields: map[string]any{"msg": "a"}, Origin: Origin{Intake: IntakeSyslog}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := fb.docs[0].Doc["source"]; got != "syslog" {
		t.Errorf("syslog: source = %v", got)
	}
	if !KnownField("source") {
		t.Error("source is not mapped up front")
	}
}
