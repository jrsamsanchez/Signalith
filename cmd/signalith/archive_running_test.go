package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signalith archive restore on a cluster whose servers share their
// archives asks the server that runs retention, and reports what it
// answers; -offline is refused while that server runs.
func TestArchiveRestoreThroughTheServerThatRunsRetention(t *testing.T) {
	serveEnv(t)
	fos := newFakeOpenSearch(t)
	path, addr := serveConfig(t, fos, "")
	logs := &syncBuffer{}
	runServe(t, path, addr, logs)

	if _, err := capture(t, func() error { return cmdArchive([]string{"restore", "-c", path, "-keep-days", "0", "x"}) }); err == nil || !strings.Contains(err.Error(), "-keep-days must be between 1 and") {
		t.Errorf("-keep-days 0: %v", err)
	}
	// The archives are shared once the audit records are: sign in until
	// they show up in OpenSearch.
	eventually(t, "the server shares its audit records and archives", func() bool {
		resp, err := http.Post("http://"+addr+"/api/login", "application/json", strings.NewReader(`{"username":"admin","password":"s3cret-pass"}`))
		if err == nil {
			resp.Body.Close()
		}
		for _, n := range fos.Indices() {
			if strings.HasPrefix(n, "signalith_audit-") {
				return true
			}
		}
		return false
	})
	c, err := loadConfig(path, newLogger(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var ac *archiveCluster
	eventually(t, "siem-serve runs retention", func() bool {
		ac, err = openArchiveCluster(ctx, c, newStore(c), io.Discard)
		return err == nil && ac != nil && ac.leader == "siem-serve"
	})

	if _, err := capture(t, func() error { return cmdArchive([]string{"restore", "-c", path}) }); err == nil || !strings.Contains(err.Error(), "name at least one archive ID") {
		t.Errorf("no ID: %v", err)
	}
	if _, err := capture(t, func() error {
		return cmdArchive([]string{"restore", "-c", path, filepath.Join("some", "day.ndjson.gz")})
	}); err == nil || !strings.Contains(err.Error(), "name archives by ID") {
		t.Errorf("a file: %v", err)
	}
	if _, err := capture(t, func() error { return cmdArchive([]string{"restore", "-c", path, "-offline", "no-such-archive"}) }); err == nil || !strings.Contains(err.Error(), "siem-serve runs retention now, so restore through it") {
		t.Errorf("-offline while a server runs retention: %v", err)
	}
	// An ID the archive does not have: the server that runs retention
	// says so.
	var out bytes.Buffer
	err = ac.restore(ctx, []string{"no-such-archive"}, 3, false, &out)
	if err == nil || ctx.Err() != nil || !strings.Contains(out.String(), "Asked siem-serve to restore 1 archived day(s)") {
		t.Errorf("restore of an unknown ID: %v\n%s", err, out.String())
	}
	if orSomeServer("") == "" || orSomeServer("siem-a") != "siem-a" {
		t.Error("orSomeServer")
	}
}
