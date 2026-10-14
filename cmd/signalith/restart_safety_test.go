package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// waitFor polls until ok, or fails with what.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A change a restart refused is set aside in the settings file, so the
// next start does not use it either.
func TestRefusedChangeIsSetAside(t *testing.T) {
	rs := startRunner(t, nil, nil)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	rs.save(`{"server.listen":"` + taken.Addr().String() + `","search.max_events":55}`)
	_, res := rs.restart()
	if res.OK || strings.Join(res.ProblemKeys, ",") != "server.listen" || strings.Join(res.Refused, ",") != "server.listen" {
		t.Fatalf("restart %+v", res)
	}
	c, err := config.Load(rs.r.path)
	if err != nil || c.Server.Listen != rs.addr || c.Search.MaxEvents != 55 {
		t.Fatalf("the next start would use %s, %d (%v)", c.Server.Listen, c.Search.MaxEvents, err)
	}
	_, view, _ := rs.call("", "GET", "/api/settings", "")
	if r := view["refused"].([]any); len(r) != 1 || !strings.Contains(r[0].(map[string]any)["reason"].(string), "cannot listen on") {
		t.Errorf("refused %v", r)
	}
	// Changing it again replaces what was set aside.
	next := freeAddr(t)
	rs.save(`{"server.listen":"` + next + `"}`)
	if c, _ := config.Load(rs.r.path); c.Server.Listen != next {
		t.Errorf("after a new change: %s", c.Server.Listen)
	}
}

// Damaged files the components read do not stop Signalith: a restart
// refuses before anything stops, and a damaged asset list is not fatal.
func TestRestartWithDamagedFiles(t *testing.T) {
	rs := startRunner(t, nil, nil)
	dir := filepath.Dir(rs.r.path)
	os.WriteFile(filepath.Join(dir, "lookups", "assets.csv"), []byte("host,priority\nweb01,urgent\n"), 0o600)
	rs.save(`{"syslog.public_port":5514}`)
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart with a damaged asset list %+v\n%s", res, rs.logs.String())
	}
	if !rs.signedIn("") {
		t.Fatal("the server stopped answering")
	}
	// Directory sign-in settings that cannot be read refuse the restart.
	os.WriteFile(filepath.Join(dir, "lookups", "directory.json"), []byte("{not json"), 0o600)
	before := rs.starts()
	rs.save(`{"syslog.public_port":5515}`)
	_, res := rs.restart()
	if res.OK || res.RolledBack || !strings.Contains(res.Error, "kept running with the previous settings") || len(res.Refused) != 0 {
		t.Fatalf("restart with a damaged directory.json %+v", res)
	}
	if rs.starts() != before || !rs.signedIn("") {
		t.Errorf("components replaced (%s -> %s) or the server stopped", before, rs.starts())
	}
}

// When neither the new settings nor the previous ones start, the web page
// stays up to say so, and Signalith keeps trying.
func TestNothingStartsThenRecovers(t *testing.T) {
	var broken atomic.Bool
	downRetry = 200 * time.Millisecond
	t.Cleanup(func() { downRetry = 30 * time.Second })
	rs := startRunner(t, func(*config.Config) error {
		if broken.Load() {
			return errors.New("the disk is full")
		}
		return nil
	}, nil)
	rs.save(`{"opensearch.index_prefix":"siem2"}`)
	broken.Store(true)
	_, res := rs.restart()
	if res.OK || !strings.Contains(res.Error, "tries again every 30 seconds") {
		t.Fatalf("restart %+v", res)
	}
	code, out, err := rs.call("", "GET", "/api/health", "")
	if err != nil || code != 503 || out["code"] != "down" || strings.Contains(out["error"].(string), "disk") {
		t.Errorf("while down: %d %v %v", code, out, err)
	}
	broken.Store(false)
	waitFor(t, "Signalith to start again", func() bool { return rs.signedIn("") })
	if st := rs.r.RestartStatus(); st.Last == nil || !st.Last.OK {
		t.Errorf("after recovering %+v", st.Last)
	}
}

// A move of the web page that nobody confirms at the new address goes
// back to the old one, which kept answering, and is set aside.
func TestUnconfirmedMoveGoesBack(t *testing.T) {
	moveWait = 600 * time.Millisecond
	t.Cleanup(func() { moveWait = api.MoveWait })
	rs := startRunner(t, nil, nil)
	old, next := rs.addr, freeAddr(t)
	rs.save(`{"server.listen":"` + next + `"}`)
	out, res := rs.restart()
	if !res.OK || out["confirm_within_s"] == nil {
		t.Fatalf("restart %+v %v", res, out)
	}
	st := rs.r.RestartStatus()
	if st.Awaiting == nil || st.Awaiting.To != "http://"+next {
		t.Fatalf("awaiting %+v", st.Awaiting)
	}
	// Another restart waits for the move.
	if code, out, _ := rs.call(old, "POST", "/api/settings/restart", "{}"); code != 409 || out["code"] != "awaiting" {
		t.Errorf("restart while awaiting %d %v", code, out)
	}
	// The old address still answers, and does not confirm.
	if !rs.signedIn(old) {
		t.Fatal("the old address stopped answering before the move was confirmed")
	}
	waitFor(t, "the move to be undone", func() bool {
		st := rs.r.RestartStatus()
		return st.Last != nil && st.Last.Reverted && !st.InProgress
	})
	last := rs.r.RestartStatus().Last
	if !last.OK || strings.Join(last.Refused, ",") != "server.listen" || !strings.Contains(last.Error, "Nobody opened Signalith at http://"+next) {
		t.Errorf("reverted %+v", last)
	}
	if !rs.signedIn(old) {
		t.Error("the old address does not answer after going back")
	}
	if c, _ := config.Load(rs.r.path); c.Server.Listen != old {
		t.Errorf("the next start would listen on %s", c.Server.Listen)
	}
	waitFor(t, "the new address to close", func() bool { _, _, err := rs.call(next, "GET", "/api/me", ""); return err != nil })
}

// A move confirmed at the new address stays, and moving back to the old
// port soon after reuses the old listener instead of failing on it.
func TestConfirmedMoveAndBackAgain(t *testing.T) {
	moveWait = 5 * time.Second
	t.Cleanup(func() { moveWait = api.MoveWait })
	rs := startRunner(t, nil, nil)
	oldAddressGrace = 10 * time.Second
	old, next := rs.addr, freeAddr(t)
	rs.save(`{"server.listen":"` + next + `"}`)
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v", res)
	}
	if !rs.signedIn(next) {
		t.Fatal("the new address does not answer")
	}
	if st := rs.r.RestartStatus(); st.Awaiting != nil || !st.Last.Confirmed {
		t.Fatalf("not confirmed: %+v %+v", st.Awaiting, st.Last)
	}
	// Back to the old port while the old listener still answers.
	if code, out, err := rs.call(next, "PUT", "/api/settings", `{"values":{"server.listen":"`+old+`"}}`); code != 200 {
		t.Fatalf("save %d %v %v", code, out, err)
	}
	code, out, _ := rs.call(next, "POST", "/api/settings/restart", "{}")
	if code != 202 {
		t.Fatalf("restart %d %v", code, out)
	}
	res := rs.wait()
	waitFor(t, "the second restart", func() bool { st := rs.r.RestartStatus(); return !st.InProgress && st.Last.At != res.At })
	if last := rs.r.RestartStatus().Last; !last.OK {
		t.Fatalf("moving back: %+v\n%s", last, rs.logs.String())
	}
	if !rs.signedIn(old) {
		t.Error("the old address does not answer")
	}
}

// A same-port address that is not on this computer is refused before
// anything stops; only "address in use" means the old listener holds it.
func TestSamePortOnAnotherAddressIsRefused(t *testing.T) {
	rs := startRunner(t, nil, nil)
	_, port, _ := net.SplitHostPort(rs.addr)
	rs.save(`{"server.listen":"192.0.2.1:` + port + `"}`)
	_, res := rs.restart()
	if res.OK || res.RolledBack || !strings.Contains(res.Error, "cannot listen on 192.0.2.1:"+port) {
		t.Fatalf("restart %+v", res)
	}
	if rs.starts() != "signalith" || !rs.signedIn("") {
		t.Errorf("components replaced or the server stopped: %s", rs.starts())
	}
}

// A syslog address on a port Signalith holds with the other protocol is
// still tried before anything stops: another program may hold it with
// this one.
func TestSyslogPortHeldWithTheOtherProtocol(t *testing.T) {
	rs := startRunner(t, nil, nil)
	// A port free for UDP, for syslog.udp. Another program (on Windows,
	// often the system itself) can take a port between the check and the
	// restart, so a refused port is tried again with another one.
	var addr string
	for try := 0; ; try++ {
		for range 20 {
			addr = freeAddr(t)
			if pc, err := net.ListenPacket("udp", addr); err == nil {
				pc.Close()
				break
			}
		}
		rs.save(`{"syslog.udp":"` + addr + `"}`)
		_, res := rs.restart()
		if res.OK {
			break
		}
		if try == 4 || !slices.Contains(res.Refused, "syslog.udp") {
			t.Fatalf("syslog.udp %+v\n%s", res, rs.logs.String())
		}
	}
	// Another program takes the same port over TCP.
	held, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("the port was taken meanwhile: %v", err)
	}
	defer held.Close()
	before := rs.starts()
	rs.save(`{"syslog.tls":"` + addr + `"}`)
	_, res := rs.restart()
	if res.OK || res.RolledBack || !strings.Contains(res.Error, "cannot receive syslog on "+addr+"/tcp") ||
		strings.Join(res.Refused, ",") != "syslog.tls" {
		t.Fatalf("restart %+v", res)
	}
	if rs.starts() != before || !rs.signedIn("") {
		t.Errorf("components replaced (%s -> %s) or the server stopped", before, rs.starts())
	}
}

// At startup, an OpenSearch connection saved on the page and never
// checked is set aside when OpenSearch answers with signalith.yaml's
// settings but not with it.
func TestStartupChecksPageOpenSearch(t *testing.T) {
	bootCheckTimeout = time.Second
	t.Cleanup(func() { bootCheckTimeout = 10 * time.Second })
	dead := "http://" + freeAddr(t)
	rs := startRunner(t, nil, map[string]any{"opensearch.url": dead})
	_, view, _ := rs.call("", "GET", "/api/settings", "")
	f := settingsField(t, view, "opensearch.url")
	if f["value"] == dead || f["refused"] == nil {
		t.Errorf("opensearch.url %v", f)
	}
	if !strings.Contains(rs.logs.String(), "did not answer with the settings saved on the Settings page") {
		t.Errorf("log:\n%s", rs.logs.String())
	}
}

// settingsField finds a setting in GET /api/settings.
func settingsField(t *testing.T, view map[string]any, key string) map[string]any {
	t.Helper()
	for _, sec := range view["sections"].([]any) {
		for _, f := range sec.(map[string]any)["fields"].([]any) {
			if fm := f.(map[string]any); fm["key"] == key {
				return fm
			}
		}
	}
	t.Fatalf("no field %s", key)
	return nil
}

func TestOverlaps(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.0.0.0:8080", "127.0.0.1:8080", true},
		{"127.0.0.1:8080", "0.0.0.0:8080", true},
		{"127.0.0.1:8080", "localhost:8080", true},
		{"127.0.0.1:8080", "192.0.2.1:8080", false},
		{"0.0.0.0:8080", "0.0.0.0:8081", false},
		{":8080", "10.0.0.1:8080", true},
	} {
		if got := overlaps(c.a, c.b); got != c.want {
			t.Errorf("overlaps(%s, %s) = %v", c.a, c.b, got)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = net.Listen("tcp", ln.Addr().String())
	if !addrInUse(err) {
		t.Errorf("not seen as in use: %v", err)
	}
}
