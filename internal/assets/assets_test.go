package assets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const assetCSV = `host,ip,cidr,owner,priority,category,bunit,location
DC01.corp.local,10.0.0.10,,it-ops,critical,domain_controller|pci,IT,HQ
web1,203.0.113.50,,web-team,high,web,Sales,AWS
,,10.20.0.0/16,,low,workstation,Corp,
,,10.20.5.0/24,finance,medium,workstation|finance,Finance,
`

const identityCSV = `identity,name,email,manager,priority,category,bunit,watchlist
bob|CORP\bob|bob.smith@corp.com,Bob Smith,bob.smith@corp.com,alice,high,admin,IT,true
svc_backup,Backup service,,it-ops,critical,service,IT,
`

func TestLookups(t *testing.T) {
	s, _ := NewStore("")
	if _, err := s.SetAssets([]byte(assetCSV)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetIdentities([]byte(identityCSV)); err != nil {
		t.Fatal(err)
	}
	for v, owner := range map[string]string{
		"DC01": "it-ops", "dc01.corp.local": "it-ops", "10.0.0.10": "it-ops", "WEB1.example.com": "web-team",
		"10.20.5.7": "finance", "10.20.9.1": "", "::ffff:10.0.0.10": "it-ops",
	} {
		a, ok := s.Asset(v)
		if !ok {
			t.Errorf("%s: no asset", v)
			continue
		}
		if a.Owner != owner {
			t.Errorf("%s: owner %q, want %q", v, a.Owner, owner)
		}
	}
	if _, ok := s.Asset("192.0.2.1"); ok {
		t.Error("unknown IP matched")
	}
	for _, u := range []string{"bob", "BOB", `CORP\bob`, "bob@corp.com", "bob.smith@corp.com"} {
		id, ok := s.Identity(u)
		if !ok || id.Name != "Bob Smith" || !id.Watchlist {
			t.Errorf("%s: %+v %v", u, id, ok)
		}
	}
	c, ok := s.Lookup("user", "svc_backup")
	if !ok || c.Kind != "identity" || c.Priority != "critical" {
		t.Errorf("user lookup = %+v", c)
	}
	c, ok = s.Lookup("dest", "DC01")
	if !ok || c.Kind != "asset" || len(c.Category) != 2 {
		t.Errorf("dest lookup = %+v", c)
	}
	if Multiplier("critical") != 2 || Multiplier("") != 1 || Multiplier("low") != 0.5 {
		t.Error("multipliers")
	}
}

func TestParseErrors(t *testing.T) {
	_, err := ParseAssets([]byte("host,priority,ip\nweb1,urgent,\n,,\nweb2,high,10.0.0.300\n,low,\n"))
	pe, ok := err.(*ParseError)
	if !ok || len(pe.Lines) != 3 || pe.Lines[0].Line != 2 || pe.Lines[2].Line != 5 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(pe.Lines[1].Msg, "10.0.0.300") {
		t.Errorf("msg = %s", pe.Lines[1].Msg)
	}
	if _, err := ParseAssets([]byte("hostname,owner\nx,y\n")); err == nil || !strings.Contains(err.Error(), "unknown column") {
		t.Errorf("unknown column: %v", err)
	}
	if _, err := ParseIdentities([]byte("name\nBob\n")); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("missing identity: %v", err)
	}
	if _, err := ParseIdentities([]byte("identity,watchlist\nbob,maybe\n")); err == nil {
		t.Error("bad watchlist accepted")
	}
	if as, err := ParseAssets([]byte("ip,owner\n10.1.1.1,x\n")); err != nil || len(as) != 1 {
		t.Errorf("ip-only list: %v", err)
	}
}

func TestRowCap(t *testing.T) {
	defer func(n int) { maxRows = n }(maxRows)
	maxRows = 100
	if as, err := ParseAssets([]byte("host\n" + strings.Repeat("web1\n", 100))); err != nil || len(as) != 100 {
		t.Fatalf("at the cap = %d %v", len(as), err)
	}
	if _, err := ParseAssets([]byte("host\n" + strings.Repeat("web1\n", 101))); err == nil || !strings.Contains(err.Error(), "more than 100 rows") {
		t.Errorf("assets over the cap: %v", err)
	}
	s, _ := NewStore("")
	if _, err := s.SetIdentities([]byte("identity\n" + strings.Repeat("bob\n", 101))); err == nil || !strings.Contains(err.Error(), "more than 100 rows") {
		t.Errorf("identities over the cap: %v", err)
	}
}

func TestFilesAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil || len(s.Assets()) != 0 {
		t.Fatal(err)
	}
	if n, err := s.SetAssets([]byte(assetCSV)); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	s2, err := NewStore(dir)
	if err != nil || len(s2.Assets()) != 4 {
		t.Fatalf("reloaded %d, %v", len(s2.Assets()), err)
	}
	if changed, _ := s2.Reload(); changed {
		t.Error("reload without a change")
	}
	os.WriteFile(filepath.Join(dir, IdentitiesFile), []byte(identityCSV), 0o600)
	if changed, err := s2.Reload(); !changed || err != nil || len(s2.Identities()) != 2 {
		t.Errorf("reload after edit: %v %v", changed, err)
	}
	if !strings.HasPrefix(string(s2.CSV("identities")), "identity,name") || !strings.Contains(string(s2.CSV("assets")), "domain_controller|pci") {
		t.Error("csv export")
	}
	// A broken edit keeps the previous lists.
	os.WriteFile(filepath.Join(dir, AssetsFile), []byte("host,priority\nx,urgent\n"), 0o600)
	if _, err := s2.Reload(); err == nil || len(s2.Assets()) != 4 {
		t.Errorf("broken edit: %v, %d assets", err, len(s2.Assets()))
	}
}

func TestCSVDownloadIsSafeInSpreadsheets(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in := "identity,name,email,manager,priority,category,bunit,watchlist\n" +
		"mallory,\"=HYPERLINK(\"\"http://evil.example\"\")\",m@x.test,+1-555,low,,@IT,\n"
	if _, err := s.SetIdentities([]byte(in)); err != nil {
		t.Fatal(err)
	}
	out := string(s.CSV("identities"))
	for _, want := range []string{`"'=HYPERLINK(""http://evil.example"")"`, "'+1-555", "'@IT"} {
		if !strings.Contains(out, want) {
			t.Errorf("download lacks %s:\n%s", want, out)
		}
	}
	// Uploading the download again gives the same values back.
	if _, err := s.SetIdentities([]byte(out)); err != nil {
		t.Fatal(err)
	}
	id, ok := s.Identity("mallory")
	if !ok || id.Name != `=HYPERLINK("http://evil.example")` || id.Manager != "+1-555" || id.BUnit != "@IT" {
		t.Errorf("round trip: %+v", id)
	}
	if got := SafeCell("10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("SafeCell changed a plain value: %q", got)
	}
}

// A damaged list must not keep the server from starting: OpenStore gives
// empty lists and the error, and picks the file up once it is fixed.
func TestOpenStoreWithADamagedList(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, AssetsFile), []byte("host,priority\nweb01,urgent\n"), 0o600)
	s, err := OpenStore(dir)
	if s == nil || err == nil || !strings.Contains(err.Error(), "urgent") {
		t.Fatalf("store %v, err %v", s, err)
	}
	if len(s.Assets()) != 0 {
		t.Errorf("%d assets from a damaged file", len(s.Assets()))
	}
	if _, err := NewStore(dir); err == nil {
		t.Error("NewStore accepted the damaged file")
	}
	os.WriteFile(filepath.Join(dir, AssetsFile), []byte(assetCSV), 0o600)
	if changed, err := s.Reload(); !changed || err != nil || len(s.Assets()) != 4 {
		t.Errorf("after the fix: %v %v, %d assets", changed, err, len(s.Assets()))
	}
}

// The overlay (rows the sample data adds) answers only what the user's
// lists do not, lives in its own files, survives a damaged user list, and
// leaves the user's files, CSV and listing alone.
func TestOverlay(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, AssetsFile), []byte(assetCSV), 0o600)
	os.WriteFile(filepath.Join(dir, IdentitiesFile), []byte(identityCSV), 0o600)
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	overlayAssets := []Asset{
		{Host: []string{"dc01"}, IP: []string{"192.0.2.110"}, Priority: "low", BUnit: "Sample data"},
		{Host: []string{"ws-fin-07"}, IP: []string{"10.20.5.7"}, Priority: "low", BUnit: "Sample data"},
	}
	overlayIDs := []Identity{{Identity: []string{`CORP\svc_backup`}, Name: "Sample backup", BUnit: "Sample data"}}
	if err := s.SetOverlay(overlayAssets, overlayIDs); err != nil {
		t.Fatal(err)
	}

	// The user's rows win; the overlay answers the rest.
	if a, _ := s.Asset("DC01"); a == nil || a.BUnit != "IT" {
		t.Errorf("DC01 = %+v, want the user's row", a)
	}
	if a, _ := s.Asset("10.20.5.7"); a == nil || a.BUnit != "Finance" {
		t.Errorf("10.20.5.7 = %+v, want the user's network row", a)
	}
	if a, _ := s.Asset("ws-fin-07"); a == nil || a.BUnit != "Sample data" {
		t.Errorf("ws-fin-07 = %+v, want the overlay's row", a)
	}
	if id, _ := s.Identity("svc_backup"); id == nil || id.Name != "Backup service" {
		t.Errorf("svc_backup = %+v, want the user's row", id)
	}
	if _, ok := s.Own().Asset("ws-fin-07"); ok {
		t.Error("Own() answered from the overlay")
	}
	if len(s.Assets()) != 4 || len(s.Identities()) != 2 || strings.Contains(string(s.CSV("assets")), "Sample data") {
		t.Error("the user's list or its CSV includes overlay rows")
	}
	if a, i := s.Overlay(); len(a) != 2 || len(i) != 1 {
		t.Errorf("Overlay() = %d, %d rows", len(a), len(i))
	}
	for name, want := range map[string]string{AssetsFile: assetCSV, IdentitiesFile: identityCSV} {
		if b, _ := os.ReadFile(filepath.Join(dir, name)); string(b) != want {
			t.Errorf("%s was rewritten", name)
		}
	}

	// Another process (the CLI) sees the overlay, even with a damaged user
	// list, and Reload in this one notices it go.
	os.WriteFile(filepath.Join(dir, AssetsFile), []byte("host,priority\nx,urgent\n"), 0o600)
	s2, err := OpenStore(dir)
	if err == nil {
		t.Fatal("the damaged list should be reported")
	}
	if a, _ := s2.Asset("ws-fin-07"); a == nil || a.BUnit != "Sample data" {
		t.Errorf("a second store does not see the overlay: %+v", a)
	}
	if err := s2.SetOverlay(nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{OverlayAssetsFile, OverlayIdentitiesFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still there: %v", name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, AssetsFile)); string(b) != "host,priority\nx,urgent\n" {
		t.Error("removing the overlay rewrote the damaged user list")
	}
	s.Reload()
	if _, ok := s.Asset("ws-fin-07"); ok {
		t.Error("the first store still answers from a removed overlay")
	}
	if a, _ := s.Asset("DC01"); a == nil || a.BUnit != "IT" {
		t.Errorf("the user's last good list was lost: %+v", a)
	}
}

// TestConcurrentWritesDoNotMix: two writers saving the same list at once
// (two servers sharing the folder, or two requests) leave one complete
// version and no temporary file behind.
func TestConcurrentWritesDoNotMix(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	a, b := strings.Repeat("a,1\n", 50000), strings.Repeat("b,2\n", 40000)
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		data := a
		if i%2 == 1 {
			data = b
		}
		go func() {
			_, err := s.write("assets.csv", []byte(data))
			done <- err
		}()
	}
	ok := 0
	for i := 0; i < 20; i++ {
		err := <-done
		switch {
		case err == nil:
			ok++
		case runtime.GOOS != "windows":
			// Windows may refuse to rename over a file another rename is
			// replacing at that instant; the writer then reports an error.
			t.Fatal(err)
		}
	}
	if ok == 0 {
		t.Fatal("no write succeeded")
	}
	got, err := os.ReadFile(filepath.Join(dir, "assets.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != a && string(got) != b {
		t.Errorf("the file mixes the two writes (%d bytes)", len(got))
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	hidden, _ := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if len(left)+len(hidden) > 0 {
		t.Errorf("temporary files left behind: %v %v", left, hidden)
	}
}
