package security

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Sentinel values stand for passwords and keys: no report may show them.
const (
	sentinelOS     = "SENTINEL-opensearch-password"
	sentinelAI     = "SENTINEL-assistant-key"
	sentinelToken  = "SENTINEL-ingest-token-0123456789abcdef"
	sentinelFeed   = "SENTINEL-feed-password"
	sentinelPrefix = "SENTINEL"
)

var (
	hashOnce sync.Once
	hash     string
)

var now = time.Date(2026, 10, 13, 14, 2, 11, 0, time.UTC)

// loadConfig loads a signalith.yaml with extra in it, in a folder of its
// own, with no settings from this process's environment.
func loadConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	hashOnce.Do(func() {
		h, err := config.HashPassword("long-enough-password")
		if err != nil {
			t.Fatal(err)
		}
		hash = h
	})
	for _, v := range os.Environ() {
		if name, _, _ := strings.Cut(v, "="); strings.HasPrefix(name, "SIGNALITH_") {
			t.Setenv(name, "")
		}
	}
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	body := "auth:\n  admin_password_hash: " + hash + "\n" + extra
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const httpsAuto = "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\n    plaintext_ingest: deny\n"

// goodFacts are the facts of a server set up safely: HTTPS with
// Signalith's own strict certificate authority, an OpenSearch that
// requires sign-in, encrypted disks, a systemd service.
func goodFacts(t *testing.T, extra string) *Facts {
	t.Helper()
	c := loadConfig(t, httpsAuto+"opensearch:\n  url: https://127.0.0.1:9200\n  username: signalith\n  password: "+sentinelOS+"\n  index_prefix: signalith\n"+extra)
	ca := &tlsauto.CAInfo{Scope: tlsauto.ScopeStandard, Fingerprint: "AB:12", Subject: "Signalith Local CA (siem-1)",
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(9, 0, 0), Names: []string{"siem-1", "10.0.0.12"}}
	f := &Facts{
		Now:    now,
		Server: ServerInfo{Name: "siem-1", Version: "v0.9.0", Go: "go1.26.9", OS: "linux", Deployment: DeployLinuxSystemd, DeploymentLabel: "Linux, systemd service"},
		Config: c, Uptime: 48 * time.Hour,
		TLS: &TLSFacts{Mode: "auto", Leaf: &LeafFacts{NotAfter: now.AddDate(0, 0, 300)}, CA: ca, ScopeSetup: "standard",
			WouldCover: map[string][]string{"standard": {"siem-1", "10.0.0.12"}, "strict": {"siem-1", "siem-1.corp.local", "10.0.0.12", "localhost", "127.0.0.1", "::1"}}},
		Runtime: &RuntimeFacts{SyslogSenders: map[string]int{}},
		Key: KeyFacts{Source: secrets.Source{Kind: secrets.FromDefault, Path: "/var/lib/signalith/keys/master.key"},
			Perm: &Perm{Owner: "signalith"}},
		Secrets: SecretFacts{Stored: []config.StoredSecret{{File: c.Path(), Setting: "opensearch.password", State: secrets.Current}}},
		Disks:   []Disk{{Path: "/var/lib/signalith", Kind: DiskEncrypted, Method: "LUKS2"}},
		OpenSearch: OpenSearchFacts{Anonymous: "closed", AuthProbed: true, AuthUser: "signalith", AuthRoles: []string{"signalith_server"},
			DataPaths: []Disk{{Path: "/var/lib/opensearch", Kind: DiskEncrypted}}},
		Users: UserFacts{BuiltinName: "admin"},
		Process: ProcessFacts{Known: true, UID: 998, UserName: "signalith", Systemd: true, NoNewPrivs: true, Seccomp: true, NoCaps: true,
			ReadOnlyRoot: true, HiddenProc: true, PrivateDev: true, Umask077: true},
		Memory: MemoryFacts{Known: true, CoreOff: true, NotDumpable: true},
		Files:  FileFacts{Known: true},
	}
	f.SettingEnv = map[string]string{}
	return f
}

// check evaluates f and returns the check id, or nil when it is hidden.
func check(t *testing.T, f *Facts, id string) *Check {
	t.Helper()
	r := Evaluate(f)
	noSecrets(t, r)
	return r.Find(id)
}

// noSecrets fails when a report shows a sentinel secret anywhere.
func noSecrets(t *testing.T, r *Report) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{string(b), Text(r), Text(r.Typographic())} {
		if strings.Contains(s, sentinelPrefix) {
			i := strings.Index(s, sentinelPrefix)
			t.Fatalf("a secret shows in the report: ...%s...", s[max(0, i-80):min(len(s), i+40)])
		}
	}
}

// tempConfigArg starts the -c the Linux commands add for the test's
// signalith.yaml, which is in a temporary folder; none on Windows, whose
// paths a Linux server can't have.
var tempConfigArg = map[bool]string{true: " -c /", false: ""}[filepath.Separator == '/']

type checkCase struct {
	name  string
	extra string // added to the config
	set   func(f *Facts)
	state State  // "" means hidden
	line  string // the exact line; "" skips the comparison
	fix   func(t *testing.T, c *Check)
}

func runCases(t *testing.T, id string, cases []checkCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts(t, tc.extra)
			if tc.set != nil {
				tc.set(f)
			}
			c := check(t, f, id)
			if tc.state == "" {
				if c != nil {
					t.Fatalf("shown: %+v", c)
				}
				return
			}
			if c == nil {
				t.Fatal("hidden")
			}
			if c.State != tc.state {
				t.Errorf("state %s, want %s (%s)", c.State, tc.state, c.Line)
			}
			if tc.line != "" && c.Line != tc.line {
				t.Errorf("line\n got %q\nwant %q", c.Line, tc.line)
			}
			if c.State == Good && c.Fix != nil {
				t.Error("a good check has a fix")
			}
			if (c.State == Risk || c.State == Attention) && c.Fix == nil {
				t.Error("a problem without a fix")
			}
			if c.Fix != nil {
				want := "How to fix"
				if c.State == Unknown {
					want = "How to check"
				}
				if c.Fix.Label != want {
					t.Errorf("fix label %q", c.Fix.Label)
				}
			}
			if tc.fix != nil {
				tc.fix(t, c)
			}
		})
	}
}

func TestHTTPS(t *testing.T) {
	runCases(t, "transit.https", []checkCase{
		{name: "auto", state: Good, line: "The web page, the API and agents use HTTPS, with Signalith's own certificate."},
		{name: "files", set: func(f *Facts) { f.Config.Server.TLS.Mode = "files" }, state: Good,
			line: "The web page, the API and agents use HTTPS, with your own certificate."},
		{name: "off on loopback", set: func(f *Facts) { f.Config.Server.TLS.Mode = "off"; f.Config.Server.Listen = "127.0.0.1:8080" }, state: Good,
			line: "HTTPS is off, but Signalith only answers on this computer (127.0.0.1:8080), so nothing it sends crosses the network."},
		{name: "proxy, direct sign-ins", set: func(f *Facts) {
			f.Config.Server.TLS.Mode = "off"
			f.Config.Server.TrustedProxies = []string{"10.0.0.5"}
			f.Runtime.DirectPlain = []string{"10.0.0.7", "10.0.0.8"}
		}, state: Attention,
			line: "A reverse proxy serves HTTPS, but 2 computers signed in to Signalith directly over plain HTTP in the last day: 10.0.0.7 and 10.0.0.8.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "server.listen" || !strings.Contains(c.Fix.Steps[1], "127.0.0.1:8080") || c.Fix.Docs.Anchor != "behind-a-reverse-proxy" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "proxy, direct agents", set: func(f *Facts) {
			f.Config.Server.TLS.Mode = "off"
			f.Config.Server.TrustedProxies = []string{"10.0.0.5"}
			f.Runtime.DirectPlainAgents = []string{"web-1 (10.0.0.4)"}
		}, state: Attention,
			line: "A reverse proxy serves HTTPS, but 1 agent sent events to Signalith directly over plain HTTP in the last day: web-1 (10.0.0.4).",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 0 || len(c.Fix.Steps) != 2 || !strings.Contains(c.Fix.Steps[0], "Add data") {
					t.Errorf("%q %+v", c.Details, c.Fix)
				}
			}},
		{name: "proxy, direct sign-ins and agents", set: func(f *Facts) {
			f.Config.Server.TLS.Mode = "off"
			f.Config.Server.TrustedProxies = []string{"10.0.0.5"}
			f.Runtime.DirectPlain = []string{"10.0.0.7"}
			f.Runtime.DirectPlainAgents = []string{"web-1 (10.0.0.4)", "db-1 (10.0.0.5)"}
		}, state: Attention,
			line: "A reverse proxy serves HTTPS, but 1 computer signed in to Signalith directly over plain HTTP in the last day: 10.0.0.7.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "2 agents sent events to Signalith directly over plain HTTP in the last day: web-1 (10.0.0.4) and db-1 (10.0.0.5)." ||
					len(c.Fix.Steps) != 3 {
					t.Errorf("%q %+v", c.Details, c.Fix)
				}
			}},
		{name: "proxy", set: func(f *Facts) {
			f.Config.Server.TLS.Mode = "off"
			f.Config.Server.TrustedProxies = []string{"10.0.0.5"}
		}, state: Good, line: "A reverse proxy at 10.0.0.5 serves HTTPS for Signalith.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || c.Tip.Label != "Make it stronger" || !strings.Contains(c.Tip.Steps[0], "port 8080") || c.Tip.Setting != "server.listen" {
					t.Errorf("tip %+v", c.Tip)
				}
			}},
		{name: "proxy in the CLI", set: func(f *Facts) {
			f.Config.Server.TLS.Mode = "off"
			f.Config.Server.TrustedProxies = []string{"10.0.0.5"}
			f.Runtime = nil
		}, state: Good, line: "A reverse proxy at 10.0.0.5 serves HTTPS for Signalith."},
		{name: "off", set: func(f *Facts) { f.Config.Server.TLS.Mode = "off" }, state: Risk,
			line: "HTTPS is off, so passwords, sessions and events cross the network unencrypted.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "server.tls.mode" || len(c.Fix.Steps) != 3 || c.Fix.Docs.Anchor != "upgrading-from-plain-http" ||
					c.Fix.Docs.URL != "https://github.com/jrsamsanchez/signalith/blob/v0.9.0/docs/https.md#upgrading-from-plain-http" {
					t.Errorf("%+v %+v", c.Fix, c.Fix.Docs)
				}
			}},
	})
}

// A signalith.yaml written before HTTPS was the default, with an https://
// public_url, leaves HTTPS to a reverse proxy Signalith believes without
// it being listed: transit.https says so, and transit.proxies stays hidden.
func TestHTTPSLegacyProxy(t *testing.T) {
	legacy := "server:\n  listen: 0.0.0.0:18972\n  public_url: https://siem.example.com\n"
	for _, tc := range []struct {
		name    string
		runtime *RuntimeFacts
		line    string
		details int
	}{
		{name: "not seen yet", runtime: &RuntimeFacts{SyslogSenders: map[string]int{}},
			line: "HTTPS is left to a reverse proxy, which Signalith trusts only because signalith.yaml was written before HTTPS was the default."},
		{name: "seen", runtime: &RuntimeFacts{SyslogSenders: map[string]int{}, LegacyProxies: []string{"127.0.0.1"}, DirectPlain: []string{"10.0.0.7"}},
			line: "HTTPS is left to the reverse proxy at 127.0.0.1, which Signalith trusts only because signalith.yaml was written before HTTPS was the default.", details: 1},
		{name: "CLI", line: "HTTPS is left to a reverse proxy, which Signalith trusts only because signalith.yaml was written before HTTPS was the default."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts(t, "")
			f.Config = loadConfig(t, legacy)
			if !f.Config.Server.LegacyProxied() {
				t.Fatal("not legacy proxied")
			}
			f.Runtime = tc.runtime
			r := Evaluate(f)
			c := r.Find("transit.https")
			if c == nil || c.State != Attention || c.Line != tc.line || len(c.Details) != tc.details {
				t.Fatalf("%+v", c)
			}
			if c.Fix == nil || c.Fix.Setting != "server.trusted_proxies" || len(c.Fix.Steps) != 2 {
				t.Errorf("%+v", c.Fix)
			}
			if p := r.Find("transit.proxies"); p != nil {
				t.Errorf("transit.proxies shown: %+v", p)
			}
		})
	}
}

func TestCertificate(t *testing.T) {
	files := func(f *Facts) {
		f.Config.Server.TLS.Mode = "files"
		f.TLS = &TLSFacts{Mode: "files", Leaf: &LeafFacts{NotAfter: now.AddDate(0, 0, 200)}, CertFile: "/etc/signalith/cert.pem",
			KeyFile: "/etc/signalith/key.pem", PublicHost: "siem.corp.local", CoversPublicHost: true}
	}
	runCases(t, "transit.certificate", []checkCase{
		{name: "auto", state: Good, line: "Signalith's own certificate is valid until 9 Aug 2027 and renews itself 30 days before."},
		{name: "no TLS", set: func(f *Facts) { f.TLS = nil }, state: ""},
		{name: "expired auto", set: func(f *Facts) { f.TLS.Leaf.NotAfter = now.AddDate(0, 0, -1) }, state: Risk,
			line: "The certificate expired on 12 Oct 2026. Agents hold their events until it's replaced, and browsers warn on every visit.",
			fix: func(t *testing.T, c *Check) {
				if !strings.Contains(c.Fix.Commands["linux"], "systemctl restart signalith") || c.Fix.Commands["windows"] == "" || c.Fix.Commands["docker"] == "" {
					t.Errorf("%+v", c.Fix.Commands)
				}
			}},
		{name: "files expiring", set: func(f *Facts) { files(f); f.TLS.Leaf.NotAfter = now.AddDate(0, 0, 10) }, state: Attention,
			line: "Your certificate expires on 23 Oct 2026, in 10 days. Replace the files before then; Signalith loads the new ones by itself.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Commands["linux"] != "openssl x509 -in /etc/signalith/cert.pem -noout -enddate" {
					t.Errorf("%+v", c.Fix.Commands)
				}
			}},
		{name: "auto not renewed", set: func(f *Facts) { f.TLS.Leaf.NotAfter = now.AddDate(0, 0, 20) }, state: Attention,
			line: "Signalith's certificate expires on 2 Nov 2026 and hasn't renewed itself. The server log says why."},
		{name: "outside", set: func(f *Facts) { f.TLS.Outside = []string{"siem.example.com"} }, state: Attention,
			line: "The certificate leaves out siem.example.com, which people or agents may use to reach this server.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "" || c.Fix.Action != "ca.prepare" || len(c.Fix.Steps) != 1 {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "files not covering", set: func(f *Facts) { files(f); f.TLS.CoversPublicHost = false }, state: Attention,
			line: "Your certificate doesn't cover siem.corp.local, the address agents are set up with."},
		{name: "files with IP addresses only", set: func(f *Facts) { files(f); f.TLS.Leaf.NoName = true }, state: Attention,
			line: "Your certificate covers only IP addresses, so agents can't check it belongs to this server, and Add data can't set them up."},
		{name: "auto with IP addresses only", set: func(f *Facts) { f.TLS.Leaf.NoName = true }, state: Good},
		{name: "files without CA", set: func(f *Facts) { files(f); f.TLS.CAMissing = true }, state: Attention,
			line: "Your certificate file doesn't include the authority that issued it, so Add data can't give it to agents."},
		{name: "weak", set: func(f *Facts) { files(f); f.TLS.Leaf.RSABits = 1024; f.TLS.Leaf.SHA1 = true }, state: Attention,
			line: "Your certificate uses a 1024-bit RSA key and SHA-1, which is too weak to trust today."},
		{name: "CA expiring", set: func(f *Facts) { f.TLS.CA.NotAfter = now.AddDate(0, 0, 100) }, state: Attention,
			line: "Signalith's certificate authority expires on 21 Jan 2027. Make a new one and switch to it before then."},
		{name: "files good", set: files, state: Good, line: "Your certificate is valid until 1 May 2027 and covers siem.corp.local."},
		{name: "several problems", set: func(f *Facts) {
			f.TLS.Leaf.NotAfter = now.AddDate(0, 0, -1)
			f.TLS.Outside = []string{"a.example.com"}
		}, state: Risk, fix: func(t *testing.T, c *Check) {
			if len(c.Details) != 1 || !strings.Contains(c.Details[0], "a.example.com") {
				t.Errorf("details %v", c.Details)
			}
		}},
	})
}

func TestCAScope(t *testing.T) {
	runCases(t, "transit.ca_scope", []checkCase{
		{name: "standard", state: Good, line: "Signalith's certificate authority can vouch only for this server and for private network names, never for public websites.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || c.Tip.Label != "Standard or strict?" || c.Tip.Action != "ca.prepare" || !strings.Contains(c.Tip.Steps[1], "Standard (in use).") ||
					!strings.Contains(c.Tip.Steps[2], "siem-1, siem-1.corp.local, 10.0.0.12 and 3 more") {
					t.Errorf("tip %+v", c.Tip)
				}
			}},
		{name: "strict", set: func(f *Facts) { f.TLS.CA.Scope = "strict"; f.TLS.ScopeSetup = "strict" }, state: Good,
			line: "Signalith's certificate authority can vouch only for this server's own names and addresses."},
		{name: "files", set: func(f *Facts) { f.TLS.Mode = "files" }, state: ""},
		{name: "next", set: func(f *Facts) { f.TLS.Next = &tlsauto.CAInfo{Scope: "strict", At: now} }, state: Attention,
			line: "A new certificate authority is ready. Switch to it once browsers and agents trust it."},
		{name: "previous", set: func(f *Facts) {
			f.TLS.Previous = &tlsauto.CAInfo{At: now.Add(-3 * time.Hour)}
			f.TLS.Refusals = []tlsauto.Refusal{{Address: "10.0.0.9", Via: "https", Count: 3}}
		}, state: Attention,
			line: "Signalith switched to a new certificate authority 3 hours ago. Remove the old one once nothing refuses the new certificate.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "1 computer refused the new certificate since the switch: 10.0.0.9." {
					t.Errorf("details %q", c.Details)
				}
			}},
		{name: "unconstrained", set: func(f *Facts) { f.TLS.CA.Scope = "unconstrained" }, state: Attention,
			line: "Signalith's certificate authority was made by an older version and can vouch for any website, to every computer that trusts it."},
		{name: "any use", set: func(f *Facts) { f.TLS.CA.AnyUse = true }, state: Attention,
			line: "Signalith's certificate authority was made by an older version and isn't limited to websites. If its key were stolen, it could sign programs or email that computers trusting it would accept.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Action != "ca.prepare" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "mismatch", set: func(f *Facts) { f.TLS.ScopeSetup = "strict" }, state: Attention,
			line: "You chose a strict certificate authority, but the one in use is standard. Make the new one and switch when you're ready.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Action != "ca.prepare" || c.Fix.Docs.Anchor != "switching-to-a-new-certificate-authority" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		// Made before names were kept exact: honest about the names under them.
		{name: "older subtrees", set: func(f *Facts) { f.TLS.CA.Subtrees = []string{"dev", "siem.example.com"} }, state: Good,
			line: "Signalith's certificate authority can vouch only for this server, private network names, and names that end in .dev or .siem.example.com.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || !strings.Contains(c.Details[0], "earlier version") {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "older subtrees, strict", set: func(f *Facts) {
			f.TLS.CA.Scope, f.TLS.ScopeSetup, f.TLS.CA.Subtrees = "strict", "strict", []string{"siem-1"}
		}, state: Good, line: "Signalith's certificate authority can vouch only for this server's own names and addresses, and for names that end in .siem-1."},
		{name: "cluster", set: func(f *Facts) { f.Runtime.ClusterServer = "siem-1" }, state: Good, fix: func(t *testing.T, c *Check) {
			if len(c.Details) != 1 || c.Details[0] != "Each server has its own certificate authority. This is siem-1's." {
				t.Errorf("%q", c.Details)
			}
		}},
	})
}

func TestAgentsPlain(t *testing.T) {
	allow := func(f *Facts) { f.Config.Server.TLS.PlaintextIngest = "allow" }
	runCases(t, "transit.agents_plain", []checkCase{
		{name: "deny", state: Good, line: "Agents can only send events over HTTPS."},
		{name: "https off", set: func(f *Facts) { f.Config.Server.TLS.Mode = "off" }, state: ""},
		{name: "senders", set: func(f *Facts) {
			allow(f)
			f.Runtime.PlainSenderCount = 2
			f.Runtime.PlainSenders = []string{"web-1 (10.0.0.4)", "db-1 (10.0.0.5)"}
		}, state: Risk, line: "2 agents send events over plain HTTP, which anyone on the network can read: web-1 (10.0.0.4) and db-1 (10.0.0.5).",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "server.tls.plaintext_ingest" || c.Fix.Page == nil || c.Fix.Page.ID != "data" || len(c.Fix.Steps) != 2 {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "none for a day", set: allow, state: Attention, line: "Agents on plain HTTP are still accepted, though none has sent that way in the last day."},
		// Agents on this computer send over loopback: nothing crosses the network.
		{name: "local only", set: func(f *Facts) { allow(f); f.Runtime.LocalPlainSenders = 1 }, state: Attention,
			line: "An agent on this computer still sends over plain HTTP. Its events don't cross the network.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Steps[0] != "Give it a new configuration from Add data." {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "local and network", set: func(f *Facts) {
			allow(f)
			f.Runtime.LocalPlainSenders = 2
			f.Runtime.PlainSenderCount = 1
			f.Runtime.PlainSenders = []string{"web-1 (10.0.0.4)"}
		}, state: Risk, line: "1 agent sends events over plain HTTP, which anyone on the network can read: web-1 (10.0.0.4).",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "2 agents on this computer still send over plain HTTP. Their events don't cross the network." {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "just started", set: func(f *Facts) { allow(f); f.Uptime = 3 * time.Hour }, state: Attention,
			line: "Agents on plain HTTP are still accepted. None has sent that way since Signalith started 3 hours ago."},
		{name: "CLI", set: func(f *Facts) { allow(f); f.Runtime = nil }, state: Attention,
			line: "Agents on plain HTTP are still accepted. The Security page shows whether any still send that way."},
	})
}

func TestSyslog(t *testing.T) {
	runCases(t, "transit.syslog", []checkCase{
		{name: "off", state: ""},
		{name: "TLS only", extra: "syslog:\n  tls: 0.0.0.0:6514\n", state: Good, line: "Syslog arrives only over TLS, so it's encrypted."},
		{name: "loopback", extra: "syslog:\n  udp: 127.0.0.1:5514\n", state: Good, line: "Syslog is accepted only from this computer."},
		{name: "loopback and TLS", extra: "syslog:\n  udp: 127.0.0.1:5514\n  tls: 0.0.0.0:6514\n", state: Good,
			line: "Syslog over TLS is encrypted, and syslog over UDP is accepted only from this computer."},
		// Only the listener other computers can reach is named.
		{name: "loopback UDP, open TCP", extra: "syslog:\n  udp: 127.0.0.1:514\n  tcp: 0.0.0.0:5514\n", state: Attention,
			line: "Syslog over TCP is accepted from any computer that can reach port 5514, so anyone could send fake events.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 2 || c.Details[0] != "Syslog over UDP is accepted only from this computer." {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "allow list", extra: "syslog:\n  udp: 0.0.0.0:5514\n  tcp: 0.0.0.0:5514\n  allow: [10.0.0.0/8, 192.168.1.1, 192.168.2.0/24, 172.16.0.0/12]\n",
			state: Good, line: "Syslog over UDP and TCP is accepted only from 10.0.0.0/8, 192.168.1.1, 192.168.2.0/24 and 1 more. It isn't encrypted, which is normal for devices that can't use TLS.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || c.Tip.Setting != "syslog.tls" {
					t.Errorf("tip %+v", c.Tip)
				}
				if len(c.Details) != 1 || c.Details[0] != "No device sent syslog in the last day." {
					t.Errorf("details %q", c.Details)
				}
			}},
		{name: "NAT", extra: "syslog:\n  udp: 0.0.0.0:5514\n  public_port: 514\n", set: func(f *Facts) { f.Runtime.SyslogNATed = true }, state: Unknown,
			line: "Docker hides syslog senders' real addresses here, so Signalith can't limit who sends. Limit who reaches port 514 with this computer's firewall."},
		{name: "open", extra: "syslog:\n  udp: 0.0.0.0:514\n  tls: 0.0.0.0:6514\n", set: func(f *Facts) { f.Runtime.SyslogSenders = map[string]int{"udp": 3, "tls": 1} },
			state: Attention, line: "Syslog over UDP is accepted from any computer that can reach port 514, so anyone could send fake events.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "syslog.allow" || c.Fix.Docs.File != "security.md" {
					t.Errorf("%+v", c.Fix)
				}
				if c.Details[0] != "In the last day: 3 devices over UDP and 1 over TLS." {
					t.Errorf("details %q", c.Details)
				}
			}},
	})
}

func TestOpenSearchTransit(t *testing.T) {
	runCases(t, "transit.opensearch", []checkCase{
		{name: "https", state: Good, line: "Signalith reaches OpenSearch over HTTPS and checks its certificate."},
		{name: "skip verify", set: func(f *Facts) {
			f.Config.OpenSearch.URL = "https://10.0.0.20:9200"
			f.Config.OpenSearch.TLSSkipVerify = true
		}, state: Risk,
			line: "Signalith doesn't check OpenSearch's certificate, so someone on the network could pose as OpenSearch and read events and its password.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "opensearch.tls_skip_verify" || c.Fix.Docs.Anchor != "4-point-signalith-at-it" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		// Traffic to OpenSearch on this computer never crosses the network.
		{name: "skip verify local", set: func(f *Facts) { f.Config.OpenSearch.TLSSkipVerify = true }, state: Attention,
			line: "Signalith doesn't check OpenSearch's certificate. OpenSearch runs on this computer, so only a program here could pose as it.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "opensearch.tls_skip_verify" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "same docker network", set: func(f *Facts) {
			f.Config.OpenSearch.URL = "http://opensearch:9200"
			f.InContainer, f.OpenSearch.SameNetwork = true, true
		}, state: Attention, line: "Events cross to OpenSearch at opensearch unencrypted. It's on the same Docker network, so they likely stay on this computer."},
		{name: "http remote", set: func(f *Facts) { f.Config.OpenSearch.URL = "http://10.0.0.20:9200" }, state: Risk,
			line: "Events and the OpenSearch password cross the network to 10.0.0.20 unencrypted."},
		{name: "http remote, no password", set: func(f *Facts) {
			f.Config.OpenSearch.URL = "http://10.0.0.20:9200"
			f.Config.OpenSearch.Password = ""
		}, state: Risk, line: "Events cross the network to 10.0.0.20 unencrypted."},
		{name: "demo remote", set: func(f *Facts) { f.Config.OpenSearch.URL = "https://10.0.0.20:9200"; f.OpenSearch.DemoCert = true }, state: Risk,
			line: "OpenSearch uses the demo certificate it ships with, whose key anyone can download, so it can't prove who it is."},
		{name: "demo local", set: func(f *Facts) { f.OpenSearch.DemoCert = true }, state: Attention},
		{name: "http local", set: func(f *Facts) { f.Config.OpenSearch.URL = "http://localhost:9200" }, state: Good,
			line: "Signalith reaches OpenSearch on this computer, so events never cross the network."},
		{name: "locked by env", set: func(f *Facts) {
			f.Config.OpenSearch.TLSSkipVerify = true
			f.SettingEnv["opensearch.tls_skip_verify"] = "SIGNALITH_OPENSEARCH_TLS_SKIP_VERIFY"
		}, state: Attention, fix: func(t *testing.T, c *Check) {
			if c.Fix.LockedBy != "SIGNALITH_OPENSEARCH_TLS_SKIP_VERIFY" {
				t.Errorf("locked by %q", c.Fix.LockedBy)
			}
		}},
	})
}

func TestOutbound(t *testing.T) {
	runCases(t, "transit.outbound", []checkCase{
		{name: "none", state: ""},
		{name: "assistant and feeds", extra: "assistant:\n  provider: anthropic\n  api_key: " + sentinelAI + "\n",
			set: func(f *Facts) {
				f.Feeds = []Feed{{Name: "a", URL: "https://a.example.com/x"}, {Name: "b", URL: "https://b.example.com/y"}}
			},
			state: Good, line: "The AI assistant and 2 threat intel feeds are reached over HTTPS."},
		{name: "assistant only", extra: "assistant:\n  provider: anthropic\n  api_key: " + sentinelAI + "\n", state: Good, line: "The AI assistant is reached over HTTPS."},
		{name: "local assistant", extra: "assistant:\n  provider: openai\n  model: llama3.1\n  url: http://localhost:11434/v1\n", state: Good, line: "The AI assistant runs on this computer."},
		{name: "feeds only", set: func(f *Facts) { f.Feeds = []Feed{{Name: "a", URL: "https://a.example.com/x"}} }, state: Good,
			line: "1 threat intel feed is downloaded over HTTPS."},
		{name: "key over http", extra: "assistant:\n  provider: openai\n  model: m\n  url: http://10.0.0.30:8000/v1\n  api_key: " + sentinelAI + "\n", state: Risk,
			line: "The AI assistant's API key crosses the network to 10.0.0.30 unencrypted.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "assistant.url" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "assistant over http without a key", extra: "assistant:\n  provider: openai\n  model: m\n  url: http://10.0.0.30:8000/v1\n", state: Good,
			line: "The AI assistant at 10.0.0.30 is reached over plain HTTP, without an API key; only questions and field names go to it."},
		{name: "feed password over http", set: func(f *Facts) { f.Feeds = []Feed{{Name: "otx", URL: "http://otx.example.com/x", Credentials: true}} },
			state: Risk, line: "Feed otx's password or key crosses the network to otx.example.com unencrypted.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Page == nil || c.Fix.Page.ID != "intel" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "feed over http", set: func(f *Facts) { f.Feeds = []Feed{{Name: "list", URL: "http://lists.example.com/x"}} }, state: Attention,
			line: "Feed list downloads over plain HTTP, so someone on the network could change what it says."},
	})
}

func TestProxies(t *testing.T) {
	runCases(t, "transit.proxies", []checkCase{
		{name: "none", state: ""},
		{name: "good", set: func(f *Facts) { f.Config.Server.TrustedProxies = []string{"10.0.0.5", "10.1.0.0/24"} }, state: Good, line: "Signalith believes forwarded HTTPS only from 10.0.0.5 and 10.1.0.0/24."},
		{name: "wide", set: func(f *Facts) { f.Config.Server.TrustedProxies = []string{"10.0.0.0/8"} }, state: Attention,
			line: "Trusted reverse proxies includes 10.0.0.0/8, so any computer in it can claim a browser used HTTPS."},
		{name: "wide v6", set: func(f *Facts) { f.Config.Server.TrustedProxies = []string{"fd00::/32"} }, state: Attention},
		{name: "legacy", set: func(f *Facts) { f.Runtime.LegacyProxies = []string{"127.0.0.1"} }, state: Attention,
			line: "Signalith believes the reverse proxy at 127.0.0.1 only because signalith.yaml was written before HTTPS was the default."},
	})
}

func TestMasterKey(t *testing.T) {
	path := "/var/lib/signalith/keys/master.key"
	runCases(t, "rest.master_key", []checkCase{
		{name: "linux file", state: Good, line: "The master key is in " + path + ", and only signalith can read it.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || c.Tip.Docs.Anchor != "keeping-the-key-elsewhere" {
					t.Errorf("tip %+v", c.Tip)
				}
			}},
		// Commands that name this server's files are for its own system
		// only: elsewhere those paths mean nothing.
		{name: "readable by all", set: func(f *Facts) { f.Key.Perm.OtherRead = true }, state: Risk,
			line: "Any account on this computer can read the master key (" + path + ").",
			fix: func(t *testing.T, c *Check) {
				want := "sudo chown signalith " + path + " && sudo chmod 600 " + path
				if c.Fix.Commands["linux"] != want || len(c.Fix.Commands) != 1 {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "readable by all, docker", set: func(f *Facts) {
			f.Key.Perm.OtherRead = true
			f.InContainer, f.Docker, f.Server.Deployment = true, true, DeployDocker
		}, state: Risk, fix: func(t *testing.T, c *Check) {
			if !strings.Contains(c.Fix.Commands["docker"], "chmod 600 /data/keys/master.key") || len(c.Fix.Commands) != 1 {
				t.Errorf("%q", c.Fix.Commands)
			}
			if !slices.Contains(c.Fix.Steps, "docker volume ls shows the volume's name.") {
				t.Errorf("%q", c.Fix.Steps)
			}
		}},
		{name: "readable by all, windows", set: func(f *Facts) {
			f.Key.Perm.SomeRead = true
			f.Key.Source.Path = `C:\ProgramData\Signalith\keys\master.key.dpapi`
			f.Server.OS, f.Server.Deployment = "windows", DeployWindowsService
		}, state: Risk, line: `Other accounts on this computer can read the master key (C:\ProgramData\Signalith\keys\master.key.dpapi).`,
			fix: func(t *testing.T, c *Check) {
				if !strings.HasPrefix(c.Fix.Commands["windows"], `icacls 'C:\ProgramData\Signalith\keys\master.key.dpapi'`) || len(c.Fix.Commands) != 1 {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "env", set: func(f *Facts) { f.Key.Source = secrets.Source{Kind: secrets.FromEnv}; f.Key.Perm = nil }, state: Attention,
			line: "The master key is in the SIGNALITH_MASTER_KEY environment variable, which is easier to leak than a file."},
		{name: "group", set: func(f *Facts) { f.Key.Perm.GroupRead = true; f.Key.Perm.Group = "adm" }, state: Attention,
			line: "The adm group can read the master key (" + path + ")."},
		{name: "owner", set: func(f *Facts) { f.Key.Perm.WrongOwner = true; f.Key.Perm.Owner = "alice" }, state: Attention,
			line: "The master key (" + path + ") belongs to alice, not to the account Signalith runs as."},
		{name: "previous", set: func(f *Facts) { f.Key.Source.OldPath = path + ".old" }, state: Attention,
			line: "The previous master key is still kept, in " + path + ".old.",
			fix: func(t *testing.T, c *Check) {
				// The config file isn't where signalith looks by default.
				if !strings.HasPrefix(c.Fix.Commands["linux"], "sudo signalith secrets rotate-master -prune"+tempConfigArg) ||
					c.Fix.Commands["windows"] != winExe+" secrets rotate-master -prune" ||
					!strings.HasSuffix(c.Fix.Commands["docker"], " secrets rotate-master -prune -c /work/signalith.yaml") {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "unused", set: func(f *Facts) { f.Key.Unused = []string{"/etc/signalith/keys/master.key"} }, state: Attention,
			line: "There's an unused copy of a master key in /etc/signalith/keys/master.key."},
		{name: "credential", set: func(f *Facts) { f.Key.Source.Kind = secrets.FromCredential }, state: Good,
			line: "The master key comes from a systemd credential, so only the Signalith service can read it."},
		{name: "windows", set: func(f *Facts) { f.Server.OS = "windows" }, state: Good, line: "The master key is protected by Windows and works only on this computer."},
		{name: "docker", set: func(f *Facts) { f.InContainer, f.Docker = true, true }, state: Good,
			line: "The master key is in the signalith-data volume, readable only by Signalith's account.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || c.Tip.Docs.Anchor != "docker" {
					t.Errorf("tip %+v", c.Tip)
				}
			}},
		// Another container, such as Kubernetes: no Docker volume, and no
		// systemd credential either.
		{name: "other container", set: func(f *Facts) { f.InContainer = true }, state: Good,
			line: "The master key is in " + path + ", and only signalith can read it.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip != nil {
					t.Errorf("tip %+v", c.Tip)
				}
			}},
		{name: "docker secret", set: func(f *Facts) {
			f.InContainer = true
			f.Key.Source = secrets.Source{Kind: secrets.FromKeyFile, Path: "/run/secrets/key"}
		},
			state: Good, line: "The master key comes from a file given to the container (/run/secrets/key)."},
		{name: "none", set: func(f *Facts) { f.Key = KeyFacts{SourceErr: &secrets.NoKeyError{}}; f.Secrets.Stored = nil }, state: Good,
			line: "No passwords or keys are stored yet, so there's no master key."},
		// Plain values but no key yet: Stored passwords and keys covers
		// them, and this line doesn't say nothing is stored.
		{name: "none yet", set: func(f *Facts) {
			f.Key = KeyFacts{SourceErr: &secrets.NoKeyError{}}
			f.Secrets.Stored = []config.StoredSecret{{Setting: "opensearch.password", State: secrets.Plain}}
		}, state: Good, line: "There's no master key yet. Signalith makes one the first time it encrypts a password or key."},
		{name: "unreadable", set: func(f *Facts) { f.Key = KeyFacts{SourceErr: errors.New("bad key file")} }, state: Unknown},
	})
}

func TestStoredSecrets(t *testing.T) {
	plain := func(f *Facts) {
		f.Secrets.Stored = []config.StoredSecret{
			{File: f.Config.Path(), Setting: "opensearch.password", State: secrets.Plain},
			{File: f.Config.Path(), Setting: "assistant.api_key", State: secrets.Plain},
		}
	}
	runCases(t, "rest.stored_secrets", []checkCase{
		{name: "good", state: Good, line: "The one stored password or key is encrypted with the master key.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || !strings.Contains(c.Details[0], "File permissions") {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "none", set: func(f *Facts) { f.Secrets.Stored = nil }, state: Good, line: "No passwords or keys are stored in Signalith's files."},
		{name: "several", set: func(f *Facts) {
			f.Secrets.Stored = append(f.Secrets.Stored, config.StoredSecret{Setting: "assistant.api_key", State: secrets.Current})
		}, state: Good, line: "All 2 stored passwords and keys are encrypted with the master key."},
		{name: "exposed", set: func(f *Facts) { plain(f); f.Secrets.Exposed = []string{f.Config.Path()} }, state: Risk,
			line: "signalith.yaml holds 2 passwords or keys as plain text, and other accounts on this computer can read it.",
			fix: func(t *testing.T, c *Check) {
				if !strings.Contains(c.Fix.Commands["linux"], "sudo signalith secrets encrypt") || !strings.Contains(c.Fix.Commands["linux"], "chmod go-rwx") {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "plain", set: plain, state: Attention, line: "2 passwords or keys are stored as plain text: opensearch.password and assistant.api_key.",
			fix: func(t *testing.T, c *Check) {
				if !strings.HasSuffix(c.Fix.Commands["docker"], "docker compose restart signalith") {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "address", set: func(f *Facts) { f.Secrets.Address = []string{"opensearch.url"} }, state: Attention,
			line: "opensearch.url has a password written into its address, where it can't be encrypted.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "opensearch.url" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "previous", set: func(f *Facts) { f.Secrets.Stored[0].State = secrets.Previous }, state: Attention,
			line: "1 value is still encrypted with the previous master key."},
		{name: "unreadable", set: func(f *Facts) { f.Secrets.Stored[0].State = secrets.Unreadable }, state: Attention,
			line: "1 value can't be decrypted with the master key in use: opensearch.password."},
		{name: "file errors", set: func(f *Facts) {
			f.Secrets.Stored = nil
			f.Secrets.Errors = map[string]error{"/x/settings.yaml": errors.New("damaged")}
		}, state: Unknown},
		{name: "denied", set: func(f *Facts) { f.deny("rest.stored_secrets") }, state: Unknown, line: "Run signalith security with sudo to check this."},
	})
}

func TestDisk(t *testing.T) {
	runCases(t, "rest.disk", []checkCase{
		{name: "encrypted", state: Good, line: "The disk that holds Signalith's files is encrypted (LUKS2)."},
		{name: "two", set: func(f *Facts) { f.Disks = append(f.Disks, Disk{Kind: DiskEncrypted}) }, state: Good,
			line: "Both disks that hold Signalith's files are encrypted."},
		{name: "bitlocker", set: func(f *Facts) {
			f.Disks = []Disk{{Kind: DiskEncrypted, Method: "BitLocker", Drive: "C:", CheckedAt: now.AddDate(0, 0, -2)}}
		}, state: Good, line: "BitLocker protects drive C:, which holds Signalith's files (checked 11 Oct 2026)."},
		{name: "plain", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskPlain, Device: "/dev/sda2"}} }, state: Attention,
			line: "The disk that holds Signalith's files (/dev/sda2) isn't encrypted, as far as Linux can tell.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 2 || c.Fix.Docs.Anchor != "disk-encryption" || c.Fix.Docs.File != "encryption.md" {
					t.Errorf("%q %+v", c.Details, c.Fix)
				}
			}},
		{name: "windows off", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskPlain, Drive: "C:", CheckedAt: now}} }, state: Attention,
			line: "Drive C:, which holds Signalith's files, isn't protected by BitLocker (checked 13 Oct 2026)."},
		{name: "suspended", set: func(f *Facts) {
			f.Disks = []Disk{{Kind: DiskEncrypted, Method: "BitLocker", Drive: "D:", Suspended: true, CheckedAt: now}}
		}, state: Attention, line: "BitLocker is suspended on drive D: (checked 13 Oct 2026).",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Commands["windows"] != "manage-bde -resume D:" {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "virtual", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskVirtual, Provider: "Amazon EC2"}} }, state: Unknown,
			line: "Signalith's files are on a virtual disk. Its host (Amazon EC2) may encrypt it, but Signalith can't see that from inside.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Steps[0] != "Check the disk's settings in Amazon EC2's console, or ask whoever runs the host." || c.Fix.Docs.File != "security.md" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "container", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskContainer}} }, state: Unknown,
			line: "Signalith runs in a container, so it can't see the disk under its files."},
		{name: "network", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskNetwork, Source: "nas:/export"}} }, state: Unknown,
			line: "Signalith's files are on a network share (nas:/export), whose disks Signalith can't see."},
		{name: "zfs", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskUnreadable, FSType: "ZFS", Source: "rpool/data"}} }, state: Unknown,
			line: "Signalith's files are on ZFS, whose encryption Signalith can't read.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Commands["linux"] != "zfs get encryption rpool/data" {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "windows no answer", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskWindows, Drive: "C:"}} }, state: Unknown,
			line: "Windows tells only administrators whether BitLocker is on."},
		{name: "memory", set: func(f *Facts) { f.Disks = []Disk{{Kind: DiskMemory}} }, state: Good, line: "Signalith's files are kept in memory only."},
		{name: "worst wins", set: func(f *Facts) { f.Disks = append(f.Disks, Disk{Kind: DiskPlain, Device: "/dev/sdb1"}) }, state: Attention},
	})
}

func TestArchives(t *testing.T) {
	arch := func(f *Facts) {
		f.Archive = &ArchiveFacts{Dir: "/var/lib/signalith/archive", Count: 120, Bytes: 3 << 30, Disk: Disk{Kind: DiskEncrypted}, Perm: &Perm{}}
	}
	runCases(t, "rest.archives", []checkCase{
		{name: "none", state: ""},
		{name: "policies, nothing yet", set: func(f *Facts) { f.Archive = &ArchiveFacts{Policies: true} }, state: Good, line: "Archiving is on; no days are archived yet."},
		{name: "good", set: arch, state: Good, line: "120 archived days (3 GB) are kept in /var/lib/signalith/archive, on an encrypted disk, readable only by Signalith."},
		{name: "readable", set: func(f *Facts) { arch(f); f.Archive.Perm.OtherRead = true }, state: Attention,
			line: "Other accounts on this computer can read the archived days in /var/lib/signalith/archive.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Commands["linux"] != "sudo chmod -R go-rwx /var/lib/signalith/archive" || len(c.Fix.Commands) != 1 {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		{name: "readable, docker", set: func(f *Facts) {
			arch(f)
			f.Archive.Perm.OtherRead = true
			f.InContainer, f.Docker, f.Server.Deployment = true, true, DeployDocker
		}, state: Attention, fix: func(t *testing.T, c *Check) {
			if c.Fix.Commands["docker"] != "docker run --rm -v docker_signalith-data:/data busybox chmod -R go-rwx /data/archive" || len(c.Fix.Commands) != 1 {
				t.Errorf("%q", c.Fix.Commands)
			}
		}},
		{name: "plain disk", set: func(f *Facts) { arch(f); f.Archive.Disk.Kind = DiskPlain }, state: Attention,
			line: "120 archived days (3 GB) are kept as plain files in /var/lib/signalith/archive, on a disk that isn't encrypted. Signalith doesn't encrypt archives itself."},
		{name: "share", set: func(f *Facts) { arch(f); f.Archive.Disk = Disk{Kind: DiskNetwork, Source: "nas:/a"} }, state: Unknown,
			line: "120 archived days (3 GB) are kept as plain files in /var/lib/signalith/archive. Signalith can't see whether the share under them is encrypted."},
		{name: "many", set: func(f *Facts) { arch(f); f.Archive.Count, f.Archive.More = archiveMaxFiles, true }, state: Good,
			fix: func(t *testing.T, c *Check) {
				if !strings.HasPrefix(c.Line, "100,000+ archived days") {
					t.Error(c.Line)
				}
			}},
	})
}

func TestOpenSearchDisk(t *testing.T) {
	runCases(t, "rest.opensearch_disk", []checkCase{
		{name: "encrypted", set: func(f *Facts) { f.OpenSearch.DataPaths = []Disk{{Path: "/var/lib/opensearch", Kind: DiskEncrypted}} }, state: Good,
			line: "OpenSearch keeps events in /var/lib/opensearch, on an encrypted disk."},
		{name: "plain", set: func(f *Facts) { f.OpenSearch.DataPaths = []Disk{{Path: "/var/lib/opensearch", Kind: DiskPlain}} }, state: Attention,
			line: "OpenSearch keeps events in /var/lib/opensearch, on a disk that isn't encrypted, as far as Linux can tell."},
		{name: "remote", set: func(f *Facts) { f.Config.OpenSearch.URL = "https://os.corp.local:9200" }, state: Unknown,
			line: "OpenSearch runs on another computer (os.corp.local), so Signalith can't see its disk."},
		{name: "docker", set: func(f *Facts) {
			f.Config.OpenSearch.URL = "https://opensearch:9200"
			f.InContainer, f.Docker = true, true
		}, state: Unknown,
			line: "OpenSearch runs in its own container. Its events are in the opensearch-data volume on this computer's disk, which Signalith can't see from its container."},
		{name: "other container", set: func(f *Facts) { f.Config.OpenSearch.URL = "https://opensearch:9200"; f.InContainer = true }, state: Unknown,
			line: "Signalith runs in a container, so it can't see the disk where OpenSearch (opensearch) keeps events."},
		{name: "failed", set: func(f *Facts) { f.OpenSearch.DataErr = "status 403"; f.OpenSearch.DataPaths = nil }, state: Unknown,
			line: "Signalith couldn't ask OpenSearch where it keeps events (status 403)."},
		{name: "virtual", set: func(f *Facts) { f.OpenSearch.DataPaths = []Disk{{Kind: DiskVirtual}} }, state: Unknown,
			line: "OpenSearch's data files are on a virtual disk. Its host may encrypt it, but Signalith can't see that from inside."},
		// OpenSearch in Docker, Signalith on the computer itself: the
		// container's folder isn't here, and the disk of / says nothing.
		{name: "folder not here", set: func(f *Facts) {
			f.OpenSearch.DataPaths, f.OpenSearch.DataMissing = nil, []string{"/usr/share/opensearch/data"}
		}, state: Unknown,
			line: "OpenSearch says it keeps events in /usr/share/opensearch/data, which isn't on this computer's disks as Signalith sees them. It may run in a container."},
		// The systemd unit hides /home (ProtectHome): an empty folder in
		// memory stands in for it, which is no answer.
		{name: "hidden", set: func(f *Facts) {
			f.OpenSearch.DataPaths = []Disk{{Path: "/home/me/opensearch/data", Kind: DiskDenied, Hidden: "/home"}}
		}, state: Unknown,
			line: "Signalith's account isn't allowed to look inside /home, so it can't tell which disk holds OpenSearch's data files."},
		{name: "in memory", set: func(f *Facts) { f.OpenSearch.DataPaths = []Disk{{Path: "/dev/shm/os", Kind: DiskMemory}} }, state: Good,
			line: "OpenSearch keeps events in /dev/shm/os, in memory only."},
		{name: "seen through a closed folder", set: func(f *Facts) {
			f.OpenSearch.DataPaths = []Disk{{Path: "/var/lib/opensearch/data", Kind: DiskEncrypted, Hidden: "/var/lib/opensearch"}}
		}, state: Good, line: "OpenSearch keeps events in /var/lib/opensearch/data, on an encrypted disk.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || !strings.Contains(c.Details[0], "can't look inside /var/lib/opensearch") {
					t.Errorf("%q", c.Details)
				}
			}},
		// Proper names keep their capital letters.
		{name: "can't tell", set: func(f *Facts) { f.OpenSearch.DataPaths = []Disk{{Kind: DiskUnknown}} }, state: Unknown,
			line: "Signalith can't tell whether the disk under OpenSearch's data files is encrypted."},
	})
}

func TestDiskLineKeepsNames(t *testing.T) {
	if got := diskLine(Disk{Kind: DiskUnknown}, "Signalith's files"); got != "Signalith can't tell whether the disk under Signalith's files is encrypted." {
		t.Error(got)
	}
}

func TestOpenSearchAccess(t *testing.T) {
	runCases(t, "rest.opensearch_access", []checkCase{
		{name: "closed", state: Good, line: "OpenSearch turns away anyone who doesn't sign in."},
		{name: "open remote", set: func(f *Facts) { f.Config.OpenSearch.URL = "http://10.0.0.20:9200"; f.OpenSearch.Anonymous = "open" }, state: Risk,
			line: "Anyone who can reach OpenSearch at 10.0.0.20:9200 can read events without signing in."},
		{name: "open, listening", set: func(f *Facts) { f.OpenSearch.Anonymous, f.OpenSearch.Listening = "open", true }, state: Risk},
		{name: "open local", set: func(f *Facts) { f.OpenSearch.Anonymous = "open" }, state: Attention,
			line: "OpenSearch lets anyone on this computer read events without signing in. It isn't listening on the network.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Docs.Anchor != "opensearch-on-linux-or-windows" {
					t.Errorf("%+v", c.Fix.Docs)
				}
			}},
		{name: "unknown", set: func(f *Facts) { f.OpenSearch.Anonymous = "unknown" }, state: Unknown,
			line: "Signalith couldn't reach OpenSearch just now, so it can't tell who else can."},
		{name: "unreachable", set: func(f *Facts) { f.OpenSearch.Anonymous, f.OpenSearch.AnonymousErr = "unknown", "connection refused" }, state: Unknown,
			line: "Signalith couldn't reach OpenSearch just now, so it can't tell who else can.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "Signalith couldn't reach OpenSearch: connection refused." || !strings.Contains(c.Fix.Steps[0], "Health page") {
					t.Errorf("%q %+v", c.Details, c.Fix)
				}
			}},
		// OpenSearch answered, but not in a way that tells.
		{name: "odd answer", set: func(f *Facts) { f.OpenSearch.Anonymous, f.OpenSearch.AnonymousErr = "unknown", "status 503" }, state: Unknown,
			line: "Signalith couldn't tell whether OpenSearch lets anyone read events without signing in.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "OpenSearch answered: status 503." {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "timed out", set: func(f *Facts) { f.TimedOut = map[string]bool{"rest.opensearch_access": true} }, state: Unknown, line: TimedOutLine},
	})
}

func TestMemory(t *testing.T) {
	runCases(t, "use.memory", []checkCase{
		{name: "linux", state: Good, line: "Signalith's memory can't be saved in a crash dump, and other programs can't read it, except as root.",
			fix: func(t *testing.T, c *Check) {
				if c.Details[0] != "Swap: off for Signalith." || c.Tip == nil || len(c.Tip.Steps) != 1 || !strings.Contains(c.Tip.Steps[0], "confidential virtual machine") {
					t.Errorf("%q %+v", c.Details, c.Tip)
				}
			}},
		{name: "swap", set: func(f *Facts) { f.Memory.SwapOn = true; f.ConfidentialVM = "AMD SEV-SNP" }, state: Good, fix: func(t *testing.T, c *Check) {
			if c.Details[0] != "Swap: on, so the system could write Signalith's memory to disk." || c.Tip == nil || len(c.Tip.Steps) != 1 || !strings.Contains(c.Tip.Steps[0], "MemorySwapMax=0") {
				t.Errorf("%q %+v", c.Details, c.Tip)
			}
		}},
		{name: "swap encrypted", set: func(f *Facts) { f.Memory.SwapOn, f.Memory.SwapEncrypted = true, true; f.ConfidentialVM = "Intel TDX" }, state: Good,
			fix: func(t *testing.T, c *Check) {
				if c.Details[0] != "Swap: on, encrypted." || c.Tip != nil {
					t.Errorf("%q %+v", c.Details, c.Tip)
				}
			}},
		{name: "dumps", set: func(f *Facts) { f.Memory.CoreOff = false }, state: Attention, line: "Signalith's memory could be saved in a crash dump, with passwords in it."},
		// The systemd unit's MemorySwapMax doesn't apply in a container.
		{name: "swap in a container", set: func(f *Facts) { f.Memory.SwapOn = true; f.InContainer = true; f.ConfidentialVM = "AMD SEV-SNP" }, state: Good,
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || len(c.Tip.Steps) != 1 || !strings.Contains(c.Tip.Steps[0], "memswap_limit") || strings.Contains(c.Tip.Steps[0], "systemd") {
					t.Errorf("%+v", c.Tip)
				}
			}},
		{name: "windows dumps", set: func(f *Facts) {
			f.Server.OS = "windows"
			f.Memory = MemoryFacts{Known: true, FullDumps: true, DumpFolder: `C:\Dumps`, DumpsRegistry: `HKLM\SOFTWARE\x`}
		}, state: Attention, line: `Windows is set to keep full memory dumps of crashing programs in C:\Dumps, which could hold passwords Signalith has in memory.`},
		{name: "windows", set: func(f *Facts) { f.Server.OS = "windows"; f.Memory = MemoryFacts{Known: true} }, state: Good,
			line: "Windows isn't set to keep full memory dumps of Signalith if it crashes."},
		{name: "not running", set: func(f *Facts) {
			f.Memory = MemoryFacts{}
			f.Process = ProcessFacts{Why: NoServiceLine}
		}, state: Unknown, line: NoServiceLine},
	})
}

func TestConfidentialVM(t *testing.T) {
	runCases(t, "use.confidential_vm", []checkCase{
		{name: "none", state: ""},
		{name: "sev", set: func(f *Facts) { f.ConfidentialVM = "AMD SEV-SNP" }, state: Good,
			line: "This server runs in a confidential virtual machine (AMD SEV-SNP), built to keep even its host from reading its memory."},
	})
}

func TestBuiltinPassword(t *testing.T) {
	set := now.AddDate(0, -1, 0)
	runCases(t, "accounts.builtin_password", []checkCase{
		{name: "good", set: func(f *Facts) { f.Admin.SetAt = &set }, state: Good, line: "The built-in admin (admin) has a password of its own, last set 13 Sep 2026."},
		{name: "public", set: func(f *Facts) { f.Admin.Public, f.Admin.FromEnv = true, true }, state: Risk,
			line: "The built-in admin's password is change-me-please, an example anyone can look up.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Fix.Steps) != 2 || !strings.HasPrefix(c.Fix.Commands["linux"], "sudo signalith passwd"+tempConfigArg) {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "docker first", set: func(f *Facts) { f.Admin.DockerFirst = true }, state: Attention,
			line: "The built-in admin still has the first password the Docker setup made, which is kept as plain text in a Docker volume."},
		{name: "env", set: func(f *Facts) { f.Admin.FromEnv = true }, state: Attention,
			line: "The built-in admin's password is set in the SIGNALITH_ADMIN_PASSWORD environment variable."},
		{name: "file", set: func(f *Facts) { f.Admin.FromFile = true }, state: Attention,
			line: "The built-in admin's password is read from the file in SIGNALITH_ADMIN_PASSWORD_FILE, as plain text.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Fix.Steps) != 2 || !strings.Contains(c.Fix.Steps[1], "delete the file") {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "weak", set: func(f *Facts) { f.Admin.WeakHash = true }, state: Attention},
	})
}

func TestBuiltinUse(t *testing.T) {
	last := now.Add(-2 * time.Hour)
	old := now.AddDate(0, 0, -30)
	runCases(t, "accounts.builtin_use", []checkCase{
		{name: "only builtin", state: Good, line: "Only the built-in admin signs in so far.",
			fix: func(t *testing.T, c *Check) {
				if c.Tip == nil || c.Tip.Page == nil || c.Tip.Page.ID != "users" {
					t.Errorf("%+v", c.Tip)
				}
			}},
		{name: "used daily", set: func(f *Facts) { f.Users.OtherAdmins = 2; f.Users.BuiltinLastSignIn = &last }, state: Attention,
			line: "The built-in admin signed in 2 hours ago, though 2 people have admin accounts of their own. Keep it for emergencies."},
		{name: "others", set: func(f *Facts) { f.Users.OtherAdmins = 1; f.Users.Others = 3; f.Users.BuiltinLastSignIn = &old }, state: Good,
			line: "People sign in with their own accounts. The built-in admin last signed in 30 days ago."},
		{name: "never", set: func(f *Facts) { f.Users.Others = 3 }, state: Good,
			line: "People sign in with their own accounts. The built-in admin has never signed in."},
	})
}

func TestTempPasswords(t *testing.T) {
	runCases(t, "accounts.temp_passwords", []checkCase{
		{name: "no local users", state: ""},
		{name: "good", set: func(f *Facts) { f.Users.Local = true }, state: Good, line: "Nobody is left on a temporary password."},
		{name: "stale", set: func(f *Facts) { f.Users.Local = true; f.Users.StaleTemporary = []string{"bob", "carol"} }, state: Attention,
			line: "2 people haven't changed the temporary password they were given over a week ago: bob and carol."},
	})
}

func TestUserFactsFrom(t *testing.T) {
	st := users.NewMemory()
	st.Now = func() time.Time { return now.AddDate(0, 0, -10) }
	mk := func(name string, role users.Role, must bool) {
		if _, err := st.Create(users.NewUser{Username: name, Role: role, Password: "a-long-password-1", MustChangePassword: must}); err != nil {
			t.Fatal(err)
		}
	}
	mk("alice", users.Admin, false)
	mk("bob", users.Viewer, true)
	st.Now = func() time.Time { return now }
	mk("carol", users.Viewer, true)
	u := UserFactsFrom(st, "admin", now)
	if !u.Local || u.OtherAdmins != 1 || u.Others != 2 || len(u.StaleTemporary) != 1 || u.StaleTemporary[0] != "bob" {
		t.Errorf("%+v", u)
	}
}

func TestDirectory(t *testing.T) {
	on := true
	dir := func(url string) func(f *Facts) {
		return func(f *Facts) {
			f.Directory = &users.LDAPSettings{Enabled: &on, URL: url, DefaultRole: "viewer"}
		}
	}
	runCases(t, "accounts.directory", []checkCase{
		{name: "off", state: ""},
		{name: "ldaps", set: dir("ldaps://dc1.corp.local:636"), state: Good,
			line: "Directory sign-in uses LDAPS to dc1.corp.local and checks its certificate.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "starttls", set: func(f *Facts) { dir("ldap://dc1.corp.local")(f); f.Directory.StartTLS = true }, state: Good,
			line: "Directory sign-in uses StartTLS to dc1.corp.local and checks its certificate."},
		{name: "plain", set: dir("ldap://dc1.corp.local"), state: Risk,
			line: "Directory passwords cross the network to dc1.corp.local unencrypted: the address is ldap:// without StartTLS.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Page == nil || c.Fix.Page.Tab != "directory" {
					t.Errorf("%+v", c.Fix.Page)
				}
			}},
		{name: "failover plain", set: func(f *Facts) { dir("ldaps://dc1.corp.local")(f); f.Directory.FailoverURL = "ldap://dc2.corp.local" }, state: Risk},
		{name: "skip verify", set: func(f *Facts) { dir("ldaps://dc1.corp.local")(f); f.Directory.TLSSkipVerify = true }, state: Risk,
			line: "Signalith doesn't check the directory server's certificate, so someone on the network could pose as it and collect passwords."},
	})
}

func TestSessions(t *testing.T) {
	runCases(t, "accounts.sessions", []checkCase{
		// Keep me signed in skips the idle limit (see auth.Sessions).
		{name: "default", state: Good, line: "People are signed out after 12 hours without use, unless they choose Keep me signed in, which keeps them signed in for up to 7 days."},
		{name: "long", set: func(f *Facts) { f.Config.Auth.SessionTimeout = "3d" }, state: Attention, line: "People stay signed in for up to 3 days without using Signalith.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "auth.session_timeout" {
					t.Errorf("%+v", c.Fix)
				}
			}},
	})
}

func TestAgentTokens(t *testing.T) {
	runCases(t, "accounts.agent_tokens", []checkCase{
		{name: "none", state: ""},
		{name: "good", extra: "ingest:\n  tokens: [" + sentinelToken + "]\n", state: Good, line: "Agents send with tokens of 24 characters or more.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "public", extra: "ingest:\n  tokens: [change-this-ingest-token]\n", state: Risk,
			line: "Agents can send events with change-this-ingest-token, an example token anyone can look up.",
			fix: func(t *testing.T, c *Check) {
				if !strings.HasPrefix(c.Fix.Commands["linux"], "sudo signalith secrets set ingest.tokens"+tempConfigArg) {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},
		// A Docker quick start upgraded from a version whose agents send
		// the old example token accepts it over plain HTTP while agents on
		// plain HTTP are (see api.retiredTokenAccepted), whatever tokens
		// are set.
		{name: "public token accepted", extra: "ingest:\n  tokens: [" + sentinelToken + "]\n", set: func(f *Facts) {
			f.Config = f.Config.WithDockerUpgrade(&config.DockerUpgrade{Upgraded: true, Index: "signalith-authentication-2026.09.30",
				IndexMade: time.Date(2026, 9, 30, 0, 4, 0, 0, time.UTC), Decided: now})
			f.InContainer, f.Docker, f.PublicTokenAccepted = true, true, true
		}, state: Risk, line: "Agents can still send events over plain HTTP with change-this-ingest-token, an example token anyone can look up.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Setting != "server.tls.plaintext_ingest" || c.Fix.Page == nil || c.Fix.Page.ID != "data" {
					t.Errorf("%+v", c.Fix)
				}
				if len(c.Details) != 2 || !strings.Contains(c.Details[0], "upgraded from an older version") || !strings.Contains(c.Details[0], "the oldest from 30 Sep 2026") ||
					!strings.Contains(c.Details[1], "ends it for good") {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "public token accepted, no tokens", set: func(f *Facts) { f.PublicTokenAccepted = true }, state: Risk},
		// Elsewhere on the Docker quick start, the check says why the old
		// token is refused.
		{name: "quick start installed new", extra: "ingest:\n  tokens: [" + sentinelToken + "]\n", set: func(f *Facts) {
			f.Config = f.Config.WithDockerUpgrade(&config.DockerUpgrade{Decided: now})
			f.InContainer, f.Docker = true, true
		}, state: Good, fix: func(t *testing.T, c *Check) {
			if len(c.Details) != 2 || !strings.Contains(c.Details[1], "change-this-ingest-token, is refused: this install started new") {
				t.Errorf("%q", c.Details)
			}
		}},
		{name: "quick start not decided yet", extra: "ingest:\n  tokens: [" + sentinelToken + "]\n", set: func(f *Facts) {
			f.Config = f.Config.WithDockerUpgrade(nil)
			f.InContainer, f.Docker = true, true
		}, state: Good, fix: func(t *testing.T, c *Check) {
			if len(c.Details) != 2 || !strings.Contains(c.Details[1], "is refused for now") || !strings.Contains(c.Details[1], "keep their events") {
				t.Errorf("%q", c.Details)
			}
		}},
		{name: "upgraded quick start, ended", extra: "ingest:\n  tokens: [" + sentinelToken + "]\n", set: func(f *Facts) {
			f.Config = f.Config.WithDockerUpgrade(&config.DockerUpgrade{Upgraded: true, Decided: now, Ended: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)})
			f.InContainer, f.Docker = true, true
		}, state: Good, fix: func(t *testing.T, c *Check) {
			if len(c.Details) != 2 || !strings.Contains(c.Details[1], "is refused for good") || !strings.Contains(c.Details[1], "since 2 Oct 2026") {
				t.Errorf("%q", c.Details)
			}
		}},
		{name: "short", extra: "ingest:\n  tokens: [SENTINEL-short-tok20]\n", state: Attention,
			line: "An agent token is only 20 characters long, so it's easier to guess. Tokens Signalith makes have 48."},
	})
}

func TestOpenSearchRole(t *testing.T) {
	runCases(t, "accounts.opensearch_role", []checkCase{
		{name: "good", state: Good, line: "Signalith signs in to OpenSearch as signalith, an account without admin rights."},
		{name: "open", set: func(f *Facts) { f.OpenSearch.Anonymous = "open" }, state: ""},
		{name: "no plugin", set: func(f *Facts) { f.OpenSearch.AuthNoPlugin = true }, state: ""},
		{name: "demo admin", set: func(f *Facts) { f.OpenSearch.DemoAdmin = true }, state: Risk,
			line: "Signalith signs in to OpenSearch as admin with the password admin, which anyone can look up."},
		{name: "all access", set: func(f *Facts) {
			f.OpenSearch.AuthUser = "admin"
			f.OpenSearch.AuthRoles = []string{"all_access", "own_index"}
		}, state: Attention,
			line: "Signalith signs in to OpenSearch as admin, which can do anything there. If its password or key leaked, so would all of OpenSearch."},
		{name: "admin backend role", set: func(f *Facts) { f.OpenSearch.AuthBackend = []string{"admin"} }, state: Attention},
		{name: "failed", set: func(f *Facts) { f.OpenSearch.AuthErr = "no answer in time" }, state: Unknown,
			line: "Signalith couldn't ask OpenSearch what its account may do."},
		{name: "unreachable", set: func(f *Facts) { f.OpenSearch.AuthErr = "connection refused" }, state: Unknown,
			fix: func(t *testing.T, c *Check) {
				if c.Details[0] != "Signalith couldn't reach OpenSearch: connection refused." || !strings.Contains(c.Fix.Steps[0], "Health page") {
					t.Errorf("%q %+v", c.Details, c.Fix)
				}
			}},
		{name: "refused", set: func(f *Facts) { f.OpenSearch.AuthErr = "status 403" }, state: Unknown,
			fix: func(t *testing.T, c *Check) {
				if c.Details[0] != "OpenSearch answered: status 403." || !strings.Contains(c.Fix.Steps[0], "roles mapped") {
					t.Errorf("%q %+v", c.Details, c.Fix)
				}
			}},
	})
}

func TestAccount(t *testing.T) {
	runCases(t, "host.account", []checkCase{
		{name: "own account", state: Good, line: "Signalith runs as its own account (signalith), not as root."},
		{name: "root", set: func(f *Facts) { f.Process.Root, f.Process.UID = true, 0 }, state: Attention,
			line: "Signalith runs as root, so a flaw in it could reach the whole computer.",
			fix: func(t *testing.T, c *Check) {
				if !strings.Contains(c.Fix.Commands["linux"], "useradd --system") || c.Fix.Docs.File != "README.md" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "root in container", set: func(f *Facts) { f.Process.Root = true; f.InContainer = true }, state: Attention, line: "Signalith runs as root inside its container."},
		{name: "container", set: func(f *Facts) { f.Process.UID = 65532; f.InContainer = true }, state: Good,
			line: "Signalith runs as an unprivileged account (uid 65532) in its container."},
		{name: "local system", set: func(f *Facts) { f.Server.OS = "windows"; f.Process = ProcessFacts{Known: true, SID: "S-1-5-18"} }, state: Attention,
			line: "Signalith runs as Local System, the most powerful account on Windows."},
		{name: "admin", set: func(f *Facts) {
			f.Server.OS = "windows"
			f.Process = ProcessFacts{Known: true, SID: "S-1-5-21-1-2-3-1001", UserName: `PC\alice`, Elevated: true}
		}, state: Attention, line: `Signalith runs as PC\alice, an administrator.`},
		{name: "admin unknown", set: func(f *Facts) {
			f.Server.OS = "windows"
			f.Process = ProcessFacts{Known: true, SID: "S-1-5-21-1-2-3-1001", UserName: `CORP\svc-siem`, AdminUnknown: true}
		}, state: Unknown, line: `Signalith runs as CORP\svc-siem. Signalith couldn't tell whether that account is an administrator.`,
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Commands["windows"] != "net localgroup Administrators" {
					t.Errorf("%+v", c.Fix)
				}
			}},
		{name: "not admin", set: func(f *Facts) {
			f.Server.OS = "windows"
			f.Process = ProcessFacts{Known: true, SID: "S-1-5-21-1-2-3-1001", UserName: `PC\svc`}
		}, state: Good, line: `Signalith runs as PC\svc, without administrator rights.`},
		{name: "service sid", set: func(f *Facts) {
			f.Server.OS = "windows"
			f.Process = ProcessFacts{Known: true, SID: "S-1-5-80-1-2-3-4-5", Service: true}
		},
			state: Good, line: `Signalith runs as its own service account (NT SERVICE\Signalith).`},
		{name: "not running", set: func(f *Facts) {
			f.Process = ProcessFacts{Why: NoServiceLine}
		}, state: Unknown},
	})
}

func TestService(t *testing.T) {
	runCases(t, "host.service", []checkCase{
		{name: "systemd", state: Good, line: "Signalith's service runs with all the protections its systemd unit sets up."},
		{name: "windows", set: func(f *Facts) { f.Server.OS = "windows" }, state: ""},
		{name: "by hand", set: func(f *Facts) { f.Process.Systemd = false }, state: Attention,
			line: "Signalith isn't running as a systemd service, so it lacks the protections the service adds."},
		{name: "missing", set: func(f *Facts) { f.Process.Seccomp, f.Process.HiddenProc = false, false }, state: Attention,
			line: "Signalith's service is missing protections its current systemd unit sets up: a system-call filter and hidden processes.",
			fix: func(t *testing.T, c *Check) {
				if !strings.Contains(c.Fix.Commands["linux"], "systemd-analyze security signalith") {
					t.Errorf("%q", c.Fix.Commands)
				}
			}},

		// Linux before 5.8 can't hide other processes: not a missing protection.
		{name: "old kernel", set: func(f *Facts) { f.Process.HiddenProc, f.Process.NoHiddenProc = false, true }, state: Good,
			line: "Signalith's service runs with all the protections its systemd unit sets up.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "Hidden processes: not available on this Linux version." {
					t.Errorf("%q", c.Details)
				}
			}},
		{name: "old kernel, missing", set: func(f *Facts) { f.Process.HiddenProc, f.Process.NoHiddenProc, f.Process.Seccomp = false, true, false }, state: Attention,
			line: "Signalith's service is missing protections its current systemd unit sets up: a system-call filter."},
		{name: "container", set: func(f *Facts) { f.InContainer = true; f.Process.NoCapsAtAll = true }, state: Good,
			line: "Signalith's container runs read-only, without extra privileges or capabilities."},
		{name: "container missing", set: func(f *Facts) { f.InContainer = true; f.Process.ReadOnlyRoot = false }, state: Attention,
			line: "Signalith's container is missing protections from the quick start: no capabilities and a read-only system."},
	})
}

func TestFiles(t *testing.T) {
	runCases(t, "host.files", []checkCase{
		{name: "good", state: Good, line: "Signalith's keys and private files can only be read by its own account."},
		{name: "windows", set: func(f *Facts) { f.Files.Admins = true }, state: Good,
			line: "Signalith's keys and private files can only be read by its own account and administrators."},
		{name: "key for all", set: func(f *Facts) {
			f.Files.Problems = []FileProblem{
				{Path: "/var/lib/signalith/tls/ca.key", Kind: "key", Read: true, Everyone: true},
				{Path: "/var/lib/signalith/lookups/users.json", Kind: "private", Read: true, Group: "staff"},
			}
		}, state: Risk, line: "Any account on this computer can read /var/lib/signalith/tls/ca.key.",
			fix: func(t *testing.T, c *Check) {
				if len(c.Details) != 1 || c.Details[0] != "The staff group can read /var/lib/signalith/lookups/users.json." {
					t.Errorf("%q", c.Details)
				}
				if c.Fix.Commands["linux"] != "sudo chmod go-rwx /var/lib/signalith/tls/ca.key\nsudo chmod go-rwx /var/lib/signalith/lookups/users.json" {
					t.Errorf("%q", c.Fix.Commands["linux"])
				}
			}},
		{name: "config writable", set: func(f *Facts) {
			f.Files.Problems = []FileProblem{{Path: "/etc/signalith/signalith.yaml", Kind: "config", Write: true, Everyone: true}}
		}, state: Risk, line: "Any account on this computer can change /etc/signalith/signalith.yaml.",
			fix: func(t *testing.T, c *Check) {
				if c.Fix.Commands["linux"] != "sudo chmod go-w /etc/signalith/signalith.yaml" {
					t.Errorf("%q", c.Fix.Commands["linux"])
				}
			}},
		{name: "private", set: func(f *Facts) {
			f.Files.Problems = []FileProblem{{Path: "/var/lib/signalith/lookups/users.json", Kind: "private", Read: true, Group: "staff"}}
		}, state: Attention, line: "Other accounts can read one of Signalith's private files: users.json."},
		{name: "folder", set: func(f *Facts) {
			f.Files.Problems = []FileProblem{{Path: "/var/lib/signalith", Kind: "folder", Write: true, Group: "staff"}}
		}, state: Attention, line: "Other accounts can change /var/lib/signalith."},
		{name: "network", set: func(f *Facts) { f.Files.NetworkState = "NFS" }, state: Attention,
			line: "Signalith's state folder is on a network share (NFS), so its keys cross the network each time they're read."},
		{name: "path with a quote", set: func(f *Facts) {
			f.Files.Problems = []FileProblem{{Path: "/srv/it's here/ca.key", Kind: "key", Read: true, Everyone: true}}
		}, state: Risk, fix: func(t *testing.T, c *Check) {
			// This server's paths: no Windows command for a Linux one.
			if c.Fix.Commands["linux"] != `sudo chmod go-rwx '/srv/it'\''s here/ca.key'` || len(c.Fix.Commands) != 1 {
				t.Errorf("%q", c.Fix.Commands)
			}
		}},
		{name: "windows path with a quote", set: func(f *Facts) {
			f.Server.OS, f.Server.Deployment = "windows", DeployWindowsService
			f.Files.Problems = []FileProblem{{Path: `C:\Signalith's\tls\ca.key`, Kind: "key", Read: true, Everyone: true}}
		}, state: Risk, fix: func(t *testing.T, c *Check) {
			if !strings.HasPrefix(c.Fix.Commands["windows"], `icacls 'C:\Signalith''s\tls\ca.key'`) || len(c.Fix.Commands) != 1 {
				t.Errorf("%q", c.Fix.Commands)
			}
		}},
	})
}

// TestEveryCheckHasCases makes sure each check is tested here.
func TestEveryCheckHasCases(t *testing.T) {
	src, err := os.ReadFile("checks_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range CheckIDs() {
		if !strings.Contains(string(src), `"`+id+`"`) {
			t.Errorf("no cases for %s", id)
		}
	}
}

// The strict tip names this server's own names first: localhost and the
// loopback addresses are in every certificate authority.
func TestOwnNamesFirst(t *testing.T) {
	got := ownNamesFirst([]string{"localhost", "127.0.0.1", "::1", "siem-1", "10.0.0.12"})
	if strings.Join(got, ",") != "siem-1,10.0.0.12,localhost,127.0.0.1,::1" {
		t.Error(got)
	}
}

func TestLeafFactsNoName(t *testing.T) {
	for _, c := range []struct {
		dns  []string
		want bool
	}{{nil, true}, {[]string{"localhost", "*.corp.example"}, true}, {[]string{"localhost", "siem.corp.example"}, false}} {
		if got := leafFacts(&x509.Certificate{DNSNames: c.dns}).NoName; got != c.want {
			t.Errorf("%q: NoName %v, want %v", c.dns, got, c.want)
		}
	}
}
