package tenants_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/ticketing"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// match is OpenSearch's index wildcard matching: * matches any run of
// characters, everything else itself.
func match(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(name, p)
		if i < 0 {
			return false
		}
		name = name[i+len(p):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1])
}

// indexNames are the index names Signalith makes under prefix p, from the
// packages that make them.
func indexNames(p string) []string {
	day := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	names := []string{
		findings.NewOpenSearch(nil, p).Index, cases.NewOpenSearch(nil, p).Index, intel.NewOpenSearch(nil, p).Index,
		respond.NewOpenSearch(nil, p).Index, playbooks.NewOpenSearch(nil, p).Index, notify.NewOpenSearch(nil, p).Index,
		endpoint.NewStore(nil, p).Index, vulnscan.NewStore(nil, p).Index, ticketing.NewOpenSearch(nil, p).Index,
		cluster.RuntimeIndex(p), shared.ConfigIndex(p), shared.SessionsIndex(p), shared.RetiredConfigIndex(p, "20261016"),
		audit.IndexName(p, day), retention.RecordIndex(p, "findings"),
	}
	for _, m := range datamodel.Models {
		names = append(names, datamodel.IndexName(p, m.Name, "2026.10.16"))
	}
	return append(names, datamodel.IndexName(p, datamodel.RiskModel, "2026.10.16"))
}

// patterns are the wildcard patterns Signalith builds from prefix p, and
// the widest a search's index= may name.
func patterns(t *testing.T, p string) []string {
	out := []string{
		p + "-*", p + "_*", // retention's and the OpenSearch card's lists
		audit.Pattern(p), shared.RetiredConfigPattern(p), assets.DiscoveryIndex(p),
	}
	for _, v := range ingest.IndexTemplate(p, nil)["index_patterns"].([]string) {
		out = append(out, v)
	}
	e := &search.Engine{Opt: search.Options{IndexPrefix: p}}
	for _, q := range []string{"", "datamodel=Authentication", "index=*", "index=" + p + "-*", "index=" + p + "-*-*"} {
		parsed := &query.Query{}
		if q != "" {
			k, v, _ := strings.Cut(q, "=")
			if k == "index" {
				parsed.Index = v
			} else {
				parsed.Datamodel = v
			}
		}
		pat, err := e.IndexPattern(parsed)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for _, one := range strings.Split(pat, ",") {
			if !strings.HasPrefix(one, "-") {
				out = append(out, one)
			}
		}
	}
	return out
}

// TestNoPatternReachesAnotherTenant is the property the index names rest
// on: no pattern of one tenant, default or not, matches an index of
// another, even when one ID starts with the other.
func TestNoPatternReachesAnotherTenant(t *testing.T) {
	ids := []string{tenants.Default, "ac", "acme", "acmex", "acme2", "acmeacme", "tacme", "t1"}
	for _, base := range []string{"signalith", "siem", "a-b", "x_y", "x.t", "x.", "a-"} {
		for _, a := range ids {
			for _, b := range ids {
				if a == b {
					continue
				}
				for _, pat := range patterns(t, tenants.Prefix(base, a)) {
					for _, name := range indexNames(tenants.Prefix(base, b)) {
						if match(pat, name) {
							t.Errorf("prefix %q: tenant %q's pattern %q matches tenant %q's index %q", base, a, pat, b, name)
						}
					}
				}
			}
			// Each tenant's own patterns do reach its own indices.
			if own := tenants.Prefix(base, a); !match(own+"-*", datamodel.IndexName(own, "Authentication", "2026.10.16")) {
				t.Errorf("tenant %q cannot reach its own events", a)
			}
		}
	}
}

// TestSearchRefusesOtherTenants: index= naming another tenant's events
// is refused.
func TestSearchRefusesOtherTenants(t *testing.T) {
	e := &search.Engine{Opt: search.Options{IndexPrefix: tenants.Prefix("signalith", "acme")}}
	for _, v := range []string{"signalith-*", "signalith-authentication-*", "signalith.t.acmex-*", "signalith.t.ac-*", "signalith_findings", "signalith.t.acme_findings"} {
		if p, err := e.IndexPattern(&query.Query{Index: v}); err == nil {
			t.Errorf("index=%s was accepted as %s", v, p)
		}
	}
}

// indexPackages are the packages that name OpenSearch indices; fieldPaths
// are their files that join field names, not index names, with ".".
var (
	indexPackages = []string{
		"agentinv", "agenttokens", "assets", "audit", "cases", "cluster", "clusterarchive", "clusterauth", "clustercfg",
		"datamodel", "endpoint", "findings", "intel", "notify", "playbooks", "respond", "retention", "risk",
		"sample", "security", "sensortune", "shared", "vulnscan",
	}
	extraFiles = []string{"../search/engine.go", "../ingest/template.go", "../ingest/ingest.go", "../api/cluster_opensearch.go"}
	fieldPaths = map[string]bool{"../search/engine.go:prefix+\".\"": true}
)

// TestIndexNamesKeepTheirPrefix scans the code that names indices: an
// index prefix may only be followed by "-" or "_" (or Infix, in
// tenants.Prefix), so no index name or pattern can run into a tenant's.
func TestIndexNamesKeepTheirPrefix(t *testing.T) {
	var files []string
	for _, pkg := range indexPackages {
		m, _ := filepath.Glob(filepath.Join("..", pkg, "*.go"))
		files = append(files, m...)
	}
	files = append(files, extraFiles...)
	checked := 0
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			b, ok := n.(*ast.BinaryExpr)
			if !ok || b.Op != token.ADD || !isPrefix(b.X) {
				return true
			}
			lit, ok := b.Y.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, _ := strconv.Unquote(lit.Value)
			checked++
			if strings.HasPrefix(v, "-") || strings.HasPrefix(v, "_") {
				return true
			}
			key := filepath.ToSlash(name) + ":prefix+" + lit.Value
			if !fieldPaths[key] {
				t.Errorf("%s: an index prefix is followed by %s; index names must go on with \"-\" or \"_\"", fset.Position(b.Pos()), lit.Value)
			}
			return true
		})
	}
	if checked < 25 {
		t.Errorf("checked only %d prefix joins; is the scan still working?", checked)
	}
}

// isPrefix reports whether e is an index prefix: a variable or field
// named prefix, Prefix or IndexPrefix.
func isPrefix(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "prefix" || v.Name == "Prefix"
	case *ast.SelectorExpr:
		return v.Sel.Name == "Prefix" || v.Sel.Name == "IndexPrefix"
	}
	return false
}
