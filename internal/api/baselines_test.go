package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/baselines"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The page reads every check with its counts, saves settings and
// exceptions over the version it read, and asks for a reset.
func TestBaselinesPage(t *testing.T) {
	srv := ostest.New(t)
	st := baselines.NewStore(store.New(store.Config{URL: srv.URL}), "t")
	if err := st.EnsureIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Baselines = st })
	code, out, raw := call(t, ts, "GET", "/api/baselines", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("get %d %s", code, raw)
	}
	checks := out["checks"].([]any)
	if len(checks) != len(baselines.Checks) {
		t.Fatalf("%d checks", len(checks))
	}
	first := checks[0].(map[string]any)
	if first["id"] != baselines.NewCountry || first["on"] != true || first["score"].(float64) != 40 ||
		!strings.Contains(first["waiting"].(string), "IP database") {
		t.Errorf("check %v", first)
	}
	version := out["version"].(string)
	body := `{"version":"` + version + `","settings":{"learning_days":21,"checks":{"unusual-hour":{"off":true},"new-country":{"score":60}},` +
		`"exceptions":[{"id":"ex-made-up","match":{"baseline":"new-country","src_country":" CA ","risk_object":""},"comment":" travel "}]}}`
	code, out, raw = call(t, ts, "PUT", "/api/baselines", body, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("put %d %s", code, raw)
	}
	set, _, _ := st.Settings(context.Background())
	if set.LearningDays != 21 || set.On(baselines.UnusualHour) || set.Score(baselines.NewCountry) != 60 {
		t.Errorf("saved %+v", set)
	}
	ex := set.Exceptions[0]
	if ex.ID == "ex-made-up" || ex.By != "admin" || ex.Added.IsZero() || ex.Match["src_country"] != "CA" || len(ex.Match) != 2 || ex.Comment != "travel" {
		t.Errorf("exception %+v", ex)
	}
	// The old version is refused.
	if code, _, _ = call(t, ts, "PUT", "/api/baselines", body, "admin", "s3cret-pass", nil); code != 409 {
		t.Errorf("stale version: %d", code)
	}
	version = out["version"].(string)
	bad := `{"version":"` + version + `","settings":{"learning_days":400,"ip_database":"ftp://x/y.gz"}}`
	if code, _, raw = call(t, ts, "PUT", "/api/baselines", bad, "admin", "s3cret-pass", nil); code != 400 || !strings.Contains(raw, "learning period") {
		t.Errorf("bad settings: %d %s", code, raw)
	}
	// A save keeps a saved exception's author and time.
	keep := `{"version":"` + version + `","settings":{"exceptions":[{"id":"` + ex.ID + `","by":"mallory","match":{"src_country":"CA"}}]}}`
	if code, _, raw = call(t, ts, "PUT", "/api/baselines", keep, "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("keep %d %s", code, raw)
	}
	set, _, _ = st.Settings(context.Background())
	if got := set.Exceptions[0]; got.ID != ex.ID || got.By != "admin" || !got.Added.Equal(ex.Added) {
		t.Errorf("kept %+v", got)
	}
	if code, _, _ = call(t, ts, "POST", "/api/baselines/nope/reset", "", "admin", "s3cret-pass", nil); code != 404 {
		t.Errorf("unknown check: %d", code)
	}
	if code, _, raw = call(t, ts, "POST", "/api/baselines/rare-process/reset", "", "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("reset %d %s", code, raw)
	}
	set, _, _ = st.Settings(context.Background())
	if set.Checks[baselines.RareProcess].ResetAt.IsZero() {
		t.Error("reset not asked for")
	}
	// A save cannot ask for a reset, nor drop one asked for.
	_, out, _ = call(t, ts, "GET", "/api/baselines", "", "admin", "s3cret-pass", nil)
	version = out["version"].(string)
	sneak := `{"version":"` + version + `","settings":{"checks":{"new-change":{"reset_at":"2030-01-01T00:00:00Z"}}}}`
	if code, _, raw = call(t, ts, "PUT", "/api/baselines", sneak, "admin", "s3cret-pass", nil); code != 200 {
		t.Fatalf("sneak %d %s", code, raw)
	}
	set, _, _ = st.Settings(context.Background())
	if !set.Checks[baselines.NewChange].ResetAt.IsZero() || set.Checks[baselines.RareProcess].ResetAt.IsZero() {
		t.Errorf("resets %+v", set.Checks)
	}
}

// A tenant's baselines are its own: its admins read and change its
// settings only, and may not change where the IP database is fetched
// from, which the provider's admins may.
func TestTenantBaselines(t *testing.T) {
	opensearch := ostest.New(t)
	cl := store.New(store.Config{URL: opensearch.URL})
	ctx := context.Background()
	mine, theirs := baselines.NewStore(cl, "t"), baselines.NewStore(cl, tenants.Prefix("t", "acme"))
	for _, st := range []*baselines.Store{mine, theirs} {
		if err := st.EnsureIndex(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reg, _ := tenants.Open(tenants.File(t.TempDir()))
	reg.Add("acme", "Acme", "test", time.Now())
	people := users.NewMemory()
	for _, u := range []users.NewUser{
		{Username: "ada", Role: users.Admin, Tenant: "acme"},
		{Username: "pat", Role: users.Admin},
	} {
		u.Password = "role-password"
		people.Create(ctx, u)
	}
	var acme *Server
	newTestServerWith(t, func(s *Server) {
		acme = s
		s.Tenants, s.Users, s.TenantID, s.Baselines = reg, people, "acme", theirs
	})
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Tenants, s.Users, s.Baselines = reg, people, mine
		s.TenantRuntime = oneTenant{acme}
	})
	save := func(user, settings string) (int, map[string]any) {
		t.Helper()
		_, view := doAs(t, ts, user, "role-password", "GET", "/api/baselines", "")
		return doAs(t, ts, user, "role-password", "PUT", "/api/baselines", `{"version":"`+view["version"].(string)+`","settings":`+settings+`}`)
	}
	if code, view := doAs(t, ts, "ada", "role-password", "GET", "/api/baselines", ""); code != 200 || view["ip_database_fixed"] != true {
		t.Fatalf("acme's admin reads %d %v", code, view)
	}
	if code, body := save("ada", `{"learning_days":21}`); code != 200 {
		t.Fatalf("acme's admin saves %d %v", code, body)
	}
	if set, _, _ := theirs.Settings(ctx); set.LearningDays != 21 {
		t.Errorf("acme's settings %+v", set)
	}
	if set, _, _ := mine.Settings(ctx); set.LearningDays != 0 {
		t.Errorf("acme's admin changed the default tenant's settings: %+v", set)
	}
	for _, src := range []string{"https://mirror.example/ip2asn.tsv.gz", "file:ip2asn.tsv", "off"} {
		if code, body := save("ada", `{"learning_days":21,"ip_database":"`+src+`"}`); code != 403 || body["code"] != "provider_only" {
			t.Errorf("acme's admin sets the IP database to %s: %d %v", src, code, body)
		}
	}
	if set, _, _ := theirs.Settings(ctx); set.IPDatabase != "" {
		t.Errorf("acme's IP database %q", set.IPDatabase)
	}
	// The provider's admin, in the default tenant: its own settings.
	if code, view := doAs(t, ts, "pat", "role-password", "GET", "/api/baselines", ""); code != 200 || view["ip_database_fixed"] != nil {
		t.Errorf("provider admin reads %d %v", code, view)
	}
	if code, body := save("pat", `{"ip_database":"off"}`); code != 200 {
		t.Errorf("provider admin turns the IP database off: %d %v", code, body)
	}
	if set, _, _ := mine.Settings(ctx); set.IPDatabase != "off" {
		t.Errorf("default tenant's IP database %q", set.IPDatabase)
	}
	if set, _, _ := theirs.Settings(ctx); set.IPDatabase != "" || set.LearningDays != 21 {
		t.Errorf("acme's settings after the provider's save %+v", set)
	}
}
