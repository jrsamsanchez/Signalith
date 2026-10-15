// Package opensearchcheck checks, from one machine, that Signalith can use
// an OpenSearch the way a server of a cluster must: it answers, its
// certificate is valid for its name, it takes Signalith's sign-in, it has
// security turned on, and this machine's clock agrees with it. Each
// finding says in plain words what to fix. signalith join runs it before
// it writes anything, and signalith opensearch-check on its own.
package opensearchcheck

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Finding is one check: OK, what was checked (or found), and when it
// failed, what to do.
type Finding struct {
	OK   bool   `json:"ok"`
	What string `json:"what"`
	Fix  string `json:"fix,omitempty"`
}

// MaxClockOffset is how far this machine's clock may be off OpenSearch's.
const MaxClockOffset = 2 * time.Second

// Failed reports whether any finding failed.
func Failed(fs []Finding) bool {
	for _, f := range fs {
		if !f.OK {
			return true
		}
	}
	return false
}

// Check checks the OpenSearch cfg names, from this machine. It stops at
// the first check the others depend on (an answer, a trusted certificate,
// an accepted sign-in).
func Check(ctx context.Context, cfg store.Config) []Finding {
	return check(ctx, cfg, time.Now)
}

func check(ctx context.Context, cfg store.Config, now func() time.Time) []Finding {
	var out []Finding
	addr := redact.URL(cfg.URL)
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Hostname() == "" {
		return []Finding{{What: "The OpenSearch address " + addr + " cannot be read", Fix: "Give the address as https://host:9200."}}
	}
	https := strings.EqualFold(u.Scheme, "https")
	rep := store.Check(ctx, cfg)
	if !rep.Reached && !rep.OK {
		return append(out, Finding{What: "OpenSearch does not answer at " + addr, Fix: rep.Message +
			" A server of a cluster reaches OpenSearch over the network: on the OpenSearch machine, listen on an address the servers reach (network.host) and open TCP 9200 to them."})
	}
	switch rep.Problem {
	case "tls":
		return append(out, Finding{OK: true, What: "OpenSearch answers at " + addr},
			Finding{What: "OpenSearch's certificate is not trusted for " + u.Hostname(), Fix: rep.Message})
	case "http":
		return append(out, Finding{OK: true, What: "Something answers at " + addr}, Finding{What: "HTTPS does not match", Fix: rep.Message})
	}
	out = append(out, Finding{OK: true, What: "OpenSearch answers at " + addr})
	if https {
		if cfg.TLSSkipVerify {
			out = append(out, Finding{What: "OpenSearch's certificate is not checked (tls_skip_verify)",
				Fix: "Give the certificate authority of OpenSearch's certificate (opensearch.ca_file) and turn Skip certificate check off."})
		} else {
			out = append(out, Finding{OK: true, What: "OpenSearch's certificate is valid for " + u.Hostname()})
		}
	} else {
		out = append(out, Finding{What: "OpenSearch is reached over plain http",
			Fix: "Several servers need OpenSearch with security turned on, over https. See Add a server → Prepare OpenSearch."})
	}
	switch rep.Problem {
	case "auth", "forbidden":
		return append(out, Finding{What: "OpenSearch refused Signalith's sign-in", Fix: rep.Message})
	case "":
	default:
		return append(out, Finding{What: "OpenSearch did not answer as it should", Fix: rep.Message})
	}
	signsIn := cfg.Username != "" || cfg.CertFile != ""
	switch secured, err := securityOn(ctx, cfg); {
	case err != nil:
		out = append(out, Finding{What: "Whether OpenSearch has security turned on could not be read", Fix: err.Error()})
	case !secured:
		out = append(out, Finding{What: "OpenSearch lets anyone in: its security plugin is off",
			Fix: "Several servers need OpenSearch with security turned on. See Add a server → Prepare OpenSearch."})
	case !signsIn:
		out = append(out, Finding{What: "Signalith has no OpenSearch user or client certificate", Fix: "Give OpenSearch's user name and password, or a client certificate."})
	default:
		out = append(out, Finding{OK: true, What: "OpenSearch accepts Signalith's sign-in"})
	}
	off, err := clockOffset(ctx, cfg, now)
	switch {
	case err != nil:
		out = append(out, Finding{What: "OpenSearch's clock could not be read", Fix: err.Error()})
	case off > MaxClockOffset || off < -MaxClockOffset:
		out = append(out, Finding{What: fmt.Sprintf("This machine's clock is %s off OpenSearch's", off.Round(time.Millisecond)),
			Fix: "Keep the clocks in sync with NTP (Linux: timedatectl set-ntp true; Windows: w32tm /resync)."})
	default:
		out = append(out, Finding{OK: true, What: "This machine's clock agrees with OpenSearch's"})
	}
	return out
}

// securityOn reports whether OpenSearch's security plugin is on: its
// authinfo route answers. Without the plugin there is no such route.
func securityOn(ctx context.Context, cfg store.Config) (bool, error) {
	c := store.New(cfg)
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, store.CheckTimeout)
	defer cancel()
	var out map[string]any
	err := c.Do(ctx, http.MethodGet, "/_plugins/_security/authinfo", nil, &out)
	var se *store.Error
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &se) && (se.Status == http.StatusBadRequest || se.Status == http.StatusNotFound):
		return false, nil
	case errors.As(err, &se) && (se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden):
		// It asked for a sign-in, so it has security.
		return true, nil
	}
	return false, err
}

// clockOffset is OpenSearch's time minus this machine's at the middle of
// the request.
func clockOffset(ctx context.Context, cfg store.Config, now func() time.Time) (time.Duration, error) {
	c := store.New(cfg)
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, store.CheckTimeout)
	defer cancel()
	var out struct {
		Nodes map[string]struct {
			OS struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"os"`
		} `json:"nodes"`
	}
	t0 := now()
	err := c.Do(ctx, http.MethodGet, "/_nodes/_local/stats/os?filter_path=nodes.*.os.timestamp", nil, &out)
	t1 := now()
	if err != nil {
		return 0, err
	}
	for _, n := range out.Nodes {
		if n.OS.Timestamp != 0 {
			return time.UnixMilli(n.OS.Timestamp).Sub(t0.Add(t1.Sub(t0) / 2)), nil
		}
	}
	return 0, errors.New("OpenSearch did not say its time")
}
