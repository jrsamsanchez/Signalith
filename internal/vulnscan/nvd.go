package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPE is a product name in the Common Platform Enumeration, the names
// Nmap and the National Vulnerability Database both use.
type CPE struct {
	Part    string // a (application), o (operating system) or h (hardware)
	Vendor  string
	Product string
	Version string
	Update  string
}

// ParseCPE reads a CPE in either form: cpe:/a:openbsd:openssh:7.4 (2.2,
// as Nmap writes it) or cpe:2.3:a:openbsd:openssh:7.4:*:… (2.3).
func ParseCPE(s string) (CPE, bool) {
	s = strings.TrimSpace(s)
	var f []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		f = splitCPE23(s[len("cpe:2.3:"):])
	case strings.HasPrefix(s, "cpe:/"):
		f = strings.Split(s[len("cpe:/"):], ":")
		for i := range f {
			if u, err := url.PathUnescape(f[i]); err == nil {
				f[i] = u
			}
		}
	default:
		return CPE{}, false
	}
	if len(f) < 3 || f[0] == "" || f[1] == "" || f[2] == "" {
		return CPE{}, false
	}
	c := CPE{Part: f[0], Vendor: strings.ToLower(f[1]), Product: strings.ToLower(f[2])}
	if len(f) > 3 {
		c.Version = f[3]
	}
	if len(f) > 4 {
		c.Update = f[4]
	}
	switch c.Part {
	case "a", "o", "h":
	default:
		return CPE{}, false
	}
	return c, true
}

// splitCPE23 splits on colons that are not escaped with a backslash, and
// removes the escapes.
func splitCPE23(s string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// Key names the product, without its version: a:openbsd:openssh.
func (c CPE) Key() string { return c.Part + ":" + c.Vendor + ":" + c.Product }

// FullVersion is the version with its update, as a version is written:
// 8.2 and p1 make 8.2p1.
func (c CPE) FullVersion() string {
	v := c.Version
	if v == "*" || v == "-" {
		v = ""
	}
	if u := c.Update; u != "" && u != "*" && u != "-" && v != "" {
		return v + u
	}
	return v
}

// String writes the CPE in the 2.3 form.
func (c CPE) String() string {
	v := c.Version
	if v == "" {
		v = "*"
	}
	u := c.Update
	if u == "" {
		u = "*"
	}
	return "cpe:2.3:" + c.Part + ":" + c.Vendor + ":" + c.Product + ":" + v + ":" + u + ":*:*:*:*:*:*"
}

// CVE is a known vulnerability, as kept for matching: only the version
// criteria of the one product it was looked up for.
type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	// CVSSVersion is the CVSS version of the score, such as 3.1.
	CVSSVersion string `json:"cvss_version,omitempty"`
	Severity    string `json:"severity"`
	Published   string `json:"published,omitempty"`
	// KEVAdded is when CISA added it to its Known Exploited
	// Vulnerabilities catalog: attackers are using it.
	KEVAdded string      `json:"kev_added,omitempty"`
	Criteria []Criterion `json:"criteria"`
}

// Criterion is one range of versions a CVE applies to.
type Criterion struct {
	Version    string `json:"v,omitempty"`
	Update     string `json:"u,omitempty"`
	StartIncl  string `json:"si,omitempty"`
	StartExcl  string `json:"se,omitempty"`
	EndIncl    string `json:"ei,omitempty"`
	EndExcl    string `json:"ee,omitempty"`
	Vulnerable bool   `json:"-"`
}

// Matches reports whether a version (with its update, such as 8.2p1) is
// in the criterion's range.
func (c Criterion) Matches(version string) bool {
	if version == "" {
		return false
	}
	if c.Version != "" && c.Version != "*" {
		if c.Version == "-" {
			return false
		}
		want := CPE{Version: c.Version, Update: c.Update}.FullVersion()
		if compareVersions(version, want) == 0 {
			return true
		}
		// 8.2 with any update matches 8.2p1.
		if (c.Update == "" || c.Update == "*") && strings.HasPrefix(strings.ToLower(version), strings.ToLower(c.Version)) {
			rest := version[len(c.Version):]
			return rest != "" && !(rest[0] >= '0' && rest[0] <= '9') && rest[0] != '.'
		}
		return false
	}
	if c.StartIncl != "" && compareVersions(version, c.StartIncl) < 0 {
		return false
	}
	if c.StartExcl != "" && compareVersions(version, c.StartExcl) <= 0 {
		return false
	}
	if c.EndIncl != "" && compareVersions(version, c.EndIncl) > 0 {
		return false
	}
	if c.EndExcl != "" && compareVersions(version, c.EndExcl) >= 0 {
		return false
	}
	return true
}

// Applies reports whether the CVE applies to a version.
func (v CVE) Applies(version string) bool {
	for _, c := range v.Criteria {
		if c.Matches(version) {
			return true
		}
	}
	return false
}

// DefaultNVDURL is the National Vulnerability Database's CVE API.
const DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDHost is the host CVE lookups reach.
const NVDHost = "services.nvd.nist.gov"

// NVD looks CVEs up in the National Vulnerability Database. Without an API
// key it may ask 5 times in 30 seconds, with one 50 times; it waits between
// requests to stay under that.
type NVD struct {
	URL    string
	APIKey string
	HTTP   *http.Client
	// Gap overrides the wait between requests (tests).
	Gap time.Duration

	mu   sync.Mutex
	last time.Time
}

// NewNVD returns a client for the CVE API at url (DefaultNVDURL when
// empty), sending key when one is set.
func NewNVD(url, key string) *NVD {
	n := &NVD{HTTP: &http.Client{Timeout: 2 * time.Minute}}
	n.Set(url, key)
	return n
}

// Set changes where lookups go and the API key, as the Settings page
// saves them.
func (n *NVD) Set(url, key string) {
	if url == "" {
		url = DefaultNVDURL
	}
	n.mu.Lock()
	n.URL, n.APIKey = url, strings.TrimSpace(key)
	n.mu.Unlock()
}

// endpoint returns where lookups go and the API key.
func (n *NVD) endpoint() (string, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.URL == "" {
		return DefaultNVDURL, n.APIKey
	}
	return n.URL, n.APIKey
}

// HasKey reports whether an API key is set.
func (n *NVD) HasKey() bool {
	_, key := n.endpoint()
	return key != ""
}

func (n *NVD) gap() time.Duration {
	switch {
	case n.Gap > 0:
		return n.Gap
	case n.APIKey != "":
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

// wait holds a request until it may go.
func (n *NVD) wait(ctx context.Context) error {
	n.mu.Lock()
	next := n.last.Add(n.gap())
	now := time.Now()
	if next.Before(now) {
		next = now
	}
	n.last = next
	n.mu.Unlock()
	t := time.NewTimer(time.Until(next))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Limits on what one product's lookup reads.
const (
	nvdPage       = 2000
	maxProductCVE = 12000
	maxNVDBody    = 96 << 20
	maxDescLen    = 400
)

// ErrNVDUnreachable wraps a lookup that could not reach the database.
var ErrNVDUnreachable = errors.New("could not reach the National Vulnerability Database")

// Product returns every CVE whose criteria name a product, with only that
// product's criteria.
func (n *NVD) Product(ctx context.Context, part, vendor, product string) ([]CVE, error) {
	match := "cpe:2.3:" + part + ":" + escapeCPE(vendor) + ":" + escapeCPE(product)
	var out []CVE
	for start := 0; start < maxProductCVE; start += nvdPage {
		q := url.Values{}
		q.Set("virtualMatchString", match)
		q.Set("resultsPerPage", strconv.Itoa(nvdPage))
		q.Set("startIndex", strconv.Itoa(start))
		page, total, err := n.page(ctx, q.Encode()+"&noRejected", vendor, product)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if start+nvdPage >= total {
			break
		}
	}
	return out, nil
}

// Ping asks for one CVE, to see that the database answers.
func (n *NVD) Ping(ctx context.Context) error {
	_, _, err := n.page(ctx, "resultsPerPage=1&cveId=CVE-2021-44228", "", "")
	return err
}

func escapeCPE(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// nvdResponse is the CVE API's answer, the parts read here.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			VulnStatus   string `json:"vulnStatus"`
			CISAAdded    string `json:"cisaExploitAdd"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics        map[string][]nvdMetric `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					Negate   bool `json:"negate"`
					CPEMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
						StartIncl  string `json:"versionStartIncluding"`
						StartExcl  string `json:"versionStartExcluding"`
						EndIncl    string `json:"versionEndIncluding"`
						EndExcl    string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (n *NVD) page(ctx context.Context, query, vendor, product string) ([]CVE, int, error) {
	if err := n.wait(ctx); err != nil {
		return nil, 0, err
	}
	base, key := n.endpoint()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+query, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Signalith vulnerability scanner")
	if key != "" {
		req.Header.Set("apiKey", key)
	}
	hc := n.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w (%s): %v", ErrNVDUnreachable, NVDHost, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		if key != "" && resp.StatusCode == http.StatusForbidden {
			return nil, 0, errors.New("the National Vulnerability Database refused the NVD API key; check it on the Settings page, or remove it to look up more slowly without one")
		}
		return nil, 0, errors.New("the National Vulnerability Database asked Signalith to slow down; lookups carry on at the next scan")
	case resp.StatusCode == http.StatusNotFound:
		// The API answers 404 for a product it has never heard of.
		return nil, 0, nil
	case resp.StatusCode != http.StatusOK:
		return nil, 0, fmt.Errorf("the National Vulnerability Database answered %s", resp.Status)
	}
	var r nvdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxNVDBody)).Decode(&r); err != nil {
		return nil, 0, fmt.Errorf("could not read the National Vulnerability Database's answer: %w", err)
	}
	out := make([]CVE, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		c := v.CVE
		if c.ID == "" || strings.EqualFold(c.VulnStatus, "Rejected") {
			continue
		}
		cve := CVE{ID: c.ID, KEVAdded: c.CISAAdded}
		if len(c.Published) >= 10 {
			cve.Published = c.Published[:10]
		}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				cve.Description = truncate(d.Value, maxDescLen)
				break
			}
		}
		cve.CVSS, cve.CVSSVersion, cve.Severity = score(c.Metrics)
		for _, cfg := range c.Configurations {
			for _, node := range cfg.Nodes {
				if node.Negate {
					continue
				}
				for _, m := range node.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					p, ok := ParseCPE(m.Criteria)
					if !ok || (vendor != "" && (p.Vendor != strings.ToLower(vendor) || p.Product != strings.ToLower(product))) {
						continue
					}
					cve.Criteria = append(cve.Criteria, Criterion{Version: p.Version, Update: p.Update,
						StartIncl: m.StartIncl, StartExcl: m.StartExcl, EndIncl: m.EndIncl, EndExcl: m.EndExcl})
				}
			}
		}
		if vendor == "" || len(cve.Criteria) > 0 {
			out = append(out, cve)
		}
	}
	return out, r.TotalResults, nil
}

// nvdMetric is one CVSS score of a CVE.
type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	// BaseSeverity is where CVSS 2 scores keep it.
	BaseSeverity string `json:"baseSeverity"`
}

// score picks a CVE's base score: CVSS 3.1, then 3.0, 4.0 and 2.0, from
// the database's own (Primary) analysis when it has one.
func score(metrics map[string][]nvdMetric) (float64, string, string) {
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"} {
		ms := metrics[key]
		if len(ms) == 0 {
			continue
		}
		m := ms[0]
		for _, x := range ms {
			if x.Type == "Primary" {
				m = x
				break
			}
		}
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		if sev == "" {
			sev = SeverityFor(m.CVSSData.BaseScore)
		}
		return m.CVSSData.BaseScore, m.CVSSData.Version, strings.ToLower(sev)
	}
	return 0, "", "unknown"
}

// SeverityFor names a CVSS 3 score's severity.
func SeverityFor(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
