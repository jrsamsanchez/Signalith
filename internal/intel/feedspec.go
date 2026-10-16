package intel

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Feed kinds.
const (
	KindURL   = "url"   // a file downloaded from a URL
	KindTAXII = "taxii" // a collection on a TAXII 2.1 server
)

// Where a feed's settings come from.
const (
	SourceConfig = "config" // signalith.yaml; read-only on the Threat intel page
	SourceUI     = "ui"     // added on the Threat intel page
)

// MinInterval is the shortest download interval a feed may have.
const MinInterval = 5 * time.Minute

// FeedSpec is a feed as written in signalith.yaml (intel.feeds) or in the
// file that keeps the feeds added on the Threat intel page. Both are
// checked by the same rules.
type FeedSpec struct {
	// Name identifies the feed; indicators show it as their source.
	Name string `yaml:"name"`
	// Kind is url (download a file, the default) or taxii (read a
	// collection from a TAXII 2.1 server).
	Kind string `yaml:"kind,omitempty"`
	// URL is the file to download, or the TAXII server's API root.
	URL string `yaml:"url"`
	// Collection is the ID of the TAXII collection to read.
	Collection string `yaml:"collection,omitempty"`
	// Format is lines (one indicator per line, # comments), csv, stix (a
	// STIX 2.1 bundle) or auto (detect it from the content). Default
	// lines; TAXII feeds are always stix.
	Format string `yaml:"format,omitempty"`
	// Type is the indicator type (ip, cidr, domain, url, md5, sha1, sha256,
	// hash, email) or auto to detect each value. Default auto.
	Type string `yaml:"type,omitempty"`
	// Column picks the CSV column, by header name or number from 1.
	Column string `yaml:"column,omitempty"`
	// Interval is how often to download. Default 1h, at least 5m.
	Interval string `yaml:"interval,omitempty"`
	// MaxAge is how long indicators stay after the feed stops updating
	// (downloads fail). Indicators dropped from the feed are removed at the
	// next download. Default 7d.
	MaxAge string `yaml:"max_age,omitempty"`
	// Weight multiplies the risk a match adds: 1 is normal, 2 doubles it.
	Weight      float64  `yaml:"weight,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	// Headers are sent with the download, for feeds that need an API key.
	// In signalith.yaml, values may use ${ENV_VAR} to keep keys out of the
	// file.
	Headers map[string]string `yaml:"headers,omitempty"`
	// Username and Password sign in with HTTP basic authentication. In
	// signalith.yaml the password may use ${ENV_VAR}.
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	// Enabled defaults to true; set false to stop using a feed without
	// deleting its settings. Its indicators are removed.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Catalog is the built-in catalog entry the feed was added from.
	Catalog string `yaml:"catalog,omitempty"`
	// From says where a shared feed came from when not from the page,
	// such as "applied from signalith.yaml on siem-a"; never in a file.
	From string `yaml:"-"`
}

// IsEnabled reports whether a feed is on.
func (s FeedSpec) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// Defaults fills empty optional settings.
func (s *FeedSpec) Defaults() {
	if s.Kind == "" {
		s.Kind = KindURL
	}
	if s.Kind == KindTAXII && (s.Format == "" || s.Format == FormatAuto) {
		s.Format = FormatSTIX
	}
	if s.Format == "" {
		s.Format = FormatLines
	}
	if s.Type == "" {
		s.Type = "auto"
	}
	if s.Interval == "" {
		s.Interval = "1h"
	}
	if s.MaxAge == "" {
		s.MaxAge = "7d"
	}
	if s.Weight == 0 {
		s.Weight = 1
	}
}

// FeedProblem is one setting that needs fixing.
type FeedProblem struct {
	Field string `json:"field"`
	Msg   string `json:"msg"`
}

func (p FeedProblem) String() string { return p.Msg }

var (
	feedNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{1,63}$`)
	headerNamePattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	envRefPattern     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	feedKinds         = []string{KindURL, KindTAXII}
	// specFormats are the formats a feed may name; auto is detected at
	// each download.
	specFormats = append(append([]string{}, Formats...), FormatAuto)
)

// Problems checks a feed's settings after Defaults. env is true for feeds
// from signalith.yaml, whose header values and password may name
// environment variables, which must be set. Uniqueness of names across
// feeds is checked by the caller.
func (s *FeedSpec) Problems(env bool) []FeedProblem {
	var p []FeedProblem
	add := func(field, format string, args ...any) {
		p = append(p, FeedProblem{Field: field, Msg: fmt.Sprintf(format, args...)})
	}
	switch {
	case !feedNamePattern.MatchString(s.Name):
		add("name", "name must be 2-64 lowercase letters, digits, -, _ or ., for example feodo-tracker")
	case s.Name == ManualSource:
		add("name", `name "manual" is reserved for indicators added by hand`)
	}
	if !slices.Contains(feedKinds, s.Kind) {
		add("kind", "kind %q must be url (download a file) or taxii (a TAXII 2.1 server)", s.Kind)
	}
	if u, err := url.Parse(s.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		if s.Kind == KindTAXII {
			add("url", "url %q must be the http(s) address of the TAXII server's API root", RedactURL(s.URL))
		} else {
			add("url", "url %q must be an http(s) address", RedactURL(s.URL))
		}
	} else if u.User != nil {
		add("url", "url must not include a user name or password; use the username and password settings instead")
	}
	if !slices.Contains(specFormats, s.Format) {
		add("format", "format %q must be one of %s", s.Format, strings.Join(specFormats, ", "))
	}
	if !slices.Contains(FeedTypes, s.Type) {
		add("type", "type %q must be one of %s", s.Type, strings.Join(FeedTypes, ", "))
	}
	switch s.Kind {
	case KindTAXII:
		if strings.TrimSpace(s.Collection) == "" {
			add("collection", "collection is required for a TAXII feed: the ID of the collection to read")
		}
		if s.Format != FormatSTIX {
			add("format", "TAXII feeds are always STIX; leave format empty or set it to stix")
		}
		if s.Column != "" {
			add("column", "column only applies to format: csv")
		}
	default:
		if s.Collection != "" {
			add("collection", "collection only applies to kind: taxii")
		}
		if s.Format == FormatCSV && strings.TrimSpace(s.Column) == "" {
			add("column", "csv feeds need a column, by header name or number from 1")
		}
		if s.Format != FormatCSV && s.Format != FormatAuto && s.Column != "" {
			add("column", "column only applies to format: csv")
		}
	}
	iv, err := ParseDuration(s.Interval)
	if err != nil {
		add("interval", "interval: %v", err)
	} else if iv < MinInterval {
		add("interval", "interval must be at least 5m; feeds update far less often")
	}
	if age, err := ParseDuration(s.MaxAge); err != nil {
		add("max_age", "max_age: %v", err)
	} else if iv > 0 && age < iv {
		add("max_age", "max_age must be at least the interval, or indicators expire between downloads")
	}
	if s.Weight < 0 || s.Weight > 10 {
		add("weight", "weight must be above 0 and at most 10 (1 is normal)")
	}
	names := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := s.Headers[k]
		switch {
		case !headerNamePattern.MatchString(k):
			add("headers", "header name %q may only use letters, digits and - (for example X-Api-Key)", k)
		case strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length"):
			add("headers", "header %s cannot be set", k)
		case strings.ContainsAny(v, "\r\n"):
			add("headers", "header %s has a line break in its value", k)
		case strings.TrimSpace(v) == "":
			add("headers", "header %s has no value", k)
		}
		if env {
			for _, m := range envRefPattern.FindAllStringSubmatch(v, -1) {
				if lookupEnv(m[1]) == "" {
					add("headers", "headers.%s uses ${%s}, which is not set in the environment", k, m[1])
				}
			}
		}
	}
	if s.Password != "" && s.Username == "" {
		add("username", "a password needs a username")
	}
	if env {
		for _, m := range envRefPattern.FindAllStringSubmatch(s.Password, -1) {
			if lookupEnv(m[1]) == "" {
				add("password", "password uses ${%s}, which is not set in the environment", m[1])
			}
		}
	}
	return p
}

// Feed converts checked settings to a feed of the given source.
func (s FeedSpec) Feed(source string) Feed {
	s.Defaults()
	iv, _ := ParseDuration(s.Interval)
	age, _ := ParseDuration(s.MaxAge)
	var headers map[string]string
	if len(s.Headers) > 0 {
		headers = make(map[string]string, len(s.Headers))
		for k, v := range s.Headers {
			headers[k] = v
		}
	}
	return Feed{
		Name: s.Name, Kind: s.Kind, URL: s.URL, Collection: strings.TrimSpace(s.Collection),
		Format: s.Format, Type: s.Type, Column: s.Column, Interval: iv, MaxAge: age,
		Weight: s.Weight, Description: s.Description, Tags: slices.Clone(s.Tags), Headers: headers,
		Username: s.Username, Password: s.Password, Enabled: s.IsEnabled(), Source: source, Catalog: s.Catalog,
		From: s.From,
	}
}

// clone returns a deep copy.
func (s FeedSpec) clone() FeedSpec {
	c := s
	c.Tags = slices.Clone(s.Tags)
	if s.Headers != nil {
		c.Headers = make(map[string]string, len(s.Headers))
		for k, v := range s.Headers {
			c.Headers[k] = v
		}
	}
	if s.Enabled != nil {
		on := *s.Enabled
		c.Enabled = &on
	}
	return c
}
