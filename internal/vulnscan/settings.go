// Package vulnscan scans the networks an admin lists with Nmap, on a
// schedule or on demand, and matches the software versions it finds to
// known vulnerabilities (CVEs) from the U.S. National Vulnerability
// Database. Results feed the Vulnerabilities page, the event indices (the
// Vulnerabilities data model, so detections and searches see them) and the
// asset list.
//
// Scans run on the server that runs the background jobs. Each network
// names the scanner that scans it (Target.Scanner); "" is that server, so a
// scanner server per network zone can take a network over later without
// any change to how networks are kept.
package vulnscan

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Settings are the networks to scan and how CVEs are looked up. They are
// kept in OpenSearch, so every server that shares it has the same ones.
type Settings struct {
	Targets []Target `json:"targets"`
	// CVELookup matches the software versions scans find to CVEs, by
	// asking the National Vulnerability Database. Off, scans still list
	// hosts, open ports and software.
	CVELookup bool `json:"cve_lookup"`
	// UpdatedBy and UpdatedAt say who saved the settings last.
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// DefaultSettings has no networks yet, with CVE lookups on.
func DefaultSettings() Settings { return Settings{Targets: []Target{}, CVELookup: true} }

// Target is one network, or a list of hosts, to scan.
type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Networks are addresses (192.0.2.10), networks (192.0.2.0/24), a
	// range in the last part of an address (192.0.2.10-50) or host names.
	Networks []string `json:"networks"`
	// Exclude are addresses, networks or names in Networks to leave out.
	Exclude []string `json:"exclude,omitempty"`
	// Ports is top100, top1000, all, or a list such as 22,80,443,8000-8100.
	Ports string `json:"ports"`
	// Gentle scans slowly and with fewer probes, for networks with fragile
	// devices such as printers and building or industrial controllers.
	Gentle   bool     `json:"gentle"`
	Schedule Schedule `json:"schedule"`
	Enabled  bool     `json:"enabled"`
	// Scanner is the scanner that scans this network: "" is the server
	// that runs the background jobs.
	Scanner   string    `json:"scanner,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
}

// Schedule says when a network is scanned on its own. Times are in the
// scanning server's time zone.
type Schedule struct {
	// Every is daily, weekly or manual (only when someone clicks Scan
	// now).
	Every string `json:"every"`
	// Hour is the hour of the day the scan starts, 0 to 23.
	Hour int `json:"hour"`
	// Weekday is the day of a weekly scan, 0 (Sunday) to 6.
	Weekday int `json:"weekday"`
}

// Schedules.
const (
	Daily  = "daily"
	Weekly = "weekly"
	Manual = "manual"
)

// Port choices besides a list.
const (
	PortsTop100  = "top100"
	PortsTop1000 = "top1000"
	PortsAll     = "all"
)

// Limits on what can be scanned, so a typo cannot start a scan of the
// whole internet or of millions of addresses.
const (
	maxTargets          = 50
	maxEntries          = 256
	maxAddresses        = 65536
	maxNameLen          = 80
	maxEntryLen         = 253
	minPrefixV4         = 16
	minPrefixV6         = 112
	maxPortSpecLen      = 512
	DefaultScheduleHour = 1
)

// InputError is settings that cannot be saved as they are.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErrorf(format string, args ...any) error {
	return &InputError{Msg: fmt.Sprintf(format, args...)}
}

var (
	hostnameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
	portListRE = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$`)
	idRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// Validate checks settings an admin saved and tidies them: entries
// trimmed, blank lines and repeats dropped.
func (s *Settings) Validate() error {
	if len(s.Targets) > maxTargets {
		return inputErrorf("at most %d networks", maxTargets)
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for i := range s.Targets {
		t := &s.Targets[i]
		if err := t.Validate(); err != nil {
			return err
		}
		if ids[t.ID] {
			return inputErrorf("two networks have the ID %q", t.ID)
		}
		ids[t.ID] = true
		if names[strings.ToLower(t.Name)] {
			return inputErrorf("two networks are named %q; give each its own name", t.Name)
		}
		names[strings.ToLower(t.Name)] = true
	}
	return nil
}

// Validate checks one network and tidies it.
func (t *Target) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return inputErrorf("every network needs a name, such as Office LAN")
	}
	if len(t.Name) > maxNameLen || strings.ContainsAny(t.Name, "\x00\r\n") {
		return inputErrorf("%q: the name is longer than %d characters or has a line break", t.Name, maxNameLen)
	}
	if !idRE.MatchString(t.ID) {
		return inputErrorf("%s: the network has no valid ID; reload the page and add it again", t.Name)
	}
	var err error
	if t.Networks, err = cleanEntries(t.Name, "Addresses to scan", t.Networks); err != nil {
		return err
	}
	if len(t.Networks) == 0 {
		return inputErrorf("%s: list at least one address, network or host name to scan", t.Name)
	}
	if t.Exclude, err = cleanEntries(t.Name, "Addresses to skip", t.Exclude); err != nil {
		return err
	}
	if n := countAddresses(t.Networks); n > maxAddresses {
		return inputErrorf("%s: that is %d addresses; one network can have at most %d (a /16). Split it into smaller networks", t.Name, n, maxAddresses)
	}
	t.Ports = strings.ReplaceAll(strings.TrimSpace(t.Ports), " ", "")
	if t.Ports == "" {
		t.Ports = PortsTop1000
	}
	if err := checkPorts(t.Ports); err != nil {
		return inputErrorf("%s: %s", t.Name, err)
	}
	switch t.Schedule.Every {
	case Daily, Weekly, Manual:
	case "":
		t.Schedule.Every = Daily
	default:
		return inputErrorf("%s: the schedule must be daily, weekly or manual", t.Name)
	}
	if t.Schedule.Hour < 0 || t.Schedule.Hour > 23 {
		return inputErrorf("%s: the hour must be from 0 to 23", t.Name)
	}
	if t.Schedule.Weekday < 0 || t.Schedule.Weekday > 6 {
		return inputErrorf("%s: the day must be from 0 (Sunday) to 6 (Saturday)", t.Name)
	}
	t.Scanner = strings.TrimSpace(t.Scanner)
	if t.Scanner != "" && !idRE.MatchString(t.Scanner) {
		return inputErrorf("%s: unknown scanner %q", t.Name, t.Scanner)
	}
	return nil
}

// cleanEntries checks a list of addresses, networks and host names.
func cleanEntries(target, field string, in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		// One entry per line, but commas and spaces also separate them.
		for _, v := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' || r == '\n' || r == '\r' }) {
			if seen[v] {
				continue
			}
			if err := checkEntry(v); err != nil {
				return nil, inputErrorf("%s: %s: %s", target, field, err)
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) > maxEntries {
		return nil, inputErrorf("%s: %s: at most %d entries", target, field, maxEntries)
	}
	return out, nil
}

// checkEntry accepts what Nmap takes as a target, in the forms this page
// documents. Nothing else reaches Nmap's command line: an entry never
// starts with "-", so it cannot be read as an option.
func checkEntry(v string) error {
	if len(v) > maxEntryLen {
		return fmt.Errorf("%q is too long", v)
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%q is not an address, network or host name", v)
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if a.Zone() != "" {
			return fmt.Errorf("%q: leave out the interface (%%%s)", v, a.Zone())
		}
		if a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("%q cannot be scanned", v)
		}
		return nil
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		minBits := minPrefixV4
		if p.Addr().Is6() {
			minBits = minPrefixV6
		}
		if p.Bits() < minBits {
			return fmt.Errorf("%q is too large; the largest network is a /%d (%d addresses)", v, minBits, maxAddresses)
		}
		return nil
	}
	if lo, hi, ok := lastOctetRange(v); ok {
		if lo > hi {
			return fmt.Errorf("%q: the range goes backwards", v)
		}
		return nil
	}
	if strings.Count(v, ".") == 3 && strings.Trim(v, "0123456789.-") == "" {
		return fmt.Errorf("%q is not an address, a network such as 192.0.2.0/24, or a range such as 192.0.2.10-50", v)
	}
	if hostnameRE.MatchString(v) {
		return nil
	}
	return fmt.Errorf("%q is not an address, a network such as 192.0.2.0/24, a range such as 192.0.2.10-50, or a host name", v)
}

// lastOctetRange reads 192.0.2.10-50.
func lastOctetRange(v string) (lo, hi int, ok bool) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return 0, 0, false
	}
	base, rng := v[:i], v[i+1:]
	if _, err := netip.ParseAddr(base + ".0"); err != nil || strings.Count(base, ".") != 2 {
		return 0, 0, false
	}
	a, b, cut := strings.Cut(rng, "-")
	if !cut {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(a)
	hi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || lo < 0 || hi > 255 {
		return 0, 0, false
	}
	return lo, hi, true
}

// countAddresses is how many addresses entries cover; a host name counts
// as one.
func countAddresses(entries []string) int {
	n := 0
	for _, v := range entries {
		if p, err := netip.ParsePrefix(v); err == nil {
			bits := p.Addr().BitLen() - p.Bits()
			if bits >= 20 {
				return maxAddresses + 1
			}
			n += 1 << bits
			continue
		}
		if lo, hi, ok := lastOctetRange(v); ok {
			n += hi - lo + 1
			continue
		}
		n++
	}
	return n
}

func checkPorts(p string) error {
	switch p {
	case PortsTop100, PortsTop1000, PortsAll:
		return nil
	}
	if len(p) > maxPortSpecLen || !portListRE.MatchString(p) {
		return fmt.Errorf("ports must be top100, top1000, all, or a list such as 22,80,443,8000-8100")
	}
	for _, part := range strings.Split(p, ",") {
		a, b, _ := strings.Cut(part, "-")
		lo, _ := strconv.Atoi(a)
		hi := lo
		if b != "" {
			hi, _ = strconv.Atoi(b)
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return fmt.Errorf("%q is not a port or a range of ports from 1 to 65535", part)
		}
	}
	return nil
}

// LastSlot is the most recent time at or before now that the schedule
// says to scan, in loc; zero for a manual schedule.
func (sc Schedule) LastSlot(now time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.Local
	}
	n := now.In(loc)
	slot := time.Date(n.Year(), n.Month(), n.Day(), sc.Hour, 0, 0, 0, loc)
	switch sc.Every {
	case Daily:
		if slot.After(n) {
			slot = slot.AddDate(0, 0, -1)
		}
	case Weekly:
		back := (int(n.Weekday()) - sc.Weekday + 7) % 7
		slot = slot.AddDate(0, 0, -back)
		if slot.After(n) {
			slot = slot.AddDate(0, 0, -7)
		}
	default:
		return time.Time{}
	}
	return slot
}

// NextSlot is the first time after now that the schedule says to scan;
// zero for a manual schedule.
func (sc Schedule) NextSlot(now time.Time, loc *time.Location) time.Time {
	last := sc.LastSlot(now, loc)
	switch {
	case last.IsZero():
		return time.Time{}
	case sc.Every == Weekly:
		return last.AddDate(0, 0, 7)
	default:
		return last.AddDate(0, 0, 1)
	}
}
