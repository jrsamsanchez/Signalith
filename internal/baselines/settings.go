package baselines

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// The checks. Each learns one kind of behavior per user or host, and adds
// risk to it when that behavior is new or rare, so these signals add up
// with the detections' own in risk-based alerting.
const (
	NewCountry  = "new-country"
	NewNetwork  = "new-network"
	UnusualHour = "unusual-hour"
	RareProcess = "rare-process"
	NewChange   = "new-change"
	DataVolume  = "data-volume"
)

// Check describes one check.
type Check struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// Entity is whom the check learns: user or system.
	Entity string `json:"entity"`
	// Data is the data model it learns from.
	Data  string `json:"data"`
	Score int    `json:"default_score"`
	// IPDB is true for the checks that need the IP database.
	IPDB bool `json:"ip_database,omitempty"`
	// MITRE and Tactic tag its risk events with ATT&CK, where what it sees
	// fits a technique or a tactic. Only one tactic each, so one unusual
	// sign-in seen by three checks is not three tactics.
	MITRE  []string `json:"mitre,omitempty"`
	Tactic string   `json:"tactic,omitempty"`
}

// Checks lists the checks in page order.
var Checks = []Check{
	{ID: NewCountry, Title: "Sign-in from a new country", Entity: "user", Data: "Authentication", Score: 40, IPDB: true, MITRE: []string{"T1078"}, Tactic: "initial-access",
		Description: "A user signs in from a country none of their sign-ins came from before, going by the network the address belongs to."},
	{ID: NewNetwork, Title: "Sign-in from a new network", Entity: "user", Data: "Authentication", Score: 15, IPDB: true, MITRE: []string{"T1078"}, Tactic: "initial-access",
		Description: "A user signs in from an internet provider or cloud network (AS) none of their sign-ins came from before, in a country they did sign in from."},
	{ID: UnusualHour, Title: "Sign-in at an unusual hour", Entity: "user", Data: "Authentication", Score: 10, MITRE: []string{"T1078"}, Tactic: "initial-access",
		Description: "A user signs in at an hour of the day that has had under 2% of their sign-in activity, once they have been seen in at least 40 different hours."},
	{ID: RareProcess, Title: "Rare process on a host", Entity: "system", Data: "Endpoint", Score: 20, Tactic: "execution",
		Description: "A host runs a program it never ran before, which at most a few hosts have ever run."},
	{ID: NewChange, Title: "New kind of change by a user", Entity: "user", Data: "Change", Score: 15,
		Description: "A user makes a kind of change they never made before, such as a cloud API call (CreateAccessKey) or deleting a group."},
	{ID: DataVolume, Title: "Unusual data volume from a host", Entity: "system", Data: "Network_Traffic", Score: 30, MITRE: []string{"T1048"}, Tactic: "exfiltration",
		Description: "A host on your network sends far more in an hour than it usually does: at least 100 MB, five times its usual hour and well outside its normal spread."},
}

// CheckByID returns a check.
func CheckByID(id string) (Check, bool) {
	i := slices.IndexFunc(Checks, func(c Check) bool { return c.ID == id })
	if i < 0 {
		return Check{}, false
	}
	return Checks[i], true
}

// DetectionID is the detection_id of a check's risk events.
func DetectionID(check string) string { return "baseline-" + check }

// Defaults.
const (
	DefaultLearningDays = 14
	DefaultForgetDays   = 90
	DefaultRareHosts    = 3
	// DefaultMinMB is the least an hour must send, in MB, to count as an
	// unusual data volume.
	DefaultMinMB = 100
	// MaxProfiles is the most users or hosts one check learns: past it,
	// new ones are not learned until old ones are forgotten.
	MaxProfiles = 100_000
	// MaxRaisedPerHour is the most risk events one check raises for one
	// hour of data, so a change seen everywhere at once (new software
	// rolled out, a VPN moved) cannot flood the risk index.
	MaxRaisedPerHour = 50
)

// Settings are the baselines' settings, saved in the baselines index and
// shared by every server.
type Settings struct {
	// Off turns every check off.
	Off bool `json:"off,omitempty"`
	// LearningDays is how long a user or host is only learned from
	// before its unusual behavior adds risk; ForgetDays how long a value,
	// and a user or host, not seen again is remembered.
	LearningDays int `json:"learning_days,omitempty"`
	ForgetDays   int `json:"forget_days,omitempty"`
	// IPDatabase is where the IP-to-network database is downloaded from:
	// "" for DefaultIPDatabase, an http(s) address, the path of a file
	// on the server that runs the background jobs, or "off".
	IPDatabase string `json:"ip_database,omitempty"`
	// RareHosts is the most hosts a program may have run on to be rare;
	// MinMB the least an unusual hour sends, in MB.
	RareHosts int `json:"rare_hosts,omitempty"`
	MinMB     int `json:"min_mb,omitempty"`
	// Checks has each check's own settings, by check ID.
	Checks map[string]CheckSettings `json:"checks,omitempty"`
	// Exceptions hold back the risk of what matches them; the behavior
	// is still learned. Their fields are those of the risk events, such
	// as baseline (the check), risk_object, baseline_value and
	// src_country.
	Exceptions []detect.Exception `json:"exceptions,omitempty"`
}

// CheckSettings are one check's settings.
type CheckSettings struct {
	Off bool `json:"off,omitempty"`
	// Score is the risk the check adds, before the asset or identity
	// priority multiplier; zero is the check's default.
	Score int `json:"score,omitempty"`
	// ResetAt asks for the check's profiles to be forgotten, so it learns
	// again from then on.
	ResetAt time.Time `json:"reset_at,omitzero"`
}

// Learning returns the learning period.
func (s Settings) Learning() time.Duration {
	return time.Duration(cmp0(s.LearningDays, DefaultLearningDays)) * 24 * time.Hour
}

// Forget returns how long what is not seen again is remembered.
func (s Settings) Forget() time.Duration {
	return time.Duration(cmp0(s.ForgetDays, DefaultForgetDays)) * 24 * time.Hour
}

func (s Settings) rareHosts() int { return cmp0(s.RareHosts, DefaultRareHosts) }

func (s Settings) minBytes() float64 { return float64(cmp0(s.MinMB, DefaultMinMB)) * 1e6 }

func cmp0(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// On reports whether a check runs.
func (s Settings) On(check string) bool { return !s.Off && !s.Checks[check].Off }

// Score returns the risk a check adds.
func (s Settings) Score(check string) int {
	if n := s.Checks[check].Score; n > 0 {
		return n
	}
	c, _ := CheckByID(check)
	return c.Score
}

// IPSource returns where the IP database comes from, "" when it is off.
func (s Settings) IPSource() string {
	v := strings.TrimSpace(s.IPDatabase)
	switch {
	case strings.EqualFold(v, "off"):
		return ""
	case v == "":
		return DefaultIPDatabase
	}
	return v
}

// Problems lists what is wrong with the settings, worded for the page.
func (s Settings) Problems() []string {
	var p []string
	if s.LearningDays != 0 && (s.LearningDays < 1 || s.LearningDays > 90) {
		p = append(p, "The learning period must be from 1 to 90 days.")
	}
	if s.ForgetDays != 0 && (s.ForgetDays < 7 || s.ForgetDays > 365) {
		p = append(p, "Forget after must be from 7 to 365 days.")
	}
	if s.Forget() < s.Learning() {
		p = append(p, "Forget after must be at least as long as the learning period.")
	}
	if s.RareHosts != 0 && (s.RareHosts < 1 || s.RareHosts > 10) {
		p = append(p, "A rare program must be one at most 1 to 10 hosts ran.")
	}
	if s.MinMB != 0 && (s.MinMB < 1 || s.MinMB > 1_000_000) {
		p = append(p, "The least unusual data volume must be from 1 MB to 1,000,000 MB (1 TB).")
	}
	if err := IPSourceProblem(s.IPDatabase); err != nil {
		p = append(p, err.Error())
	}
	for id, c := range s.Checks {
		if _, ok := CheckByID(id); !ok {
			p = append(p, fmt.Sprintf("There is no check %q.", id))
		}
		if c.Score < 0 || c.Score > 1000 {
			p = append(p, "A check's risk score must be from 1 to 1000.")
		}
	}
	for i := range s.Exceptions {
		e := &s.Exceptions[i]
		if b, ok := e.Match["baseline"]; ok && !strings.ContainsAny(b, "*?") {
			if _, known := CheckByID(b); !known {
				p = append(p, fmt.Sprintf("Exception %s names no check: %q.", e.ID, b))
			}
		}
	}
	p = append(p, detect.ExceptionProblems(s.Exceptions)...)
	return p
}

// IPSourceProblem checks where the IP database comes from: empty, off, an
// https address without a password, or file: and the name of a .gz, .tsv
// or .txt file in the ipdb folder of the server that runs the background
// jobs (FileDir). Only a bare file name is taken, so the setting can't read
// other files of the server or reach a network share.
func IPSourceProblem(v string) error {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "off") {
		return nil
	}
	if name, ok := ipFile(v); ok {
		return fileNameProblem(name)
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("The IP database must be off, an https address, or file: and the name of a file in the ipdb folder.")
	}
	if u.Scheme != "https" {
		return errors.New("The IP database address must use https, so its contents can't be changed on the way.")
	}
	if u.User != nil {
		return errors.New("The IP database address can't have a user name or password in it.")
	}
	return nil
}

func fileNameProblem(name string) error {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") || strings.ContainsAny(name, `/\:`) || strings.ContainsRune(name, 0) {
		return errors.New("The IP database file must be just a file name, such as file:ip2asn-combined.tsv.gz, in the ipdb folder.")
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".gz", ".tsv", ".txt":
		return nil
	}
	return errors.New("The IP database file must be a .tsv or .gz file.")
}

// ipFile returns the file name of a file source, file:NAME.
func ipFile(v string) (string, bool) {
	if len(v) > 5 && strings.EqualFold(v[:5], "file:") {
		return strings.TrimSpace(v[5:]), true
	}
	return "", false
}
