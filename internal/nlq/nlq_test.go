package nlq

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

type hints struct{}

func (hints) KnownUser(v string) bool { return v == "alice" || v == "bob" }
func (hints) KnownHost(v string) bool { return v == "web1" || v == "dc01" }

func TestTranslate(t *testing.T) {
	cases := map[string]string{
		"failed logins in the last 24 hours":                    `datamodel=Authentication action=failure earliest=-24h`,
		"Failed logins from 203.0.113.9?":                       `datamodel=Authentication action=failure src=203.0.113.9`,
		"top 10 users with failed logins":                       `datamodel=Authentication action=failure | top limit=10 user`,
		"users with more than 5 failed logins in the last hour": `datamodel=Authentication action=failure earliest=-1h | stats count by user | where count>5 | sort -count`,
		"how many failed logins per user":                       `datamodel=Authentication action=failure | stats count by user | sort -count`,
		"successful logins for alice yesterday":                 `datamodel=Authentication action=success user=alice earliest=-1d@d latest=@d`,
		"ssh logins as root":                                    `datamodel=Authentication app=sshd user=root`,
		"powershell executed on web1":                           `datamodel=Endpoint process_name=powershell.exe dest=web1`,
		"processes containing mimikatz":                         `datamodel=Endpoint process=*mimikatz*`,
		"what processes ran on web1 today":                      `datamodel=Endpoint dest=web1 earliest=@d | stats count by process_name | sort -count`,
		"most common processes":                                 `datamodel=Endpoint | top limit=10 process_name`,
		"rare processes on dc01":                                `datamodel=Endpoint dest=dc01 | stats count by process_name | sort count | head 10`,
		"connections to port 4444":                              `datamodel=Network_Traffic dest_port=4444`,
		"blocked connections by source ip":                      `datamodel=Network_Traffic action=blocked | stats count by src | sort -count`,
		"outbound traffic over time":                            `datamodel=Network_Traffic | timechart count`,
		"total bytes by destination last 7 days":                `datamodel=Network_Traffic earliest=-7d | stats sum(bytes) as total_bytes by dest | sort -total_bytes`,
		"connections with bytes over 1000000":                   `datamodel=Network_Traffic bytes>1000000`,
		"accounts created this week":                            `datamodel=Change action=created object_category=user earliest=@w`,
		"users added to the admin group":                        `datamodel=Change action=modified object_category=group`,
		"which hosts have the highest risk score":               `datamodel=Risk risk_object_type=system | stats sum(risk_score) as risk_score by risk_object | sort -risk_score | head 10`,
		"risky users":                                           `datamodel=Risk risk_object_type=user | stats sum(risk_score) as risk_score by risk_object | sort -risk_score`,
		"failed logins per hour":                                `datamodel=Authentication action=failure | timechart span=1h count`,
		"distinct users per source with failed logins":          `datamodel=Authentication action=failure | stats dc(user) as distinct_user by src | sort -distinct_user`,
		"show user, src and dest for failed logins":             `datamodel=Authentication action=failure | table _time, user, src, dest`,
		"logins not from 10.0.0.1":                              `datamodel=Authentication src!=10.0.0.1`,
		"failed logins except root":                             `datamodel=Authentication action=failure user!=root`,
		"rdp logons to dc01 in the past 3 days":                 `datamodel=Authentication logon_type=10 dest=dc01 earliest=-3d`,
		"processes with parent winword":                         `datamodel=Endpoint parent_process_name=winword.exe`,
		"cmd.exe spawned by excel":                              `datamodel=Endpoint process_name=cmd.exe parent_process_name=excel.exe`,
		`events mentioning "invoke-expression"`:                 `invoke-expression`,
		"how many distinct users logged in today":               `datamodel=Authentication earliest=@d | stats dc(user) as distinct_user`,
		"which users logged in to more than 3 hosts":            `datamodel=Authentication | stats dc(dest) as distinct_dest by user | where distinct_dest>3 | sort -distinct_dest`,
		"show me everything from 10.1.2.3":                      `src=10.1.2.3`,
		"traffic to or from 10.1.2.3":                           `datamodel=Network_Traffic src=10.1.2.3 OR dest=10.1.2.3`,
		"events on web1 in the last 15 minutes":                 `host=web1 earliest=-15m`,
		"failed sudo":                                           `datamodel=Authentication action=failure app=sudo`,
		"risk by detection":                                     `datamodel=Risk | stats sum(risk_score) as risk_score by detection_id | sort -risk_score`,
		// Antivirus data.
		"malware on web1":                        `datamodel=Malware type=threat dest=web1`,
		"malware on servers last week":           `datamodel=Malware type=threat earliest=-1w | stats count by dest | sort -count`,
		"hosts where antivirus was turned off":   `datamodel=Malware type=health action=disabled | stats count by dest | sort -count`,
		"malware not removed in the last 7 days": `datamodel=Malware type=threat action IN (allowed, failed, restored) earliest=-7d`,
		"ransomware detections this week":        `datamodel=Malware type=threat category=ransomware earliest=@w`,
		"top threats":                            `datamodel=Malware type=threat | top limit=10 signature`,
		"antivirus exclusions added this month":  `datamodel=Malware type=health action=exclusion_added earliest=@mon`,
		"quarantined files on web1":              `datamodel=Malware type=threat action=quarantined dest=web1 | stats count by file_name | sort -count`,
		"files changed on web1":                  `datamodel=Filesystem action=modified dest=web1`,
		"top files on web1":                      `datamodel=Filesystem dest=web1 | top limit=10 file_name`,
		"asr blocks by rule":                     `datamodel=Malware type=rule action=blocked | stats count by rule | sort -count`,
		"defender events on dc01 today":          `datamodel=Malware vendor_product="Microsoft Defender Antivirus" dest=dc01 earliest=@d`,
		"antivirus exclusions removed":           `datamodel=Malware type=health action=exclusion_removed`,
		"clamav definitions failing":             `datamodel=Malware type=health action=update_failed vendor_product=ClamAV`,
		"tamper attempts on dc01":                `datamodel=Malware type=health action=tamper_blocked dest=dc01`,
		"attack surface reduction blocks":        `datamodel=Malware type=rule action=blocked`,
		"malware protection turned off on web1":  `datamodel=Malware type=health action=disabled dest=web1`,
		"disabled accounts":                      `action=modified`,
	}
	for in, want := range cases {
		r, err := Translate(in, hints{})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		got := strings.ReplaceAll(r.Query, "\n", " ")
		if got != want {
			t.Errorf("%q\n got %s\nwant %s", in, got, want)
		}
		if _, err := query.Parse(r.Query); err != nil {
			t.Errorf("%q: does not parse: %v", in, err)
		}
		if r.Confidence != 1 || len(r.Unknown) > 0 {
			t.Errorf("%q: confidence %.2f unknown %v", in, r.Confidence, r.Unknown)
		}
		if len(r.Steps) == 0 {
			t.Errorf("%q: no explanation", in)
		}
	}
}

func TestUnknownWordsLowerConfidence(t *testing.T) {
	r, err := Translate("lateral movement via wmi from 10.0.0.5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Confidence >= 0.5 || strings.Join(r.Unknown, " ") != "lateral movement wmi" {
		t.Errorf("confidence %.2f unknown %v", r.Confidence, r.Unknown)
	}
	if r.Query != "src=10.0.0.5" {
		t.Errorf("query %q", r.Query)
	}
}

func TestEmptyQuestion(t *testing.T) {
	if _, err := Translate("   ", nil); err == nil {
		t.Error("want an error for an empty question")
	}
}

func TestStepsExplain(t *testing.T) {
	r, _ := Translate("top 5 users with failed logins in the last 7 days", nil)
	var got []string
	for _, s := range r.Steps {
		got = append(got, s.Phrase+" => "+s.Meaning)
	}
	want := []string{
		"top 5 => the top 5",
		"users => one row per user",
		"failed => only failures",
		"logins => logon data (Authentication)",
		"last 7 days => time range: last 7 days",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("steps:\n%s", strings.Join(got, "\n"))
	}
}

func TestThresholdWithChartCountsWholeRange(t *testing.T) {
	r, _ := Translate("users with more than 2 failed logins per hour", nil)
	if strings.ReplaceAll(r.Query, "\n", " ") != "datamodel=Authentication action=failure | stats count by user | where count>2 | sort -count" {
		t.Errorf("query %q", r.Query)
	}
	found := false
	for _, s := range r.Steps {
		found = found || (s.Phrase == "per hour" && strings.HasPrefix(s.Meaning, "not applied"))
	}
	if !found {
		t.Errorf("steps %v", r.Steps)
	}
}
