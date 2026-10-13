package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
)

// QueryPrefix starts the name of every query Signalith schedules, so
// results are told apart from anything else a host sends.
const QueryPrefix = "signalith_"

// Scheduled query names, without QueryPrefix.
const (
	qOS       = "os"
	qSoftware = "software"
	qUsers    = "users"
	qPorts    = "ports"
	qServices = "services"
	qStartup  = "startup"
	qFIM      = "fim"
	qAddrs    = "addresses"
	// qCheck starts the name of each configuration check's query, followed
	// by the check's ID.
	qCheck = "check_"
)

// scheduled is one query in a host's schedule.
type scheduled struct {
	name     string
	sql      string
	interval int // seconds
	snapshot bool
}

// schedule returns the queries a platform runs. Inventory queries are
// differential: osquery reports what was added or removed since the last
// run (everything, the first time), so an unchanged host sends nothing.
func schedule(platform string, set Settings) []scheduled {
	inv := set.InventoryMinutes * 60
	if inv <= 0 {
		inv = 3600
	}
	qs := []scheduled{
		{qOS, "SELECT name, version, build, arch, platform FROM os_version;", inv, false},
		{qUsers, usersSQL(platform), inv, false},
		{qPorts, "SELECT DISTINCT lp.port AS port, CASE lp.protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE CAST(lp.protocol AS TEXT) END AS transport, " +
			"lp.address AS address, p.name AS process_name, p.path AS path FROM listening_ports lp LEFT JOIN processes p USING (pid) " +
			"WHERE lp.port != 0 AND lp.address NOT IN ('127.0.0.1', '::1');", max(inv/6, 300), false},
		{qStartup, "SELECT name, path, source, type FROM startup_items;", inv, false},
		{qAddrs, "SELECT address FROM interface_addresses WHERE address NOT LIKE '127.%' AND address != '::1' AND address NOT LIKE 'fe80:%';", inv, true},
	}
	switch platform {
	case Windows:
		qs = append(qs,
			scheduled{qSoftware, "SELECT name, version, publisher AS vendor, install_location AS path, 'windows' AS package_type FROM programs;", inv, false},
			scheduled{qServices, "SELECT name, display_name, start_type, path, user_account FROM services;", inv, false})
	case Darwin:
		qs = append(qs,
			scheduled{qSoftware, "SELECT name, bundle_short_version AS version, '' AS vendor, path, 'macos' AS package_type FROM apps;", inv, false},
			scheduled{qServices, "SELECT label AS name, program AS path, CAST(run_at_load AS TEXT) AS start_type FROM launchd;", inv, false})
	default:
		qs = append(qs,
			scheduled{qSoftware, "SELECT name, version, maintainer AS vendor, '' AS path, 'deb' AS package_type FROM deb_packages " +
				"UNION ALL SELECT name, version || '-' || release, vendor, '' AS path, 'rpm' AS package_type FROM rpm_packages;", inv, false},
			scheduled{qServices, "SELECT id AS name, description AS display_name, unit_file_state AS start_type, fragment_path AS path FROM systemd_units WHERE id LIKE '%.service';", inv, false})
	}
	if set.FIM && len(set.FilePaths[platform]) > 0 {
		if platform == Windows {
			qs = append(qs, scheduled{qFIM, "SELECT action, path, old_path, time FROM ntfs_journal_events;", 60, false})
		} else {
			qs = append(qs, scheduled{qFIM, "SELECT target_path, action, sha256, size, uid, time FROM file_events;", 60, false})
		}
	}
	// Configuration checks are differential too: a host reports each
	// result the first time, then only when it changes.
	if set.Checks {
		every := set.CheckMinutes * 60
		if every <= 0 {
			every = 3600
		}
		for _, c := range checks.For(platform) {
			qs = append(qs, scheduled{qCheck + c.ID, c.SQL, every, false})
		}
	}
	return qs
}

func usersSQL(platform string) string {
	if platform == Windows {
		return "SELECT username, description, directory, type FROM users WHERE type != 'special';"
	}
	return "SELECT username, CAST(uid AS TEXT) AS uid, description, directory, shell FROM users;"
}

// Config returns the osquery configuration a host of a platform gets, and
// a hash that changes when it does.
func Config(platform string, set Settings) ([]byte, string) {
	sched := map[string]any{}
	for _, q := range schedule(platform, set) {
		e := map[string]any{"query": q.sql, "interval": q.interval}
		if q.snapshot {
			e["snapshot"] = true
		}
		sched[QueryPrefix+q.name] = e
	}
	cfg := map[string]any{
		"options": map[string]any{
			// Results go to Signalith; nothing is kept on the host's disk.
			"logger_tls_period":      10,
			"schedule_splay_percent": 10,
		},
		"decorators": map[string]any{
			"load": []string{"SELECT hostname FROM system_info;"},
		},
		"schedule": sched,
	}
	if set.FIM {
		if paths := set.FilePaths[platform]; len(paths) > 0 {
			cfg["file_paths"] = map[string]any{"signalith": paths}
			if ex := set.ExcludePaths[platform]; len(ex) > 0 {
				cfg["exclude_paths"] = map[string]any{"signalith": ex}
			}
		}
	}
	b, _ := json.Marshal(cfg)
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:8])
}

// NormalizePlatform turns osquery's platform names (ubuntu, rhel, windows,
// darwin…) into linux, windows or darwin.
func NormalizePlatform(platform, like string) string {
	p := strings.ToLower(platform)
	switch {
	case p == "windows" || strings.Contains(strings.ToLower(like), "windows"):
		return Windows
	case p == "darwin" || strings.Contains(strings.ToLower(like), "darwin"):
		return Darwin
	}
	return Linux
}
