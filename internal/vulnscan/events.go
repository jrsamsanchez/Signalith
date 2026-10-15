package vulnscan

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Model is the data model scan results are written under.
const Model = "Vulnerabilities"

// Sourcetype marks events from Signalith's own scans.
const Sourcetype = "signalith:vulnscan"

// Event categories.
const (
	CategoryOpenPort      = "open_port"
	CategoryVulnerability = "vulnerability"
)

// Events turns a scan's hosts into events: one per open port, and one per
// CVE that applies to the software on it.
func Events(sc *Scan, scanner string, hosts []*Host, at time.Time) []ingest.Event {
	var out []ingest.Event
	for _, h := range hosts {
		dest := h.Hostname
		if dest == "" {
			dest = h.Address
		}
		for _, svc := range h.Services {
			base := map[string]any{
				"host": scanner, "sourcetype": Sourcetype, "vendor_product": "Signalith Nmap scan",
				"dest": dest, "dest_ip": h.Address, "dest_port": svc.Port, "transport": svc.Transport,
				"scan_id": sc.ID, "scan_network": sc.TargetName,
			}
			if svc.Name != "" {
				base["app"] = svc.Name
			}
			if p := strings.TrimSpace(svc.Product + " " + svc.Version); p != "" {
				base["product"] = svc.Product
				if svc.Version != "" {
					base["product_version"] = svc.Version
				}
			}
			if len(svc.CPEs) > 0 {
				base["cpe"] = svc.CPEs[0]
			}
			if svc.Port > 0 {
				port := copyFields(base)
				port["category"] = CategoryOpenPort
				port["severity"] = "informational"
				port["signature"] = openPortSignature(svc.Service)
				port["signature_id"] = svc.Transport + "/" + strconv.Itoa(svc.Port)
				out = append(out, ingest.Event{Time: at, Model: Model, Fields: port})
			} else {
				// A weakness of the host itself, not of one port.
				delete(base, "dest_port")
			}
			for _, v := range svc.Vulns {
				f := copyFields(base)
				f["category"] = CategoryVulnerability
				f["signature_id"] = v.Key()
				f["signature"] = vulnSignature(v)
				f["severity"] = v.Severity
				f["cvss"] = v.CVSS
				f["known_exploited"] = strconv.FormatBool(v.KEV)
				if v.CVE != "" {
					f["cve"] = v.CVE
					f["url"] = "https://nvd.nist.gov/vuln/detail/" + v.CVE
				}
				if v.CPE != "" {
					f["cpe"] = v.CPE
				}
				if v.Source == SourceOpenVAS {
					f["vendor_product"] = "Signalith OpenVAS scan"
					f["vuln_source"] = SourceOpenVAS
					f["openvas_oid"] = v.OID
					if v.Solution != "" {
						f["solution"] = truncate(v.Solution, 500)
					}
				}
				out = append(out, ingest.Event{Time: at, Model: Model, Fields: f})
			}
		}
	}
	return out
}

func openPortSignature(svc Service) string {
	what := svc.Name
	if svc.Product != "" {
		what = strings.TrimSpace(svc.Product + " " + svc.Version)
	}
	if what == "" {
		what = "unknown service"
	}
	return "Open port " + strconv.Itoa(svc.Port) + "/" + svc.Transport + ": " + what
}

func vulnSignature(v Vuln) string {
	if v.Source == SourceOpenVAS && v.Name != "" {
		if v.CVE != "" {
			return truncate(v.CVE+": "+v.Name, 200)
		}
		return truncate(v.Name, 200)
	}
	d := v.Description
	// The first sentence: a period inside a version number (2.4.49) does
	// not end it.
	if i := strings.Index(d, ". "); i > 0 && i < 160 {
		d = d[:i]
	}
	if i := strings.IndexByte(d, '\n'); i > 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	d = truncate(d, 160)
	if d == "" {
		return v.CVE
	}
	return v.CVE + ": " + d
}

func copyFields(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+8)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// writeEvents writes a scan's events in batches.
func (s *Scanner) writeEvents(ctx context.Context, sc *Scan, hosts []*Host, at time.Time) error {
	evs := Events(sc, s.Server, hosts, at)
	if len(evs) > maxScanEvents {
		s.log().Warn("vulnerability scan found more than can be written as events; the Vulnerabilities page has them all", "scan", sc.ID, "events", len(evs), "written", maxScanEvents)
		evs = evs[:maxScanEvents]
	}
	ctx = ingest.WithOrigin(ctx, ingest.Origin{Intake: ingest.IntakeScanner})
	for i := 0; i < len(evs); i += eventBatch {
		if _, err := s.Events.IngestEvents(ctx, evs[i:min(i+eventBatch, len(evs))]); err != nil {
			return err
		}
	}
	return nil
}
