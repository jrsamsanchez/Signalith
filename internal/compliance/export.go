package compliance

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"strings"
)

// StatusLabel is a status as the report words it.
func StatusLabel(s Status) string {
	switch s {
	case Met:
		return "Evidence"
	case Partial:
		return "Partial"
	case Missing:
		return "Gap"
	case External:
		return "Handled outside Signalith"
	case NotApplicable:
		return "Not applicable"
	}
	return string(s)
}

// Find returns one framework's report.
func (r *Report) Find(id string) (*FrameworkReport, bool) {
	for i := range r.Frameworks {
		if r.Frameworks[i].ID == id {
			return &r.Frameworks[i], true
		}
	}
	return nil, false
}

// WriteCSV writes one row per control and piece of evidence, for an
// auditor's spreadsheet.
func WriteCSV(w io.Writer, rep *Report, f *FrameworkReport, server string) error {
	cw := csv.NewWriter(w)
	head := []string{"framework", "control", "group", "title", "status", "evidence", "evidence_status", "detail", "nist_800_53", "note", "note_by", "note_at", "server", "generated"}
	if err := cw.Write(head); err != nil {
		return err
	}
	base := func(c ControlReport) []string {
		return []string{f.Name + " " + f.Version, c.ID, c.Group, c.Title, StatusLabel(c.Status)}
	}
	tail := func(c ControlReport) []string {
		note, by, at := "", "", ""
		if a := c.Attestation; a != nil {
			note, by, at = a.Note, a.By, a.At.UTC().Format("2006-01-02 15:04 UTC")
		}
		return []string{strings.Join(c.NIST, " "), note, by, at, server, rep.Generated.UTC().Format("2006-01-02 15:04 UTC")}
	}
	for _, c := range f.Controls {
		rows := [][]string{}
		for _, e := range c.Evidence {
			rows = append(rows, []string{e.Name, StatusLabel(e.Status), e.Detail})
		}
		if ch := c.Checks; ch != nil && ch.Checks > 0 {
			var failing []string
			for _, x := range ch.Failing {
				failing = append(failing, fmt.Sprintf("%s (%s, %d %s)", x.Title, x.Platform, x.Hosts, plural(x.Hosts, "host", "hosts")))
			}
			d := fmt.Sprintf("%d checks: %d pass, %d fail, %d not applicable, %d waiting", ch.Checks, ch.Pass, ch.Fail, ch.NA, ch.Pending)
			if len(failing) > 0 {
				d += ". Failing: " + strings.Join(failing, "; ")
			}
			rows = append(rows, []string{"Configuration check results", "", d})
		}
		if len(c.Detections) > 0 {
			var names []string
			for _, d := range c.Detections {
				names = append(names, d.Name)
			}
			rows = append(rows, []string{"Detections on", "", strings.Join(names, "; ")})
		}
		for _, r := range rows {
			rec := append(append(base(c), r...), tail(c)...)
			if err := cw.Write(safeCSV(rec)); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// safeCSV keeps spreadsheet programs from reading a cell as a formula.
func safeCSV(rec []string) []string {
	for i, v := range rec {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			rec[i] = "'" + v
		}
	}
	return rec
}

// WriteHTML writes a report page to print or save as PDF.
func WriteHTML(w io.Writer, rep *Report, f *FrameworkReport, server, version string) error {
	type group struct {
		Name     string
		Controls []ControlReport
	}
	var groups []group
	for _, c := range f.Controls {
		if len(groups) == 0 || groups[len(groups)-1].Name != c.Group {
			groups = append(groups, group{Name: c.Group})
		}
		groups[len(groups)-1].Controls = append(groups[len(groups)-1].Controls, c)
	}
	var b bytes.Buffer
	err := reportTemplate.Execute(&b, map[string]any{
		"R": rep, "F": f, "Groups": groups, "Server": server, "Version": version,
		"Generated": rep.Generated.UTC().Format("2 January 2006, 15:04 UTC"),
	})
	if err != nil {
		return err
	}
	_, err = w.Write(b.Bytes())
	return err
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"label": StatusLabel,
	"join":  strings.Join,
	"more": func(ds []DetectionRef, n int) []DetectionRef {
		if len(ds) > n {
			return ds[:n]
		}
		return ds
	},
	"sub":    func(a, b int) int { return a - b },
	"count":  func(n int) string { return count(int64(n)) },
	"stamp":  func(a *Attestation) string { return a.At.UTC().Format("2006-01-02") },
	"plural": plural,
	"n":      func(m map[Status]int, k string) int { return m[Status(k)] },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.F.Name}} {{.F.Version}} evidence report · Signalith</title>
<style>
  :root { color-scheme: light; --ink: #14171f; --muted: #5b6372; --line: #dfe3ea; --soft: #f5f7fa;
    --met: #13795b; --met-bg: #e3f4ec; --part: #8a5a00; --part-bg: #fbf0d9; --gap: #b42318; --gap-bg: #fde8e6; --ext: #3b5bdb; --ext-bg: #e7ecfd; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #fff; color: var(--ink); font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  main { max-width: 920px; margin: 0 auto; padding: 40px 32px 64px; }
  .hint { background: var(--soft); border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px; color: var(--muted); margin-bottom: 28px; }
  header { border-bottom: 2px solid var(--ink); padding-bottom: 16px; margin-bottom: 24px; }
  .brand { font-weight: 600; letter-spacing: .02em; color: var(--muted); font-size: 12px; text-transform: uppercase; }
  h1 { font-size: 26px; line-height: 1.2; margin: 6px 0 8px; }
  h2 { font-size: 17px; margin: 32px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
  .meta { color: var(--muted); margin: 0; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin: 20px 0 8px; }
  .kpi { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
  .kpi b { display: block; font-size: 22px; line-height: 1.2; }
  .kpi span { color: var(--muted); font-size: 12px; }
  .note { color: var(--muted); font-size: 12.5px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; vertical-align: top; padding: 10px 8px; border-bottom: 1px solid var(--line); }
  th { font-size: 12px; color: var(--muted); font-weight: 600; }
  tr { break-inside: avoid; page-break-inside: avoid; }
  td.id { white-space: nowrap; font-weight: 600; width: 1%; }
  td.st { width: 1%; white-space: nowrap; }
  .pill { display: inline-block; border-radius: 999px; padding: 1px 9px; font-size: 12px; font-weight: 600; }
  .met { color: var(--met); background: var(--met-bg); }
  .partial { color: var(--part); background: var(--part-bg); }
  .missing { color: var(--gap); background: var(--gap-bg); }
  .external, .na { color: var(--ext); background: var(--ext-bg); }
  ul { margin: 6px 0 0; padding-left: 18px; }
  li { margin: 2px 0; }
  .ev-st { font-weight: 600; }
  .ev-st.met { background: none; } .ev-st.partial { background: none; } .ev-st.missing { background: none; }
  .small { font-size: 12.5px; color: var(--muted); }
  .attest { margin-top: 6px; padding: 6px 10px; border-left: 3px solid var(--ext); background: var(--ext-bg); border-radius: 4px; }
  footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
  @media print {
    main { padding: 0; max-width: none; }
    .hint { display: none; }
    h2 { break-after: avoid; page-break-after: avoid; }
    @page { margin: 16mm 14mm; }
  }
</style>
</head>
<body>
<main>
<p class="hint">To save this report as a PDF, use your browser's Print command and choose Save as PDF.</p>
<header>
  <div class="brand">Signalith compliance evidence</div>
  <h1>{{.F.Name}} {{.F.Version}}</h1>
  <p class="meta">Server {{.Server}} · Generated {{.Generated}}{{if .Version}} · Signalith {{.Version}}{{end}}</p>
</header>
<section class="summary" aria-label="Summary">
  <div class="kpi"><b>{{.F.Score}}%</b><span>Coverage score</span></div>
  <div class="kpi"><b>{{n .F.Counts "met"}}</b><span>With evidence</span></div>
  <div class="kpi"><b>{{n .F.Counts "partial"}}</b><span>Partial</span></div>
  <div class="kpi"><b>{{n .F.Counts "missing"}}</b><span>Gaps</span></div>
  <div class="kpi"><b>{{n .F.Counts "external"}}</b><span>Handled outside</span></div>
  <div class="kpi"><b>{{n .F.Counts "na"}}</b><span>Not applicable</span></div>
</section>
<p class="note">The score counts controls with evidence as 1 and partly supported ones as ½, out of the controls that apply. This report lists only the {{len .F.Controls}} controls a SIEM can give evidence for; the rest of {{.F.Name}} is outside its scope.</p>
{{range .R.Notes}}<p class="note"><b>Note:</b> {{.}}</p>{{end}}
{{range .Groups}}
<h2>{{.Name}}</h2>
<table>
  <thead><tr><th scope="col">Control</th><th scope="col">Evidence in Signalith</th><th scope="col">Status</th></tr></thead>
  <tbody>
  {{range .Controls}}
  <tr>
    <td class="id">{{.ID}}</td>
    <td>
      <b>{{.Title}}</b>
      <ul>
        {{range .Evidence}}<li><span class="ev-st {{.Status}}">{{.Name}}:</span> {{.Detail}}</li>{{end}}
        {{with .Checks}}{{if gt .Checks 0}}{{if .Failing}}<li><span class="ev-st partial">Failing checks:</span> {{range $i, $c := .Failing}}{{if $i}}; {{end}}{{$c.Title}} ({{$c.Platform}}, {{$c.Hosts}} {{plural $c.Hosts "host" "hosts"}}){{end}}</li>{{end}}{{end}}{{end}}
        {{if .Detections}}<li class="small">Detections on: {{range $i, $d := more .Detections 12}}{{if $i}}; {{end}}{{$d.Name}}{{end}}{{if gt (len .Detections) 12}}; and {{sub (len .Detections) 12}} more{{end}}</li>{{end}}
      </ul>
      {{with .Attestation}}<div class="attest"><b>{{label .Status}}</b> ({{.By}}, {{stamp .}}): {{.Note}}</div>{{end}}
      {{if .NIST}}<div class="small">NIST SP 800-53: {{join .NIST ", "}}</div>{{end}}
    </td>
    <td class="st"><span class="pill {{.Status}}">{{label .Status}}</span></td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}
<footer>
  <p>{{.F.Notice}}</p>
  <p>Signalith maps its own data, detections and checks to these controls. The mapping shows where Signalith gives evidence; it does not by itself make a system compliant, and an assessor decides what evidence is enough.</p>
</footer>
</main>
</body>
</html>
`))
