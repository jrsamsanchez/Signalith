// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

// sizingTable writes the sizing runs' numbers as a Markdown table, one
// row per load phase of each run, for docs/performance.md.
func sizingTable(reports []*Report) string {
	var b strings.Builder
	b.WriteString("| Servers | Agents asked to send (events/s) | Stored (events/s) | p99 answer to agents | Busiest server CPU (cores) | Most memory of one server |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, r := range reports {
		servers := max(len(r.Servers), 1)
		for _, p := range r.Phases {
			stored := p.Counts["agent_events_stored"]
			if p.Name == "drain" || stored == 0 || p.Seconds == 0 {
				continue
			}
			p99 := "-"
			if l, ok := p.Latencies["ingest"]; ok && l.Count > 0 {
				p99 = fmtMS(l.P99)
			}
			cpu, mem := "-", "-"
			if v, ok := p.Values["server_cpu_cores"]; ok {
				cpu = fmt.Sprintf("%.1f", v)
			}
			if v, ok := p.Values["server_memory_mb"]; ok {
				mem = fmt.Sprintf("%.0f MB", v)
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n", servers, p.Name,
				roundRate(float64(stored)/p.Seconds), p99, cpu, mem)
		}
	}
	return b.String()
}

// roundRate writes events per second to two significant figures, which
// is all one run on a shared machine can tell.
func roundRate(v float64) string {
	switch {
	case v >= 10000:
		return fmt.Sprintf("%.0f", float64(int(v/1000+0.5))*1000)
	case v >= 1000:
		return fmt.Sprintf("%.0f", float64(int(v/100+0.5))*100)
	default:
		return fmt.Sprintf("%.0f", float64(int(v/10+0.5))*10)
	}
}

func fmtMS(ms float64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.1f s", ms/1000)
	}
	return fmt.Sprintf("%.0f ms", ms)
}
