package sample

import "time"

// sourceStopped: the second domain controller's Security log stops
// arriving one evening after it sent all day, and Signalith notices
// itself, two hours on.
func (g *gen) sourceStopped() {
	last := g.day(2, 19, 42)
	noticed := last.Add(2*time.Hour + 9*time.Minute)
	g.b.generic(noticed, "source:health", map[string]any{
		"vendor_product": "Signalith", "signature": "Data source stopped sending",
		"host": "dc-02", "dvc": "dc-02", "stopped_sourcetype": "WinEventLog:Security",
		"last_seen": last.UTC().Format(time.RFC3339), "quiet_minutes": 129,
		"message": "dc-02 stopped sending WinEventLog:Security: nothing for 129 minutes (last event " +
			last.UTC().Format("2006-01-02 15:04") + " UTC), after sending all day before",
	})
	g.story(Story{
		ID:    "source-stopped",
		Title: "A domain controller stops sending its Security log",
		Summary: "dc-02 sends its Windows Security log all day, then nothing arrives from it one evening. " +
			"Signalith notices two hours later; Endpoints shows whether the agent or the host is at fault.",
		Detections: []string{"data-source-stopped"},
	}, noticed.Add(time.Minute), "dc-02")
}
