package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Churn changes one setting over and over through the Settings page's
// API, naming the revision it read (if_version) as the page does, and
// times how long until every server uses the new value.
type Churn struct {
	load     ChurnLoad
	sessions []*Session
	m        *Metrics
}

// settingsView is the part of GET /api/settings used here.
type settingsView struct {
	Sections []struct {
		Fields []struct {
			Key     string `json:"key"`
			Value   any    `json:"value"`
			Version *int64 `json:"version"`
		} `json:"fields"`
	} `json:"sections"`
}

func (v settingsView) field(key string) (value any, version *int64, ok bool) {
	for _, s := range v.Sections {
		for _, f := range s.Fields {
			if f.Key == key {
				return f.Value, f.Version, true
			}
		}
	}
	return nil, nil, false
}

func (c *Churn) Run(ctx context.Context) {
	if len(c.sessions) == 0 {
		c.m.Add("churn_without_admin", 1)
		return
	}
	tick := time.NewTicker(c.load.Every.D())
	defer tick.Stop()
	for n := 0; ; n++ {
		c.change(ctx, c.sessions[n%len(c.sessions)], c.load.Values[n%len(c.load.Values)])
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (c *Churn) change(ctx context.Context, s *Session, value any) {
	var view settingsView
	if err := s.Do(ctx, http.MethodGet, "/api/settings", nil, &view); err != nil {
		c.m.Add("churn_errors", 1)
		return
	}
	_, version, ok := view.field(c.load.Key)
	if !ok {
		c.m.Add("churn_unknown_key", 1)
		return
	}
	body := map[string]any{"values": map[string]any{c.load.Key: value}}
	if version != nil {
		body["if_version"] = map[string]int64{c.load.Key: *version}
	}
	start := time.Now()
	err := s.Do(ctx, http.MethodPut, "/api/settings", body, nil)
	c.m.Observe("churn_save", time.Since(start))
	switch st := statusOf(err); {
	case err == nil:
		c.m.Add("churn_saved", 1)
	case st == http.StatusConflict:
		c.m.Add("churn_conflicts", 1)
		return
	default:
		if ctx.Err() == nil {
			c.m.Add("churn_errors", 1)
			c.m.Add("churn_status_"+strconv.Itoa(st), 1)
		}
		return
	}
	// Until every server shows the new value.
	want := fmt.Sprint(value)
	for _, other := range c.sessions {
		for {
			var v settingsView
			if err := other.Do(ctx, http.MethodGet, "/api/settings", nil, &v); err == nil {
				if got, _, _ := v.field(c.load.Key); fmt.Sprint(jsonValue(got)) == want {
					break
				}
			}
			if ctx.Err() != nil || time.Since(start) > 5*time.Minute {
				c.m.Add("churn_not_converged", 1)
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	took := time.Since(start)
	c.m.Observe("settings_converge", took)
	c.m.Set("", "settings_converge_seconds", took.Seconds())
}

// jsonValue writes whole numbers without a decimal point, so 5000 read
// back from JSON matches 5000 in the scenario.
func jsonValue(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int64(f)
	}
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return v
}
