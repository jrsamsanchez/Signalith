package api

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
)

// Network sensors on the Health page: how many send, how many went
// silent, drop packets or run on old rules. A sensor is an agent that
// sends Zeek, Suricata or sensor status batches.

const (
	// sensorSilentAfter is how long without a batch makes a sensor
	// silent: it sends its status line every 5 minutes.
	sensorSilentAfter = 15 * time.Minute
	// sensorDropping is the share of packets dropped above which a sensor
	// is dropping packets.
	sensorDropping = 5.0
	// sensorRulesOld is the rules' age above which they are old: they
	// update daily.
	sensorRulesOld = 3 * 24 * time.Hour
	// sensorHealthFor is how long the counts are kept between Health
	// page loads.
	sensorHealthFor = 30 * time.Second
)

// sensorTag matches the tags a network sensor's agent sends with.
var sensorTag = regexp.MustCompile(`^(zeek|suricata|sensor)(\.|$)`)

// sensorCounts are the Health page's network sensor counts.
type sensorCounts struct {
	Total    int `json:"total"`
	Sending  int `json:"sending"`
	Silent   int `json:"silent"`
	Dropping int `json:"dropping"`
	RulesOld int `json:"rules_old"`
}

type sensorHealthCache struct {
	mu  sync.Mutex
	at  time.Time
	out *sensorCounts
}

// countSensors counts the network sensors among agents at now.
func countSensors(agents []agentinv.Agent, now time.Time) *sensorCounts {
	var c sensorCounts
	for _, a := range agents {
		if a.Refusing || (a.Sensor == nil && !sensorTag.MatchString(a.Tag)) {
			continue
		}
		c.Total++
		if now.Sub(a.LastSeen) > sensorSilentAfter {
			c.Silent++
		} else {
			c.Sending++
		}
		s := a.Sensor
		if s == nil {
			continue
		}
		if s.DropPercent > sensorDropping {
			c.Dropping++
		}
		if s.Suricata != nil {
			updated, err := time.Parse(time.RFC3339, s.RulesUpdated)
			if s.RulesUpdate == "failed" || err != nil || now.Sub(updated) > sensorRulesOld {
				c.RulesOld++
			}
		}
	}
	if c.Total == 0 {
		return nil
	}
	return &c
}

// sensorHealth returns the network sensor counts, nil when there are no
// sensors, read again at most every sensorHealthFor.
func (s *Server) sensorHealth(ctx context.Context) *sensorCounts {
	if s.Agents == nil {
		return nil
	}
	c := &s.sensorCache
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.at.IsZero() && now.Sub(c.at) < sensorHealthFor {
		return c.out
	}
	list, _, err := s.agents().List(ctx)
	if err != nil {
		// The ones this server heard from are still counted.
		s.Log.Warn("the agents other servers heard from could not be read", "err", err)
	}
	c.at, c.out = now, countSensors(list, now)
	return c.out
}
