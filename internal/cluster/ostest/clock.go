// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ostest

import (
	"sort"
	"sync"
	"time"
)

// Clock is a fake clock for tests. Its wall time (Now) and its monotonic
// time (Mono) move together when Advance is called, and the wall time can
// also be set apart from the monotonic one, as when a computer's clock is
// corrected or wrong.
type Clock struct {
	mu     sync.Mutex
	wall   time.Time
	mono   time.Duration
	timers []*timer
}

type timer struct {
	at time.Duration
	ch chan time.Time
}

// NewClock returns a clock at start.
func NewClock(start time.Time) *Clock {
	return &Clock{wall: start}
}

// Now returns the wall time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

// Mono returns the monotonic time since the clock was made.
func (c *Clock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

// After returns a channel that receives the wall time once the clock has
// been advanced by d.
func (c *Clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.wall
		return ch
	}
	c.timers = append(c.timers, &timer{at: c.mono + d, ch: ch})
	return ch
}

// Until returns a channel that receives the wall time once Mono reaches
// at, or at once if it has.
func (c *Clock) Until(at time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if at <= c.mono {
		ch <- c.wall
		return ch
	}
	c.timers = append(c.timers, &timer{at: at, ch: ch})
	return ch
}

// Advance moves both times forward by d and fires the timers that are
// due, in order.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.mono += d
	sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].at < c.timers[j].at })
	keep := c.timers[:0]
	for _, t := range c.timers {
		if t.at <= c.mono {
			t.ch <- c.wall
			continue
		}
		keep = append(keep, t)
	}
	c.timers = keep
}

// SetWall sets the wall time without moving the monotonic time, as a
// clock correction does.
func (c *Clock) SetWall(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = t
}

// Waiting returns how many timers wait to fire.
func (c *Clock) Waiting() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}
