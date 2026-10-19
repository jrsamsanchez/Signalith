// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/json"
	"strings"
	"time"
)

// CustomTagPrefix starts the tag of records an agent sends for a custom
// parser an admin saved on the Add data page: custom.<parser name>. The
// agent's tail input sets it, or a script sends it in X-Signalith-Tag.
const CustomTagPrefix = "custom."

// CustomParsers parses records sent under a custom parser's tag. Parse
// reports false when no saved parser has the name, and the record then
// goes through the built-in parsers like any other. drop reports a record
// that is no event, such as a CSV file's header line.
type CustomParsers interface {
	ParseCustom(name string, r map[string]any, now time.Time) (ev Event, drop, ok bool)
}

// ValidFieldName reports whether a name can be a sender-chosen field (see
// validFieldName), for parsers that check names before events are made.
func ValidFieldName(name string) bool { return validFieldName(name) && !Reserved(name) }

// normalize is Normalize, with a custom parser first for the records sent
// under its tag. A parser that panics on a crafted record leaves it to
// the built-in parsers, so one bad record cannot fail its batch.
func (p *Pipeline) normalize(tag string, r map[string]any, now time.Time) (ev Event, drop bool) {
	if p.Custom != nil && strings.HasPrefix(tag, CustomTagPrefix) {
		if ev, drop, ok := p.parseCustom(tag[len(CustomTagPrefix):], r, now); ok {
			return finishCustom(ev, r, now), drop
		}
	}
	return Normalize(tag, r, now), false
}

func (p *Pipeline) parseCustom(name string, r map[string]any, now time.Time) (ev Event, drop, ok bool) {
	defer func() {
		if recover() != nil {
			parserPanics.Add(1)
			ev, drop, ok = Event{}, false, false
		}
	}()
	return p.Custom.ParseCustom(name, r, now)
}

// finishCustom fills what a custom parser left out, as Normalize does.
func finishCustom(ev Event, r map[string]any, now time.Time) Event {
	if ev.Time.IsZero() {
		ev.Time = recordTime(r, now)
	}
	if ev.Model == "" {
		ev.Model = "Other"
	}
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	if _, ok := ev.Fields["message"]; !ok {
		raw, _ := json.Marshal(r)
		ev.Fields["message"] = string(raw)
	}
	if !hasSource(ev.Fields) {
		if f := str(r, "file"); f != "" {
			ev.Fields["source"] = truncateUTF8(CapValue(f), maxSourceLen)
		}
	}
	return ev
}
