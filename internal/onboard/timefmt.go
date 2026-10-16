package onboard

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// TimeFormatSpec is a way of writing times that parsers read. Times
// without a zone are taken as UTC.
type TimeFormatSpec struct {
	Name    string `json:"name"`
	Example string `json:"example"`
	layouts []string
	epoch   time.Duration // the unit of an epoch number, or 0
	noYear  bool
}

// TimeFormats lists the time formats, in the order detection tries them.
var TimeFormats = []*TimeFormatSpec{
	{Name: "iso8601", Example: "2026-10-16T14:05:09.123Z", layouts: []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05"}},
	{Name: "iso8601_space", Example: "2026-10-16 14:05:09", layouts: []string{"2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05"}},
	{Name: "slash_ymd", Example: "2026/10/16 14:05:09", layouts: []string{"2006/01/02 15:04:05"}},
	{Name: "clf", Example: "16/Oct/2026:14:05:09 +0000", layouts: []string{"02/Jan/2006:15:04:05 -0700"}},
	{Name: "us", Example: "10/16/2026 14:05:09", layouts: []string{"01/02/2006 15:04:05", "1/2/2006 15:04:05", "1/2/2006 3:04:05 PM", "01/02/2006 03:04:05 PM"}},
	{Name: "rfc1123", Example: "Fri, 16 Oct 2026 14:05:09 GMT", layouts: []string{time.RFC1123, time.RFC1123Z}},
	{Name: "syslog", Example: "Oct 16 14:05:09", layouts: []string{"Jan _2 15:04:05", "Jan _2 2006 15:04:05"}, noYear: true},
	{Name: "ctime", Example: "Fri Oct 16 14:05:09 2026", layouts: []string{time.ANSIC, time.UnixDate}},
	{Name: "epoch", Example: "1792159509", epoch: time.Second},
	{Name: "epoch_ms", Example: "1792159509123", epoch: time.Millisecond},
}

func timeFormat(name string) *TimeFormatSpec {
	for _, f := range TimeFormats {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// parse reads s in the format.
func (f *TimeFormatSpec) parse(s string, now time.Time) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if f.epoch != 0 {
		n, err := strconv.ParseFloat(s, 64)
		if err != nil || n <= 0 || strings.ContainsAny(s, "eE") {
			return time.Time{}, false
		}
		var t time.Time
		if f.epoch == time.Millisecond {
			t = time.UnixMilli(int64(n))
		} else {
			sec := int64(n)
			t = time.Unix(sec, int64((n-float64(sec))*1e9))
		}
		// Between 2000 and 2100: anything else is some other number.
		if t.Year() < 2000 || t.Year() > 2100 {
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	for _, l := range f.layouts {
		t, err := time.Parse(l, s)
		if err != nil {
			continue
		}
		if f.noYear && t.Year() == 0 {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(48 * time.Hour)) {
				t = t.AddDate(-1, 0, 0) // December's lines read in January
			}
		}
		return t.UTC(), true
	}
	return time.Time{}, false
}

// parseTimeValue reads an event time from a field's value, in f, or in
// any format when f is nil.
func parseTimeValue(v any, f *TimeFormatSpec, now time.Time) (time.Time, bool) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case int64:
		s = strconv.FormatInt(x, 10)
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		s = x.String()
	default:
		return time.Time{}, false
	}
	if f != nil {
		return f.parse(s, now)
	}
	if spec := detectTimeFormat([]string{s}, true, now); spec != nil {
		return spec.parse(s, now)
	}
	return time.Time{}, false
}

// detectTimeFormat returns the first format that reads every value, or
// nil. Epoch numbers count only when epochOK (the field's name says it
// is a time), since any number could pass for one.
func detectTimeFormat(values []string, epochOK bool, now time.Time) *TimeFormatSpec {
	if len(values) == 0 {
		return nil
	}
	for _, f := range TimeFormats {
		if f.epoch != 0 && !epochOK {
			continue
		}
		all := true
		for _, v := range values {
			if _, ok := f.parse(v, now); !ok {
				all = false
				break
			}
		}
		if all {
			return f
		}
	}
	return nil
}
