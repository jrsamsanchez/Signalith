// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// callMore evaluates the JSON, time, printf and range functions; ok is
// false for a function it does not know.
func (ev *evaluator) callMore(fn string, args []any) (any, bool) {
	arg := func(i int) any {
		if i < len(args) {
			return args[i]
		}
		return nil
	}
	if v, ok := callBits(fn, args); ok {
		return v, true
	}
	switch fn {
	case "spath", "json_extract":
		s, ok := evStr(arg(0))
		if !ok {
			return nil, true
		}
		doc, ok := ev.parseJSON(s)
		if !ok {
			return nil, true
		}
		if len(args) < 2 {
			return ev.str(s), true
		}
		path, ok := evStr(arg(1))
		if !ok || path == "" || len(path) > query.MaxSpathPath {
			return nil, true
		}
		vals := spathAt(doc, strings.Split(path, "."), nil)
		out := make([]any, 0, len(vals))
		for _, v := range vals {
			if x := spathValue(v); x != nil {
				out = append(out, x)
			}
		}
		if len(out) == 1 && !strings.Contains(path, "{}") {
			return ev.charged(out[0]), true
		}
		return ev.list(out), true
	case "json_valid":
		s, ok := evStr(arg(0))
		return ok && json.Valid([]byte(s)), true
	case "json_keys":
		s, ok := evStr(arg(0))
		if !ok {
			return nil, true
		}
		doc, ok := ev.parseJSON(s)
		m, isObj := doc.(map[string]any)
		if !ok || !isObj {
			return nil, true
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b, _ := json.Marshal(keys)
		return ev.str(string(b)), true
	case "json_array_to_mv":
		s, ok := evStr(arg(0))
		if !ok {
			return nil, true
		}
		doc, ok := ev.parseJSON(s)
		items, isArr := doc.([]any)
		if !ok || !isArr {
			return nil, true
		}
		if len(items) > maxMultiValues {
			return ev.fail("a multivalue field would hold %d values; the limit is %d", len(items), maxMultiValues), true
		}
		var out []any
		for _, it := range items {
			if x := spathValue(it); x != nil {
				out = append(out, x)
			}
		}
		return ev.list(out), true
	case "json_object":
		if len(args)%2 != 0 {
			return ev.fail("json_object() takes keys and values in pairs"), true
		}
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < len(args); i += 2 {
			k, ok := evStr(args[i])
			if !ok {
				return nil, true
			}
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			writeJSONValue(&b, args[i+1])
			if !ev.fits(b.Len()) {
				return nil, true
			}
		}
		b.WriteByte('}')
		return ev.str(b.String()), true
	case "json_array":
		var b strings.Builder
		b.WriteByte('[')
		for i, a := range args {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONValue(&b, a)
			if !ev.fits(b.Len()) {
				return nil, true
			}
		}
		b.WriteByte(']')
		return ev.str(b.String()), true
	case "relative_time":
		t, ok := toTime(arg(0))
		spec, ok2 := evStr(arg(1))
		if !ok || !ok2 {
			return nil, true
		}
		rt, ok := query.RelativeTimeIn(t, spec, ev.loc)
		if !ok || rt.Year() < 1 || rt.Year() > 9999 {
			return nil, true
		}
		return numOut(float64(rt.Unix()) + float64(rt.Nanosecond())/1e9), true
	case "mvrange":
		start, ok1 := evNum(arg(0))
		end, ok2 := evNum(arg(1))
		step := 1.0
		ok3 := true
		if len(args) > 2 {
			step, ok3 = evNum(arg(2))
		}
		if !ok1 || !ok2 || !ok3 || step <= 0 || math.IsNaN(step) || math.IsNaN(start) || math.IsNaN(end) || math.IsInf(start, 0) || math.IsInf(end, 0) {
			return nil, true
		}
		n := math.Ceil((end - start) / step)
		if n > maxMultiValues {
			return ev.fail("a multivalue field would hold more than %d values; the limit is %d", maxMultiValues, maxMultiValues), true
		}
		var out []any
		for i := 0; i < int(n); i++ {
			out = append(out, numOut(start+float64(i)*step))
		}
		return ev.list(out), true
	case "printf":
		format, ok := evStr(arg(0))
		if !ok {
			return nil, true
		}
		s, ok := printf(format, args[1:])
		if !ok {
			return ev.fail("printf() formats can use %%s, %%d, %%i, %%f, %%e, %%g, %%x, %%X, %%o, %%c and %%%%, with widths up to %d", maxPrintfWidth), true
		}
		if !ev.fits(len(s)) {
			return nil, true
		}
		return ev.str(s), true
	case "isint":
		f, ok := evNum(arg(0))
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0), true
	case "validate":
		if len(args)%2 != 0 {
			return ev.fail("validate() takes conditions and messages in pairs"), true
		}
		for i := 0; i < len(args); i += 2 {
			if !truth(args[i]) {
				return args[i+1], true
			}
		}
		return nil, true
	}
	return nil, false
}

// charged counts v against the search's budget and returns it.
func (ev *evaluator) charged(v any) any {
	if !ev.charge(valueSize(v)) {
		return nil
	}
	return v
}

// parseJSON decodes s for the JSON functions, counting each byte as an
// evaluation step: decoding a byte costs about what a step does. The last
// value it decoded is kept, so several calls on the same field decode it
// once.
func (ev *evaluator) parseJSON(s string) (any, bool) {
	if ev.jsonText == s && ev.jsonOK {
		return ev.jsonDoc, true
	}
	if !ev.stepN(len(s)) {
		return nil, false
	}
	doc, ok := parseJSON(s)
	ev.jsonText, ev.jsonDoc, ev.jsonOK = s, doc, ok
	return doc, ok
}

// parseJSON decodes one JSON value, numbers kept exact.
func parseJSON(s string) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return nil, false
	}
	return v, true
}

// writeJSONValue writes a field value as JSON: numbers as numbers, a
// multivalue field as an array, a missing value as null.
func writeJSONValue(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONValue(b, e)
		}
		b.WriteByte(']')
	case int64, int, float64, bool:
		j, _ := json.Marshal(x)
		b.Write(j)
	default:
		s, _ := evStr(x)
		j, _ := json.Marshal(s)
		b.Write(j)
	}
}

// relativeTime applies an SPL time modifier (-1d@d, +2h, @w, now) to t,
// in UTC. @w snaps to Sunday, as in Splunk.
func relativeTime(t time.Time, spec string) (time.Time, bool) {
	return query.RelativeTime(t, spec)
}

// maxPrintfWidth caps a printf width or precision, so a short format
// cannot build a huge value.
const maxPrintfWidth = 1000

// printf formats args with C-style conversions; ok is false for a format
// it does not accept.
func printf(format string, args []any) (string, bool) {
	var b strings.Builder
	next := 0
	arg := func() any {
		if next < len(args) {
			next++
			return args[next-1]
		}
		next++
		return nil
	}
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		j := i + 1
		for j < len(format) && strings.IndexByte("-+ 0#", format[j]) >= 0 {
			j++
		}
		numStart := j
		for j < len(format) && (format[j] >= '0' && format[j] <= '9' || format[j] == '.') {
			j++
		}
		if j >= len(format) {
			return "", false
		}
		for _, part := range strings.Split(format[numStart:j], ".") {
			if n, err := strconv.Atoi(part); part != "" && (err != nil || n > maxPrintfWidth) {
				return "", false
			}
		}
		if strings.Count(format[numStart:j], ".") > 1 {
			return "", false
		}
		spec := format[i:j]
		verb := format[j]
		switch verb {
		case '%':
			b.WriteByte('%')
		case 's':
			s, _ := evStr(arg())
			b.WriteString(fmtSprintf(spec+"s", s))
		case 'd', 'i':
			f, _ := evNum(arg())
			b.WriteString(fmtSprintf(spec+"d", int64(f)))
		case 'x', 'X', 'o', 'c':
			f, _ := evNum(arg())
			b.WriteString(fmtSprintf(spec+string(verb), int64(f)))
		case 'f', 'e', 'g', 'E', 'G':
			f, _ := evNum(arg())
			b.WriteString(fmtSprintf(spec+string(verb), f))
		default:
			return "", false
		}
		if b.Len() > maxEvalValue {
			return b.String(), true
		}
		i = j
	}
	return b.String(), true
}

func fmtSprintf(format string, v any) string { return fmt.Sprintf(format, v) }
