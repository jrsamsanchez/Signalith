package shared

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Extra holds the fields of a JSON object that the type read into does
// not know. Every body type embeds it (tagged json:"-"), so a server that
// is older than the one that wrote a document keeps the fields it does not
// know when it writes the document back:
//
//	type Feeds struct {
//		Feeds []Feed `json:"feeds"`
//		shared.Extra `json:"-"`
//	}
//
// Doc and Collection handle a body's own Extra. A type inside a body
// (each feed of a list) that keeps its unknown fields too does it in its
// own MarshalJSON and UnmarshalJSON, with MarshalExtra and
// UnmarshalExtra.
type Extra map[string]json.RawMessage

func (e *Extra) extraFields() *Extra { return e }

// extended is a type that embeds Extra.
type extended interface{ extraFields() *Extra }

// MergeExtra returns raw, a JSON object, with the fields of e it lacks
// added.
func MergeExtra(raw []byte, e Extra) ([]byte, error) {
	if len(e) == 0 {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("not a JSON object: %.40s", raw)
	}
	for k, v := range e {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
	return json.Marshal(fields)
}

// SplitExtra returns the fields of raw, a JSON object, that known (the
// same value written out again by a type that drops what it does not
// know) lacks; nil when there are none.
func SplitExtra(raw, known []byte) (Extra, error) {
	var all, have map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(known, &have); err != nil {
		return nil, err
	}
	var out Extra
	for k, v := range all {
		if _, ok := have[k]; ok {
			continue
		}
		if out == nil {
			out = Extra{}
		}
		out[k] = v
	}
	return out, nil
}

// MarshalExtra writes v, then adds the fields of e it lacks. A type with
// its own Extra calls it from MarshalJSON on a copy of itself whose type
// has no MarshalJSON:
//
//	func (f Feed) MarshalJSON() ([]byte, error) {
//		type plain Feed
//		return shared.MarshalExtra(plain(f), f.Extra)
//	}
func MarshalExtra(v any, e Extra) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return MergeExtra(raw, e)
}

// UnmarshalExtra reads data into v and returns the fields v does not
// know. v points to a type with no UnmarshalJSON and an empty Extra:
//
//	func (f *Feed) UnmarshalJSON(data []byte) error {
//		type plain Feed
//		var p plain
//		extra, err := shared.UnmarshalExtra(data, &p)
//		*f = Feed(p)
//		f.Extra = extra
//		return err
//	}
func UnmarshalExtra(data []byte, v any) (Extra, error) {
	if err := json.Unmarshal(data, v); err != nil {
		return nil, err
	}
	known, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return SplitExtra(data, known)
}

// encodeBody writes a body as its JSON text, with its unknown fields.
func encodeBody[T any](v *T) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if x, ok := any(v).(extended); ok {
		if raw, err = MergeExtra(raw, *x.extraFields()); err != nil {
			return "", err
		}
	}
	return string(raw), nil
}

// decodeBody reads a body's JSON text, keeping its unknown fields.
func decodeBody[T any](body string) (*T, error) {
	v := new(T)
	dec := json.NewDecoder(bytes.NewReader([]byte(body)))
	if err := dec.Decode(v); err != nil {
		return nil, err
	}
	if x, ok := any(v).(extended); ok {
		*x.extraFields() = nil
		known, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		extra, err := SplitExtra([]byte(body), known)
		if err != nil {
			return nil, err
		}
		*x.extraFields() = extra
	}
	return v, nil
}
