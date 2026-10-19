// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import "maps"

// Audit events can carry credentials: a TokenReview holds the token it
// checks, a TokenRequest's answer the token it made, and a Secret its
// data, when the cluster's audit policy records request or response
// bodies. Whatever the policy, Signalith never keeps them: they are
// replaced before the event's fields and its raw copy are made.

// kubeRedacted is what a credential is replaced with.
const kubeRedacted = "[redacted]"

// kubeRedact returns the event with its credentials replaced, sharing
// what it does not change with r.
func kubeRedact(r map[string]any) map[string]any {
	ref, _ := r["objectRef"].(map[string]any)
	resource, _ := ref["resource"].(string)
	sub, _ := ref["subresource"].(string)
	sensitive := resource == "secrets" || resource == "tokenreviews" || resource == "tokenrequests" || sub == "token"
	var out map[string]any
	for _, k := range []string{"requestObject", "responseObject"} {
		v, has := r[k]
		if !has || v == nil {
			continue
		}
		obj, ok := v.(map[string]any)
		if !ok {
			// A JSON patch (a list of operations) or anything else that
			// is not an object can carry the values anywhere in it.
			if sensitive {
				if out == nil {
					out = maps.Clone(r)
				}
				out[k] = kubeRedacted
			}
			continue
		}
		red := kubeRedactObject(obj, resource, sub)
		if red == nil {
			continue
		}
		if out == nil {
			out = maps.Clone(r)
		}
		out[k] = red
	}
	if out == nil {
		return r
	}
	return out
}

// kubeRedactObject returns obj with its credentials replaced, or nil
// when it has none.
func kubeRedactObject(obj map[string]any, resource, sub string) map[string]any {
	kind, _ := obj["kind"].(string)
	changed := false
	out := maps.Clone(obj)
	// A token checked (TokenReview) or made (TokenRequest).
	if resource == "tokenreviews" || resource == "tokenrequests" || sub == "token" ||
		kind == "TokenReview" || kind == "TokenRequest" {
		for _, part := range []string{"spec", "status"} {
			if m, ok := out[part].(map[string]any); ok {
				if _, has := m["token"]; has {
					m = maps.Clone(m)
					m["token"] = kubeRedacted
					out[part] = m
					changed = true
				}
			}
		}
	}
	// A Secret, or a list of them.
	if resource == "secrets" || kind == "Secret" {
		if kubeRedactSecret(out) {
			changed = true
		}
	}
	if items, ok := out["items"].([]any); ok && (resource == "secrets" || kind == "SecretList") {
		items = append([]any(nil), items...)
		for i, it := range items {
			if m, ok := it.(map[string]any); ok {
				m = maps.Clone(m)
				if kubeRedactSecret(m) {
					items[i] = m
					changed = true
				}
			}
		}
		out["items"] = items
	}
	if !changed {
		return nil
	}
	return out
}

// kubeRedactSecret replaces a Secret's values, keeping their keys, and
// the copy of it kubectl apply keeps in an annotation. s is changed in
// place, and its nested maps are replaced, not changed.
func kubeRedactSecret(s map[string]any) bool {
	changed := false
	for _, k := range []string{"data", "stringData"} {
		switch v := s[k].(type) {
		case map[string]any:
			m := make(map[string]any, len(v))
			for key := range v {
				m[key] = kubeRedacted
			}
			s[k] = m
			changed = true
		case nil:
		default:
			s[k] = kubeRedacted
			changed = true
		}
	}
	if md, ok := s["metadata"].(map[string]any); ok {
		if ann, ok := md["annotations"].(map[string]any); ok {
			if _, has := ann[lastApplied]; has {
				ann = maps.Clone(ann)
				ann[lastApplied] = kubeRedacted
				md = maps.Clone(md)
				md["annotations"] = ann
				s["metadata"] = md
				changed = true
			}
		}
	}
	return changed
}
