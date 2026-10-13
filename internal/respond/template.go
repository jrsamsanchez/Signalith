package respond

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// An HTTP action's URL and body name the values of a run with
// placeholders: {{.ip}}, {{.domain}}, {{.user}}, {{.host}}, {{.target}},
// {{.target_kind}}, {{.finding_id}}, {{.case_id}}, {{.actor}} and
// {{.reason}}. They look like Go templates but are not: the text is read
// once, each placeholder is replaced by its value escaped for where it
// stands, and the result is never read again, so a value can never add
// placeholders, template code, JSON or URL syntax of its own.
//
// In the URL a value is path-escaped before the "?" and query-escaped
// after it, and placeholders may not stand in the scheme, host or port,
// so a target cannot send the request somewhere else. In a JSON body a
// value is escaped as the inside of a JSON string, so placeholders go
// between quotes ("{{.ip}}"); a form body query-escapes it; a text body
// takes it as it is.

// Placeholders lists the names a template may use.
var Placeholders = []string{"ip", "domain", "user", "host", "target", "target_kind", "finding_id", "case_id", "actor", "reason"}

var placeholder = regexp.MustCompile(`\{\{\s*\.([a-z_]+)\s*\}\}`)

// Values are what placeholders stand for in one run.
type Values map[string]string

// valuesFor fills the values of a run: the target under its kind and as
// target.
func valuesFor(kind, target, findingID, caseID, actor, reason string) Values {
	v := Values{"target": target, "target_kind": kind, "finding_id": findingID, "case_id": caseID, "actor": actor, "reason": reason}
	if kind != "" {
		v[kind] = target
	}
	return v
}

// sampleValues fill templates when they are checked.
var sampleValues = Values{"ip": "203.0.113.7", "domain": "bad.example.com", "user": "jdoe", "host": "ws-0042",
	"target": "203.0.113.7", "target_kind": "ip", "finding_id": "F-1", "case_id": "CASE-1", "actor": "analyst", "reason": "test"}

// checkTemplate reports a placeholder that is not known, or "{{" that is
// not a placeholder.
func checkTemplate(text string) error {
	rest := placeholder.ReplaceAllStringFunc(text, func(m string) string {
		return ""
	})
	if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
		return fmt.Errorf("it has {{ or }} that is not a placeholder; placeholders look like {{.ip}}")
	}
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		if !slices.Contains(Placeholders, m[1]) {
			return fmt.Errorf("{{.%s}} is not a placeholder; use %s", m[1], placeholderList())
		}
	}
	return nil
}

func placeholderList() string {
	out := make([]string, len(Placeholders))
	for i, p := range Placeholders {
		out[i] = "{{." + p + "}}"
	}
	return strings.Join(out, " ")
}

// expand replaces each placeholder in text with esc of its value, in one
// pass.
func expand(text string, v Values, esc func(string) string) string {
	return placeholder.ReplaceAllStringFunc(text, func(m string) string {
		name := placeholder.FindStringSubmatch(m)[1]
		return esc(v[name])
	})
}

// jsonInner escapes s as the inside of a JSON string: quotes, backslashes,
// control characters, and < > & as \u escapes.
func jsonInner(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// Body formats.
const (
	BodyJSON = "json"
	BodyForm = "form"
	BodyText = "text"
)

// bodyContentType is the Content-Type sent with each body format.
var bodyContentType = map[string]string{
	BodyJSON: "application/json",
	BodyForm: "application/x-www-form-urlencoded",
	BodyText: "text/plain; charset=utf-8",
}

// expandBody fills a body template for its format.
func expandBody(text, format string, v Values) string {
	switch format {
	case BodyForm:
		return expand(text, v, url.QueryEscape)
	case BodyText:
		return expand(text, v, func(s string) string { return s })
	}
	return expand(text, v, jsonInner)
}

// splitURLTemplate splits a URL template into its scheme and authority
// ("https://fw.example.com:443") and the rest, which starts with "/", "?"
// or "#", or is empty.
func splitURLTemplate(text string) (origin, rest string, err error) {
	scheme, after, ok := strings.Cut(text, "://")
	if !ok {
		return "", "", fmt.Errorf("it must start with https:// or http://")
	}
	i := strings.IndexAny(after, "/?#")
	if i < 0 {
		i = len(after)
	}
	return scheme + "://" + after[:i], after[i:], nil
}

// checkURLTemplate checks an HTTP action's URL template: http or https, a
// host without placeholders, no user name or password in it, known
// placeholders.
func checkURLTemplate(text string) error {
	if err := checkTemplate(text); err != nil {
		return err
	}
	origin, _, err := splitURLTemplate(text)
	if err != nil {
		return err
	}
	if strings.Contains(origin, "{{") {
		return fmt.Errorf("placeholders cannot stand in the server's address, only in the path and query")
	}
	u, err := url.Parse(expandURL(text, sampleValues))
	if err != nil {
		return fmt.Errorf("it is not a URL (%v)", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("it must start with https:// or http://")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("it has no server name")
	}
	if u.User != nil {
		return fmt.Errorf("put the user name and password in their own fields, not in the URL")
	}
	return nil
}

// expandURL fills a URL template: values are path-escaped before the
// first "?" and query-escaped after it.
func expandURL(text string, v Values) string {
	origin, rest, err := splitURLTemplate(text)
	if err != nil {
		return text
	}
	path, query, hasQuery := strings.Cut(rest, "?")
	out := origin + expand(path, v, url.PathEscape)
	if hasQuery {
		out += "?" + expand(query, v, url.QueryEscape)
	}
	return out
}

// usesPlaceholder reports whether a template names p.
func usesPlaceholder(text, p string) bool {
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		if m[1] == p {
			return true
		}
	}
	return false
}
