// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

// Marker starts every comment Signalith writes on a ticket, so people see
// where it came from and the sync never takes it back as a new comment.
const Marker = "[Signalith]"

// Limits on what goes to a ticket.
const (
	maxSummary     = 250   // Jira's summary holds 255 characters
	maxShortDesc   = 160   // ServiceNow's short_description holds 160
	maxDescription = 20000 // well under both systems' limits
	maxComment     = 20000
)

// ticketContent is what a new ticket gets: only what the people working
// it need, never events or the rows a detection found.
type ticketContent struct {
	CaseID      string
	Title       string
	Severity    string
	Status      string
	Description string
	// Link opens the case in Signalith; "" when server.public_url is not
	// set.
	Link string
}

// markerID is a case's ID as it goes into the marker each ticket carries
// (a Jira label, a ServiceNow correlation ID): the ID itself when it is
// short and holds only characters both take (case IDs such as
// CASE-20261012-3fa9c1d27b40e865 do), else a short hash of it.
func markerID(caseID string) string {
	if markerSafe.MatchString(caseID) {
		return caseID
	}
	sum := sha256.Sum256([]byte(caseID))
	return "h" + hex.EncodeToString(sum[:8])
}

var markerSafe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

// jiraLabel is the label a Jira issue opened for a case carries.
func jiraLabel(caseID string) string { return "signalith-" + markerID(caseID) }

// correlationID is the correlation_id a ServiceNow ticket opened for a
// case carries.
func correlationID(caseID string) string { return "signalith:" + markerID(caseID) }

// CaseLink returns the address that opens a case in Signalith, or "" when
// the public address is not set.
func CaseLink(publicURL, caseID string) string {
	publicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if publicURL == "" {
		return ""
	}
	return publicURL + "/#cases?id=" + url.QueryEscape(caseID)
}

// contentOf returns what a ticket for case c gets.
func contentOf(c *cases.Case, link string) ticketContent {
	return ticketContent{
		CaseID: c.ID, Title: c.Title, Severity: c.Severity, Status: c.Status,
		Description: truncate(c.Description, maxDescription), Link: link,
	}
}

// lines returns the ticket's description as lines of plain text; the
// link is its own line when there is one.
func (t ticketContent) lines() []string {
	out := []string{
		"Opened from Signalith case " + t.CaseID + ".",
		"Severity: " + label(t.Severity) + ". Status in Signalith: " + label(t.Status) + ".",
	}
	if t.Link != "" {
		out = append(out, "Case: "+t.Link)
	}
	if d := strings.TrimSpace(t.Description); d != "" {
		out = append(out, "")
		out = append(out, strings.Split(strings.ReplaceAll(d, "\r\n", "\n"), "\n")...)
	}
	return out
}

// text is the description as plain text.
func (t ticketContent) text() string { return strings.Join(t.lines(), "\n") }

// label writes a status or severity for people: in_progress is "In
// progress".
func label(v string) string {
	v = strings.ReplaceAll(v, "_", " ")
	if v == "" {
		return "none"
	}
	r, n := utf8.DecodeRuneInString(v)
	return string(unicode.ToUpper(r)) + v[n:]
}

// noteComment is the comment a case note becomes on the ticket.
func noteComment(e cases.Entry) string {
	return truncate(Marker+" "+e.Author+": "+e.Text, maxComment)
}

// ours reports whether a comment's text starts with Marker, as every
// comment Signalith writes does.
func ours(text string) bool {
	return strings.HasPrefix(strings.TrimLeftFunc(text, unicode.IsSpace), Marker)
}

// sentByUs reports whether a ticket's comment is one Signalith wrote, so
// it is not taken back to case c: it starts with Marker and is by the
// connection's own account. Anyone can start a comment with Marker, so
// one by someone else is taken. When the system does not say who the
// account is, such a comment is Signalith's when it is one of the case's
// notes as sent.
func sentByUs(cm comment, c *cases.Case) bool {
	switch {
	case !ours(cm.Text):
		return false
	case cm.Own:
		return true
	case !cm.OwnUnknown:
		return false
	}
	text := strings.TrimSpace(strings.ReplaceAll(cm.Text, "\r\n", "\n"))
	for _, e := range c.Entries {
		if e.Kind == cases.KindNote && strings.TrimSpace(noteComment(e)) == text {
			return true
		}
	}
	return false
}

// imported reports whether a case note came from a ticket's comment, so
// it is not sent back to any ticket.
func imported(author string) bool {
	for _, t := range Types {
		if strings.HasPrefix(author, t+":") {
			return true
		}
	}
	return false
}

// maxImportedText is the most of a ticket's comment a case note takes;
// the rest is cut, with an ellipsis.
const maxImportedText = 4 << 10

// noteText is the case note a ticket's comment becomes: its text, without
// control characters other than line breaks, and cut to maxImportedText.
func noteText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	return truncate(strings.TrimSpace(s), maxImportedText)
}

// authorName is the name a comment's author gets on the case: the
// system, a colon and the name, as in "jira:Dana Scully".
func authorName(system, name string) string {
	name = clean(name, 80)
	if name == "" {
		name = "someone"
	}
	return system + ":" + name
}

// truncate cuts s to at most n bytes, on a character boundary, with an
// ellipsis when it was cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// truncateRunes cuts s to at most n characters.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// adfDoc builds an Atlassian Document Format document from lines of
// plain text: one paragraph for each run of lines between blank ones,
// with line breaks inside, and web addresses as links.
func adfDoc(lines []string) map[string]any {
	var content []any
	var para []any
	flush := func() {
		if len(para) > 0 {
			content = append(content, map[string]any{"type": "paragraph", "content": para})
			para = nil
		}
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(para) > 0 {
			para = append(para, map[string]any{"type": "hardBreak"})
		}
		para = append(para, adfInline(line)...)
	}
	flush()
	if content == nil {
		content = []any{map[string]any{"type": "paragraph", "content": []any{}}}
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

// adfInline returns one line as ADF text nodes, with each http or https
// address a link.
func adfInline(line string) []any {
	var out []any
	for line != "" {
		i := strings.Index(line, "https://")
		if j := strings.Index(line, "http://"); j >= 0 && (i < 0 || j < i) {
			i = j
		}
		if i < 0 {
			out = append(out, map[string]any{"type": "text", "text": line})
			break
		}
		if i > 0 {
			out = append(out, map[string]any{"type": "text", "text": line[:i]})
		}
		end := strings.IndexFunc(line[i:], unicode.IsSpace)
		if end < 0 {
			end = len(line) - i
		}
		link := line[i : i+end]
		out = append(out, map[string]any{"type": "text", "text": link,
			"marks": []any{map[string]any{"type": "link", "attrs": map[string]any{"href": link}}}})
		line = line[i+end:]
	}
	return out
}

// adfText returns the plain text of an Atlassian Document Format node:
// text nodes as they are, a line break for each hard break and block, and
// the names of mentions, emoji and links that have no text. It reads at
// most maxADFNodes nodes and maxADFDepth levels, so a hostile document
// cannot make it work without end.
func adfText(node any) string {
	var b strings.Builder
	count := 0
	var walk func(n any, depth int)
	walk = func(n any, depth int) {
		count++
		if count > maxADFNodes || depth > maxADFDepth || b.Len() > cases.MaxTextLen*2 {
			return
		}
		m, ok := n.(map[string]any)
		if !ok {
			return
		}
		typ, _ := m["type"].(string)
		attrs, _ := m["attrs"].(map[string]any)
		switch typ {
		case "text":
			s, _ := m["text"].(string)
			b.WriteString(s)
			return
		case "hardBreak":
			b.WriteString("\n")
			return
		case "mention":
			if s, _ := attrs["text"].(string); s != "" {
				b.WriteString(s)
			}
			return
		case "emoji":
			if s, _ := attrs["text"].(string); s != "" {
				b.WriteString(s)
			} else if s, _ := attrs["shortName"].(string); s != "" {
				b.WriteString(s)
			}
			return
		case "inlineCard", "blockCard":
			if s, _ := attrs["url"].(string); s != "" {
				b.WriteString(s)
			}
			return
		}
		children, _ := m["content"].([]any)
		for _, c := range children {
			walk(c, depth+1)
		}
		// Paragraphs are apart by a blank line, as the lines adfDoc made
		// them from were; list items and rows by a line break.
		switch typ {
		case "paragraph", "heading", "codeBlock", "blockquote", "panel":
			for b.Len() > 0 && !strings.HasSuffix(b.String(), "\n\n") {
				b.WriteString("\n")
			}
		case "listItem", "rule", "tableRow", "mediaSingle":
			if !strings.HasSuffix(b.String(), "\n") {
				b.WriteString("\n")
			}
		}
	}
	walk(node, 0)
	return strings.TrimSpace(b.String())
}

// Bounds of adfText.
const (
	maxADFNodes = 20000
	maxADFDepth = 50
)
