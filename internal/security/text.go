// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// textWidth is where the text report wraps.
const textWidth = 78

// Text renders a report as plain text: ASCII punctuation, wrapped at 78
// columns with hanging indents. Words, and so links, are never broken.
// The commands shown are those for the report's own deployment. It is
// what signalith security prints and what the page's export gives.
//
// Control and formatting characters are shown escaped (\x1b, \u202e):
// another server's name comes from its own heartbeat, and must not be
// able to move the cursor, clear the screen or hide a link in the
// terminal of whoever reads the report.
func Text(r *Report) string {
	return printable(text(r))
}

func text(r *Report) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	name := r.Server.Name
	if name == "" {
		name = "this server"
	}
	w("Signalith security report for " + name)
	head := "Checked " + r.CheckedAt.UTC().Format("2006-01-02 15:04") + " UTC."
	if r.Server.Version != "" {
		head += " Signalith " + r.Server.Version
		if r.Server.Go != "" {
			head += " (" + r.Server.Go + ")"
		}
		head += "."
	}
	if r.Server.DeploymentLabel != "" {
		head += " " + r.Server.DeploymentLabel + "."
	}
	b.WriteString(wrap(head, "", ""))
	w("")
	b.WriteString(wrap(summaryText(r.Summary), "", ""))
	family := Family(r.Server.Deployment)

	byID := map[string]Check{}
	for _, c := range r.Checks {
		byID[c.ID] = c
	}
	if len(r.FixFirst) > 0 {
		w("")
		w("Fix first")
		for i, id := range r.FixFirst {
			c := byID[id]
			num := itoa(i+1) + ". "
			pad := strings.Repeat(" ", len(num))
			b.WriteString(wrap(num+c.State.Word()+": "+c.Title, "", pad))
			b.WriteString(wrap(isoDates(c.Line), pad, pad))
			for _, d := range c.Details {
				b.WriteString(wrap(isoDates(d), pad, pad))
			}
			if c.Fix != nil {
				b.WriteString(fixText(c.Fix, pad, family))
			}
		}
	}
	for _, g := range r.Groups {
		var rows []Check
		for _, c := range r.Checks {
			if c.Group == g.ID {
				rows = append(rows, c)
			}
		}
		if len(rows) == 0 {
			continue
		}
		w("")
		w(g.Title)
		const col = 16
		pad := strings.Repeat(" ", col)
		for _, c := range rows {
			tag := "  [" + tagWord(c.State) + "]"
			b.WriteString(wrap(c.Title, tag+strings.Repeat(" ", max(1, col-len(tag))), pad))
			b.WriteString(wrap(isoDates(c.Line), pad, pad))
			if c.State == Good || c.State == Unknown {
				for _, d := range c.Details {
					b.WriteString(wrap(isoDates(d), pad, pad))
				}
			}
			if c.State == Unknown && c.Fix != nil {
				b.WriteString(fixText(c.Fix, pad, family))
			}
			if c.Tip != nil && len(c.Tip.Steps) > 0 {
				b.WriteString(tipText(c.Tip, pad))
			}
		}
	}
	if len(r.Others) > 0 {
		w("")
		w("Other servers")
		for _, o := range r.Others {
			b.WriteString(wrap("- "+cutName(o.Name, maxPeerName)+": "+otherText(o), "  ", "    "))
		}
	}
	if len(r.AlwaysOn) > 0 {
		w("")
		w("Always on")
		for _, s := range r.AlwaysOn {
			b.WriteString(wrap("- "+s, "  ", "    "))
		}
	}
	if len(r.NotChecked) > 0 {
		w("")
		w("Not checked here")
		for _, s := range r.NotChecked {
			b.WriteString(wrap("- "+s, "  ", "    "))
		}
		b.WriteString(wrap("How to check these yourself: "+NotCheckedDocs(r.Server.Version).URL, "  ", "  "))
	}
	return b.String()
}

// maxPeerName caps how much of another server's name the report shows.
const maxPeerName = 80

// cutName cuts s to at most n characters, ending with "...".
func cutName(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-3]) + "..."
}

// printable escapes the characters in s that a terminal would act on
// rather than show (control characters other than line ends, and
// invisible formatting such as right-to-left overrides).
func printable(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, c := range s {
		switch {
		case !unsafeRune(c):
			b.WriteRune(c)
		case c < 0x100:
			fmt.Fprintf(&b, "\\x%02x", c)
		default:
			fmt.Fprintf(&b, "\\u%04x", c)
		}
	}
	return b.String()
}

func unsafeRune(c rune) bool {
	return c != '\n' && (unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == utf8.RuneError)
}

// tipText renders a tip: one step after its label, or the label on a
// line of its own with each step under it.
func tipText(t *Fix, pad string) string {
	label := t.Label
	if !strings.HasSuffix(label, "?") {
		label += ":"
	}
	if len(t.Steps) == 1 {
		return wrap(label+" "+isoDates(t.Steps[0]), pad, pad)
	}
	s := pad + label + "\n"
	for _, step := range t.Steps {
		s += wrap("- "+isoDates(step), pad, pad+"  ")
	}
	return s
}

func tagWord(s State) string {
	switch s {
	case Risk:
		return "at risk"
	case Attention:
		return "attention"
	case Unknown:
		return "can't tell"
	}
	return "good"
}

// summaryText is the summary line, leaving out what is zero.
func summaryText(s Summary) string {
	var parts []string
	if s.Risk > 0 {
		parts = append(parts, itoa(s.Risk)+" at risk")
	}
	if s.Attention > 0 {
		parts = append(parts, itoa(s.Attention)+plural(s.Attention, " needs attention", " need attention"))
	}
	if len(parts) == 0 {
		parts = append(parts, "nothing needs attention")
	}
	parts = append(parts, itoa(s.Good)+" good")
	if s.Unknown > 0 {
		parts = append(parts, itoa(s.Unknown)+" Signalith can't check from here")
	}
	return "Summary: " + strings.Join(parts, ", ") + "."
}

func otherText(o OtherServer) string {
	if o.NotChecked {
		return "not checked (older version)."
	}
	if o.CheckedAt == nil {
		return "not checked yet."
	}
	var parts []string
	if o.Risk > 0 {
		parts = append(parts, itoa(o.Risk)+" at risk")
	}
	if o.Attention > 0 {
		parts = append(parts, itoa(o.Attention)+plural(o.Attention, " needs attention", " need attention"))
	}
	if len(parts) == 0 {
		parts = append(parts, "nothing needs attention")
	}
	s := strings.Join(parts, ", ")
	if o.CheckedAt != nil {
		s += " (checked " + o.CheckedAt.UTC().Format("2006-01-02 15:04") + " UTC)"
	}
	return s + "."
}

// pageTitles name the pages a fix may point to.
var pageTitles = map[string]string{
	"data":      "Add data",
	"users":     "Users",
	"intel":     "Threat intel",
	"retention": "Data retention",
}

// fixText renders a fix, indented by pad, with the commands for family.
func fixText(x *Fix, pad, family string) string {
	var b strings.Builder
	if len(x.Steps) > 0 {
		b.WriteString(pad + x.Label + ":\n")
		for _, s := range x.Steps {
			b.WriteString(wrap("- "+isoDates(s), pad, pad+"  "))
		}
	}
	if x.Setting != "" {
		where := "Settings page"
		if s, ok := config.Lookup(x.Setting); ok {
			for _, sec := range config.Sections {
				if sec.ID == s.Section {
					where += ", " + sec.Title
				}
			}
		}
		if x.LockedBy != "" {
			where = "set by " + x.LockedBy + " where Signalith is started"
		}
		b.WriteString(wrap("Setting: "+x.Setting+" ("+where+")", pad, pad+"  "))
	}
	if x.Page != nil {
		title := pageTitles[x.Page.ID]
		if title == "" {
			title = strings.TrimPrefix(x.Page.Label, "Open ")
		}
		if x.Page.Tab == "directory" {
			title += ", Directory sign-in"
		}
		b.WriteString(wrap("Page: "+title, pad, pad+"  "))
	}
	if x.Action == "ca.prepare" {
		b.WriteString(wrap("On the Security page: Make a new certificate authority.", pad, pad+"  "))
	}
	if cmd := x.Commands[family]; cmd != "" {
		b.WriteString(pad + "Run:\n")
		for _, line := range strings.Split(cmd, "\n") {
			b.WriteString(pad + "  " + line + "\n")
		}
	}
	if x.Docs != nil && x.Docs.URL != "" {
		b.WriteString(pad + "Docs: " + x.Docs.URL + "\n")
	}
	return b.String()
}

// wrap breaks s into lines of at most textWidth columns: the first
// starts with first, the others with rest. A word longer than a line,
// such as a link, gets a line of its own and is never broken.
func wrap(s, first, rest string) string {
	var b strings.Builder
	line := first
	empty := true
	for _, word := range strings.Fields(s) {
		switch {
		case empty:
			line += word
			empty = false
		case len(line)+1+len(word) <= textWidth:
			line += " " + word
		default:
			b.WriteString(line + "\n")
			line = rest + word
		}
	}
	b.WriteString(line + "\n")
	return b.String()
}

var dayForm = regexp.MustCompile(`\b([1-9]|[12][0-9]|3[01]) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4})\b`)

// isoDates writes the dates in a line as 2026-11-12, as the text report
// does; the page shows 12 Nov 2026.
func isoDates(s string) string {
	return dayForm.ReplaceAllStringFunc(s, func(m string) string {
		t, err := time.Parse("2 Jan 2006", m)
		if err != nil {
			return m
		}
		return t.Format("2006-01-02")
	})
}
