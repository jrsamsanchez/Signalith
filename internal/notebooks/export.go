package notebooks

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Markdown renders a notebook as a Markdown document, for sharing a hunt
// and what it found outside Signalith. Each search shows its query and
// up to rows rows of its last result.
func Markdown(n *Notebook, rows int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", n.Title)
	if n.Description != "" {
		b.WriteString(n.Description + "\n\n")
	}
	if len(n.Techniques) > 0 {
		fmt.Fprintf(&b, "**ATT&CK:** %s  \n", strings.Join(n.Techniques, ", "))
	}
	fmt.Fprintf(&b, "**Time range:** last %s  \n", n.TimeRange)
	if n.Owner != "" {
		fmt.Fprintf(&b, "**Owner:** %s  \n", n.Owner)
	}
	if len(n.Cases) > 0 {
		fmt.Fprintf(&b, "**Investigations:** %s  \n", strings.Join(n.Cases, ", "))
	}
	b.WriteString("\n")
	for _, c := range n.Cells {
		switch c.Kind {
		case KindMarkdown:
			b.WriteString(c.Text + "\n\n")
		case KindSearch:
			title := c.Title
			if title == "" {
				title = "Search"
			}
			fmt.Fprintf(&b, "### %s\n\n", title)
			if c.Text != "" {
				b.WriteString(c.Text + "\n\n")
			}
			fence := "```"
			for strings.Contains(c.Query, fence) {
				fence += "`"
			}
			fmt.Fprintf(&b, "%sspl\n%s\n%s\n\n", fence, c.Query, fence)
			writeResult(&b, c.Result, rows)
		}
	}
	return []byte(b.String())
}

func writeResult(b *strings.Builder, r *Result, rows int) {
	if r == nil {
		b.WriteString("_Not run yet._\n\n")
		return
	}
	when := r.RanAt.UTC().Format(time.RFC3339)
	if r.Error != "" {
		fmt.Fprintf(b, "_Failed when it ran at %s: %s_\n\n", when, cell(r.Error))
		return
	}
	if len(r.Rows) == 0 {
		fmt.Fprintf(b, "_No results when it ran at %s._\n\n", when)
		return
	}
	cols := r.Columns
	if len(cols) == 0 {
		for k := range r.Rows[0] {
			cols = append(cols, k)
		}
	}
	if r.Kind == "events" {
		keep := cols[:0:0]
		for _, c := range cols {
			if c != "_raw" {
				keep = append(keep, c)
			}
		}
		cols = keep[:min(len(keep), 8)]
	}
	shown := r.Rows[:min(len(r.Rows), rows)]
	fmt.Fprintf(b, "_%d rows when it ran at %s", len(r.Rows), when)
	if r.Truncated {
		b.WriteString(", more not kept")
	}
	if len(shown) < len(r.Rows) {
		fmt.Fprintf(b, "; the first %d shown", len(shown))
	}
	b.WriteString("._\n\n")
	b.WriteString("| " + strings.Join(mapStrings(cols, cell), " | ") + " |\n")
	b.WriteString("|" + strings.Repeat(" --- |", len(cols)) + "\n")
	for _, row := range shown {
		vals := make([]string, len(cols))
		for i, c := range cols {
			vals[i] = cell(valueText(row[c]))
		}
		b.WriteString("| " + strings.Join(vals, " | ") + " |\n")
	}
	b.WriteString("\n")
}

func mapStrings(in []string, f func(string) string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

func valueText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, y := range x {
			parts[i] = valueText(y)
		}
		return strings.Join(parts, ", ")
	case float64, bool, json.Number:
		return fmt.Sprint(x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// cell makes text safe inside a Markdown table cell: one line, pipes and
// HTML escaped so no table, link or markup can be injected from event data.
// cellEscaper keeps a value from the data plain text in a Markdown table:
// line breaks become spaces, < > & become entities and every other
// character Markdown gives a meaning gets a backslash, so a value cannot
// make a link, an image, emphasis or a new table cell.
var cellEscaper = func() *strings.Replacer {
	pairs := []string{"\r\n", " ", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "&", "&amp;"}
	for _, c := range "\\`*_{}[]()#+-.!|~:" {
		pairs = append(pairs, string(c), "\\"+string(c))
	}
	return strings.NewReplacer(pairs...)
}()

func cell(s string) string {
	if len(s) > 300 {
		s = cutUTF8(s, 300) + "…"
	}
	return cellEscaper.Replace(s)
}

// cutUTF8 cuts s to at most n bytes on a character boundary.
func cutUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
