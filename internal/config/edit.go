// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/securefile"
	"gopkg.in/yaml.v3"
)

// SetAdminPasswordHash writes hash as auth.admin_password_hash in the
// config file at path and changes nothing else. Comments, layout and the
// other settings stay exactly as they are, and settings that came from
// environment variables (such as SIGNALITH_OPENSEARCH_PASSWORD) are not
// copied into the file, as they would be by loading and saving it.
func SetAdminPasswordHash(path, hash string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config file %s not found; create one with: signalith init", path)
		}
		return err
	}
	out, err := setScalar(data, []string{"auth", "admin_password_hash"}, hash)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	// The new file keeps the old one's owner, permissions and (on
	// Windows) access list.
	return securefile.WriteFile(path, out)
}

// SetOpenSearch writes url and the certificate files Signalith signs in
// to OpenSearch with as opensearch.url, ca_file, cert_file and key_file in
// the config file at path, changing nothing else in it.
func SetOpenSearch(path, url, caFile, certFile, keyFile string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, kv := range [][2]string{{"url", url}, {"ca_file", caFile}, {"cert_file", certFile}, {"key_file", keyFile}} {
		if data, err = setScalar(data, []string{"opensearch", kv[0]}, kv[1]); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return securefile.WriteFile(path, data)
}

// setScalar returns the YAML document data with the value at keys set to
// value. An existing single-line value is replaced in the text itself, so
// nothing else in the file moves; otherwise the key is added and the
// document is written out again (keeping its comments).
func setScalar(data []byte, keys []string, value string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	node := doc.Content[0]
	if node.Kind != yaml.MappingNode {
		return nil, errors.New("the file is not a YAML mapping of settings")
	}
	for i, key := range keys {
		var next *yaml.Node
		for j := 0; j+1 < len(node.Content); j += 2 {
			if node.Content[j].Value == key {
				next = node.Content[j+1]
				break
			}
		}
		last := i == len(keys)-1
		if next == nil {
			// Add the missing key, then write the whole document out.
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			if last {
				next = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
			}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, next)
			if last {
				return encode(&doc)
			}
		} else if !last && next.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s is not a section of settings", strings.Join(keys[:i+1], "."))
		}
		node = next
	}
	if node.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("%s is not a single value", strings.Join(keys, "."))
	}
	if out, ok := replaceInLine(data, node, value); ok && valueAt(out, keys) == value {
		return out, nil
	}
	node.Value, node.Tag, node.Style = value, "!!str", 0
	return encode(&doc)
}

func encode(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(4)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

// replaceInLine swaps a plain or quoted scalar that sits on one line for
// value, double-quoted, keeping the rest of the line (such as a comment).
func replaceInLine(data []byte, node *yaml.Node, value string) ([]byte, bool) {
	if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || node.Line < 1 || node.Column < 1 {
		return nil, false
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if node.Line > len(lines) {
		return nil, false
	}
	line := lines[node.Line-1]
	start := byteOffset(line, node.Column)
	rest := line[start:]
	var end int
	switch {
	case node.Style&yaml.DoubleQuotedStyle != 0:
		end = closingQuote(rest, '"', '\\')
	case node.Style&yaml.SingleQuotedStyle != 0:
		end = closingQuote(rest, '\'', 0)
	default:
		if !bytes.HasPrefix(rest, []byte(node.Value)) {
			return nil, false
		}
		end = len(node.Value)
	}
	if end <= 0 {
		return nil, false
	}
	var out bytes.Buffer
	for i := 0; i < node.Line-1; i++ {
		out.Write(lines[i])
	}
	out.Write(line[:start])
	if node.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0 && plainScalar(value) {
		// A value that was not quoted stays so when it can.
		out.WriteString(value)
	} else {
		out.WriteString(strconv.Quote(value))
	}
	out.Write(rest[end:])
	for i := node.Line; i < len(lines); i++ {
		out.Write(lines[i])
	}
	return out.Bytes(), true
}

// safePlain matches text that can be written without quotes: no spaces,
// quotes, # or other characters YAML treats specially.
var safePlain = regexp.MustCompile(`^[A-Za-z0-9_$][A-Za-z0-9_.:$/+=-]*$`)

// plainScalar reports whether v reads back as the same string when
// written without quotes (so not true, 123 or null).
func plainScalar(v string) bool {
	if !safePlain.MatchString(v) || strings.HasSuffix(v, ":") {
		return false
	}
	var back map[string]any
	if yaml.Unmarshal([]byte("v: "+v), &back) != nil {
		return false
	}
	s, ok := back["v"].(string)
	return ok && s == v
}

// byteOffset returns where a YAML column (counted in characters from 1)
// starts in line.
func byteOffset(line []byte, column int) int {
	start := 0
	for col := 1; col < column && start < len(line); col++ {
		_, size := utf8.DecodeRune(line[start:])
		start += size
	}
	return start
}

// valueAt returns the text value at keys in a YAML document, or "" when
// there is none, to check an edit before trusting it.
func valueAt(data []byte, keys []string) string {
	var m map[string]any
	if yaml.Unmarshal(data, &m) != nil {
		return ""
	}
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = mm[k]
	}
	s, _ := v.(string)
	return s
}

// closingQuote returns the index just past the quote that closes the
// quoted value at the start of b, or -1.
func closingQuote(b []byte, quote, escape byte) int {
	if len(b) == 0 || b[0] != quote {
		return -1
	}
	for i := 1; i < len(b); i++ {
		switch {
		case escape != 0 && b[i] == escape:
			i++
		case b[i] == quote:
			if escape == 0 && i+1 < len(b) && b[i+1] == quote {
				i++ // '' inside a single-quoted value
				continue
			}
			return i + 1
		}
	}
	return -1
}
