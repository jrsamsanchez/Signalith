// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// fetchLimits bound one download.
type fetchLimits struct {
	// MaxBytes stops reading after this many bytes. It must be above 0:
	// a download with no budget left reads nothing.
	MaxBytes int64
	// Partial keeps what was read when MaxBytes is reached, instead of
	// failing; tests use it to preview large feeds.
	Partial bool
	// Refuse fails at once when the server says the feed is larger.
	Refuse int64
	// Pages caps TAXII pages.
	Pages int
	// Keep, when above 0, keeps only this many indicators (a test's
	// samples) while counting all of them.
	Keep int
	// Timeout is for messages; the context enforces it.
	Timeout time.Duration
}

// fetched is a downloaded and parsed feed, before it is stored.
type fetched struct {
	Result *ParseResult
	Bytes  int64
	// Truncated is set when a limit stopped the download early and only
	// part of the feed was read.
	Truncated bool
	// Incomplete is set when a TAXII pull stopped early because the server
	// was slow: what was read is stored, but nothing is removed, since the
	// rest of the collection was not seen.
	Incomplete bool
	Note       string
	html       bool
	json       bool
}

// TooBigError is a download over the size limit.
type TooBigError struct{ Max int64 }

func (e *TooBigError) Error() string {
	return fmt.Sprintf("The feed is larger than %s, the most Signalith downloads.", fmtBytes(e.Max))
}

func fmtBytes(n int64) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%d MB", n>>20)
	}
	return fmt.Sprintf("%d KB", max(n>>10, 1))
}

// httpGet downloads one URL with a feed's credentials. A truncated body (with
// lim.Partial) is cut after its last full line.
func (f *Feeds) httpGet(ctx context.Context, fd Feed, rawURL, accept string, lim fetchLimits) ([]byte, bool, http.Header, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false, nil, plain("The URL is not valid.")
	}
	if err := checkHost(u, f.AllowLoopback, f.Protected); err != nil {
		return nil, false, nil, err
	}
	max := lim.MaxBytes
	if max <= 0 {
		// The caller's budget is spent; never fall back to a larger one.
		return nil, false, nil, &TooBigError{Max: max}
	}
	names := make([]string, 0, len(fd.Headers))
	for k := range fd.Headers {
		names = append(names, k)
	}
	ctx = context.WithValue(ctx, secretHeadersKey{}, names)
	ctx = context.WithValue(ctx, dialTrackKey{}, &dialTrack{})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, nil, plain("The URL is not valid.")
	}
	req.Header.Set("User-Agent", "Signalith threat intel")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for k, v := range fd.Headers {
		req.Header.Set(k, fd.expand(v))
	}
	if fd.Username != "" {
		req.SetBasicAuth(fd.Username, fd.expand(fd.Password))
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, false, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, false, resp.Header, &HTTPError{Code: resp.StatusCode, Status: resp.Status, Said: serverSaid(resp.Header.Get("Content-Type"), body)}
	}
	if lim.Refuse > 0 && resp.ContentLength > lim.Refuse {
		return nil, false, resp.Header, &TooBigError{Max: lim.Refuse}
	}
	if resp.ContentLength > max && !lim.Partial {
		return nil, false, resp.Header, &TooBigError{Max: max}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, false, resp.Header, err
	}
	if int64(len(data)) <= max {
		return data, false, resp.Header, nil
	}
	if !lim.Partial {
		return nil, false, resp.Header, &TooBigError{Max: max}
	}
	data = data[:max]
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		data = data[:i+1]
	}
	return data, true, resp.Header, nil
}

// serverSaid returns a short message from an error response, when it is
// plain text or JSON rather than a web page.
func serverSaid(contentType string, body []byte) string {
	mt, _, _ := mime.ParseMediaType(contentType)
	if mt != "" && mt != "text/plain" && !strings.HasSuffix(mt, "json") {
		return ""
	}
	s := strings.TrimSpace(string(body))
	if s == "" || !utf8.ValidString(s) || looksHTML([]byte(s)) {
		return ""
	}
	// A JSON error, such as a TAXII server's {"title": ..., "description": ...},
	// reads better as its message than as raw JSON.
	if strings.HasPrefix(s, "{") {
		var obj map[string]any
		if json.Unmarshal([]byte(s), &obj) != nil {
			return ""
		}
		s = ""
		for _, k := range []string{"description", "message", "error_description", "detail", "error", "title"} {
			if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
				s = strings.TrimSpace(v)
				break
			}
		}
		if s == "" {
			return ""
		}
	}
	s, _, _ = strings.Cut(s, "\n")
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// looksHTML reports whether a download is a web page.
func looksHTML(data []byte) bool {
	head := bytes.ToLower(bytes.TrimSpace(data[:min(len(data), 1024)]))
	return bytes.HasPrefix(head, []byte("<!doctype html")) || bytes.HasPrefix(head, []byte("<html")) ||
		bytes.Contains(head, []byte("<head>")) || bytes.Contains(head, []byte("<body"))
}

// fetch downloads and parses a feed without storing it.
func (f *Feeds) fetch(ctx context.Context, fd Feed, now time.Time, lim fetchLimits) (*fetched, error) {
	if fd.Kind == KindTAXII {
		return f.fetchTAXII(ctx, fd, now, lim)
	}
	data, truncated, _, err := f.httpGet(ctx, fd, fd.URL, "", lim)
	if err != nil {
		return nil, err
	}
	out := &fetched{Bytes: int64(len(data)), Truncated: truncated, html: looksHTML(data), json: looksLikeJSON(data)}
	res, err := Parse(data, ParseOptions{Format: fd.Format, Type: fd.Type, Column: fd.Column, Now: now, Keep: lim.Keep})
	if err != nil {
		if truncated && (fd.Format == FormatSTIX || out.json) {
			return nil, plain("The feed is larger than %s, too large to preview, since its JSON cannot be read in part. It can still be added: downloads allow up to %s.", fmtBytes(lim.MaxBytes), fmtBytes(f.maxBytes()))
		}
		return nil, plain("%s", sentence(err.Error()))
	}
	out.Result = res
	if truncated {
		out.Note = fmt.Sprintf("Only the first %s were checked; the full feed is larger.", fmtBytes(lim.MaxBytes))
	}
	return out, nil
}

// emptyMessage explains a download with no indicators.
func emptyMessage(got *fetched) string {
	res := got.Result
	switch {
	case got.html:
		return "The server sent a web page, not a feed. Check the URL: a feed's address is usually a download link on that page."
	case got.json && res.Format != FormatSTIX:
		return "The server sent JSON that is not STIX 2.1. Signalith reads STIX 2.1 bundles, TAXII 2.1 servers, CSV files and plain lists."
	case res.Skipped > 0:
		return fmt.Sprintf("None of the %d values were valid indicators (the first was %q). Check the feed's format, type and column.", res.Skipped, res.Example)
	case res.Reserved > 0:
		return fmt.Sprintf("The feed lists only private or reserved addresses (%d), which Signalith skips so they never match your own network.", res.Reserved)
	}
	return "The feed has no indicators."
}

// sentence capitalizes a message and ends it with a period.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	r, n := utf8.DecodeRuneInString(s)
	s = strings.ToUpper(string(r)) + s[n:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
