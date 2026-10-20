// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

const plainFeedsFile = `feeds:
  - name: otx
    url: https://otx.example.com/feed.txt
    headers:
      X-OTX-API-KEY: plain-otx-key
    username: svc
    password: plain-feed-pw
  - name: open
    url: https://open.example.com/list.txt
kept:
  - name: old
    until: 2099-01-01T00:00:00Z
`

// TestFeedsFileEncrypted checks that the feeds file still reads plain
// values, that ResealFeedsFile encrypts them (and nothing else), and that
// a value that cannot be decrypted stops only its feed, with a problem
// that says what to do.
func TestFeedsFileEncrypted(t *testing.T) {
	f := newTestFeeds(t)
	if err := os.WriteFile(f.File, []byte(plainFeedsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Load(); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.Get("otx"); got.Headers["X-OTX-API-KEY"] != "plain-otx-key" || got.Password != "plain-feed-pw" || got.Problem != "" {
		t.Fatalf("plain file: %+v", got)
	}

	seal := func(s secrets.Stored) (string, error) { return secrets.Seal(s.Field, s.Value) }
	var labels []string
	out, n, err := ResealFeedsFile([]byte(plainFeedsFile), func(s secrets.Stored) (string, error) {
		labels = append(labels, s.Label+" as "+s.Field)
		return seal(s)
	})
	if err != nil || n != 2 {
		t.Fatalf("reseal: n=%d err=%v", n, err)
	}
	want := []string{"feeds[otx] password as intel_feeds[otx].password", "feeds[otx] header X-OTX-API-KEY as intel_feeds[otx].headers.X-OTX-API-KEY"}
	if strings.Join(labels, "|") != strings.Join(want, "|") {
		t.Errorf("values passed: %q", labels)
	}
	text := string(out)
	if strings.Contains(text, "plain-otx-key") || strings.Contains(text, "plain-feed-pw") || strings.Count(text, "enc:v1:") != 2 ||
		!strings.Contains(text, "name: old") || !strings.HasPrefix(text, "# Threat intel feeds added") {
		t.Errorf("resealed file:\n%s", out)
	}
	if again, n, _ := ResealFeedsFile(out, seal); n != 0 || string(again) != text {
		t.Error("resealing an encrypted file should change nothing")
	}
	if err := os.WriteFile(f.File, out, 0o600); err != nil {
		t.Fatal(err)
	}
	g := newTestFeeds(t)
	g.File = f.File
	if got, _ := g.Get("otx"); got.Headers["X-OTX-API-KEY"] != "plain-otx-key" || got.Password != "plain-feed-pw" || got.Problem != "" {
		t.Fatalf("encrypted file: %+v", got)
	}

	// Another master key: the feed shows a problem, the other one runs.
	other := secrets.NewKeyring(t.TempDir())
	if _, err := other.Seal("x", "make a key"); err != nil {
		t.Fatal(err)
	}
	prev := secrets.Default()
	secrets.SetDefault(other)
	defer secrets.SetDefault(prev)
	h := newTestFeeds(t)
	h.File = f.File
	got, _ := h.Get("otx")
	if !strings.Contains(got.Problem, "The saved password and header X-OTX-API-KEY cannot be decrypted with this server's master key") {
		t.Errorf("problem = %q", got.Problem)
	}
	if open, _ := h.Get("open"); open.Problem != "" {
		t.Errorf("a feed without secrets should still run: %q", open.Problem)
	}
	// Entering them again fixes it, and the values are written with the
	// key in use.
	if _, err := h.UpdateFeed(context.Background(), "otx", FeedInput{Name: "otx", URL: "https://otx.example.com/feed.txt", Username: "svc",
		Password: "new-pw", Headers: []HeaderInput{{Name: "X-OTX-API-KEY", Value: "new-key"}}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.Get("otx"); got.Problem != "" || got.Password != "new-pw" {
		t.Errorf("after entering again: %+v", got)
	}
	data, _ := os.ReadFile(f.File)
	if !strings.Contains(string(data), "enc:v1:"+other.KeyID()+":") || strings.Contains(string(data), "new-key") {
		t.Errorf("rewritten file:\n%s", data)
	}
}

// A typed key or password that starts like an encrypted value would be
// stored as it is, so it is refused.
func TestFeedInputRefusesEncryptedLookingValues(t *testing.T) {
	in := FeedInput{Name: "my-feed", URL: "https://feeds.example.com/list.txt",
		Headers: []HeaderInput{{Name: "X-Key", Value: "enc:v1:0011aabb:AAAA"}}, Username: "me", Password: "enc:v2:x"}
	_, probs := in.spec(nil)
	var msgs []string
	for _, p := range probs {
		msgs = append(msgs, p.Msg)
	}
	if got := strings.Join(msgs, "; "); strings.Count(got, "how encrypted values look") != 2 {
		t.Errorf("problems: %s", got)
	}
	in.Headers[0].Value, in.Password = "enc:not-encrypted", "enc:hunter2"
	if _, probs := in.spec(nil); len(probs) != 0 {
		t.Errorf("plain values starting with enc: refused: %v", probs)
	}
}
