// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// What Slack and Teams send is read before it is trusted only as far as
// checking its signature needs; these keep the readers from failing on
// anything.

func FuzzSlackPayload(f *testing.F) {
	f.Add([]byte(url.Values{"payload": {`{"type":"block_actions","actions":[{"action_id":"signalith_ack","value":"v1|ack|f|0|00"}],"message":{"blocks":[{"type":"actions","elements":[{"action_id":"signalith_ack"}]}]}}`}}.Encode()))
	f.Add([]byte("payload=%7B%7D"))
	f.Add([]byte("%zz"))
	f.Fuzz(func(t *testing.T, body []byte) {
		h := http.Header{}
		h.Set("X-Slack-Request-Timestamp", "1700000000")
		h.Set("X-Slack-Signature", "v0=00")
		_ = VerifySlack("secret", h, body, time.Unix(1700000000, 0))
		p, err := parseSlack(body)
		if err != nil || p.Message == nil {
			return
		}
		out := slackReplace(p.Message.Blocks, "done")
		if _, err := json.Marshal(out); err != nil {
			t.Fatalf("replacement does not encode: %v", err)
		}
	})
}

func FuzzTeamsActivity(f *testing.F) {
	f.Add([]byte(`{"type":"message","text":"<at>Signalith</at> link ABCDE-12345","conversation":{"conversationType":"channel"}}`))
	f.Add([]byte(`{"type":"invoke","value":{"action":{"verb":"signalith.ack","data":{"signalith":1}}}}`))
	f.Add([]byte(`{"text":"<at>unclosed"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var a activity
		if json.Unmarshal(body, &a) != nil {
			return
		}
		_ = a.tenant()
		_, _ = a.botAdded(), a.botRemoved()
		_ = mentionText(a.Text)
		_, _ = a.Value.Action.Data["signalith"].(string)
	})
}
