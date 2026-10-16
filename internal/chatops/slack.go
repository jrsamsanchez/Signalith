package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Slack sends a button click to the app's Interactivity Request URL as a
// form with one field, payload, holding JSON, and signs the request with
// the app's signing secret: X-Slack-Signature is v0= and the hex
// HMAC-SHA256 of "v0:<X-Slack-Request-Timestamp>:<body>".
// https://api.slack.com/authentication/verifying-requests-from-slack

// SlackMaxAge is how old a Slack request may be, either way, before it
// is refused as a replay.
const SlackMaxAge = 5 * time.Minute

// Errors of a Slack request that is not signed right.
var (
	errSlackUnsigned = errors.New("the request has no Slack signature")
	errSlackOld      = errors.New("the request is too old (or the clocks differ by more than five minutes)")
	errSlackBadSig   = errors.New("the Slack signature does not match: check the signing secret")
)

// VerifySlack checks a Slack request's signature and age.
func VerifySlack(secret string, h http.Header, body []byte, now time.Time) error {
	ts, sig := h.Get("X-Slack-Request-Timestamp"), h.Get("X-Slack-Signature")
	if ts == "" || !strings.HasPrefix(sig, "v0=") {
		return errSlackUnsigned
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errSlackUnsigned
	}
	if d := now.Sub(time.Unix(sec, 0)); d > SlackMaxAge || d < -SlackMaxAge {
		return errSlackOld
	}
	if !hmac.Equal([]byte(sig), []byte(SlackSign(secret, ts, body))) {
		return errSlackBadSig
	}
	return nil
}

// SlackSign returns the X-Slack-Signature of a request: what Slack sends,
// and what tests send.
func SlackSign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// slackPayload is the part of a block_actions payload Signalith reads.
type slackPayload struct {
	Type string `json:"type"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
		TeamID   string `json:"team_id"`
	} `json:"user"`
	Team struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
	} `json:"team"`
	Enterprise *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"enterprise"`
	TriggerID   string `json:"trigger_id"`
	ResponseURL string `json:"response_url"`
	Actions     []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
		ActionTS string `json:"action_ts"`
	} `json:"actions"`
	// Message is the message the button is in, which the answer replaces.
	Message *struct {
		Text   string            `json:"text"`
		Blocks []json.RawMessage `json:"blocks"`
	} `json:"message"`
}

// parseSlack reads a click's payload from the form body.
func parseSlack(body []byte) (slackPayload, error) {
	var p slackPayload
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return p, errors.New("the request is not a form")
	}
	raw := form.Get("payload")
	if raw == "" {
		return p, errors.New("the request has no payload")
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, errors.New("the payload is not JSON")
	}
	return p, nil
}

// SlackResponseURLAllowed reports whether a response_url is Slack's, so
// an answer (which may hold a link to Signalith) only goes to Slack.
func SlackResponseURLAllowed(u *url.URL) bool {
	return u != nil && slackResponseURL.MatchString(u.String())
}

// slackResponseURL matches the response_url Slack sends with a click, as
// in https://hooks.slack.com/actions/T0123/4567/AbCd.
var slackResponseURL = regexp.MustCompile(`^https://hooks\.slack(-gov)?\.com(:443)?(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+$`)

// slackButtonPrefix starts the action_id of Signalith's buttons.
const slackButtonPrefix = "signalith_"

// slackReplace returns blocks without Signalith's buttons, but for its
// link button, and with outcome added after them, to replace the message
// a button was clicked in, so nobody clicks it again.
func slackReplace(blocks []json.RawMessage, outcome string) []any {
	out := make([]any, 0, len(blocks)+1)
	for _, raw := range blocks {
		var b map[string]any
		if json.Unmarshal(raw, &b) != nil {
			continue
		}
		if b["type"] == "actions" {
			els, _ := b["elements"].([]any)
			var keep []any
			for _, e := range els {
				m, _ := e.(map[string]any)
				id, _ := m["action_id"].(string)
				if strings.HasPrefix(id, slackButtonPrefix) && m["url"] == nil {
					continue
				}
				keep = append(keep, e)
			}
			if len(keep) == 0 {
				continue
			}
			b["elements"] = keep
		}
		out = append(out, b)
	}
	return append(out, map[string]any{"type": "context", "elements": []any{
		map[string]any{"type": "plain_text", "text": cutRunes(outcome, 2000), "emoji": true},
	}})
}

// slackEscape escapes the characters Slack's mrkdwn gives meaning to.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func cutRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
