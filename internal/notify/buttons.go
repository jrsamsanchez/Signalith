// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// The buttons of an interactive channel (see Channel.Interactive): a
// finding message carries Acknowledge, an approval message Approve and
// Reject. Each button's value names what it acts on and is signed with
// the channel's own secret (the Slack app's signing secret, or the Teams
// app's client secret), so a message someone else posted to the chat, say
// with a webhook URL they found, cannot carry a button Signalith acts on.

// Button actions.
const (
	ButtonApprove = "approve"
	ButtonReject  = "reject"
	ButtonAck     = "ack"
)

// Button is what one button acts on: the action, the finding (ack) or
// playbook run (approve and reject) and, for those, the step that waits.
type Button struct {
	Action string
	ID     string
	Step   int
}

// buttonVersion starts every button value.
const buttonVersion = "v1"

// ErrBadButton is a button value Signalith did not sign for the channel,
// or one signed with a secret the channel no longer has.
var ErrBadButton = errors.New("this button was not sent by Signalith for this channel, or the channel's secret changed since; use the Approvals or Findings page instead")

// buttonSecret is the secret a channel signs its buttons with.
func buttonSecret(c Channel) string {
	switch c.Type {
	case TypeSlack:
		return c.SigningSecret
	case TypeTeamsApp:
		return c.AppPassword
	}
	return ""
}

// buttonMAC is the signature of b on channel c, with the channel's secret.
func buttonMAC(c Channel, b Button) string {
	// A key of its own, so the signature never matches anything else
	// made with the secret.
	k := hmac.New(sha256.New, []byte(buttonSecret(c)))
	k.Write([]byte("signalith chat buttons " + buttonVersion))
	mac := hmac.New(sha256.New, k.Sum(nil))
	mac.Write([]byte(c.ID + "|" + b.Action + "|" + b.ID + "|" + strconv.Itoa(b.Step)))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// SignButton returns the value of a button of channel c, as in
// v1|approve|<run>|2|<signature>.
func SignButton(c Channel, b Button) string {
	return strings.Join([]string{buttonVersion, b.Action, b.ID, strconv.Itoa(b.Step), buttonMAC(c, b)}, "|")
}

// ParseButton checks a button value against channel c and returns what
// it acts on, or ErrBadButton.
func ParseButton(c Channel, v string) (Button, error) {
	if buttonSecret(c) == "" || len(v) > 500 {
		return Button{}, ErrBadButton
	}
	parts := strings.Split(v, "|")
	if len(parts) != 5 || parts[0] != buttonVersion {
		return Button{}, ErrBadButton
	}
	step, err := strconv.Atoi(parts[3])
	if err != nil || step < 0 || step > 1000 {
		return Button{}, ErrBadButton
	}
	b := Button{Action: parts[1], ID: parts[2], Step: step}
	switch b.Action {
	case ButtonApprove, ButtonReject, ButtonAck:
	default:
		return Button{}, ErrBadButton
	}
	if b.ID == "" || !hmac.Equal([]byte(parts[4]), []byte(buttonMAC(c, b))) {
		return Button{}, ErrBadButton
	}
	return b, nil
}

// buttons lists the buttons a message carries on channel c: none unless
// the channel is interactive; Approve only where the channel lets it
// approve.
func (m Message) buttons(c Channel) []Button {
	if !c.Interactive() {
		return nil
	}
	switch m.Kind {
	case KindFinding:
		if m.FindingID == "" {
			return nil
		}
		return []Button{{Action: ButtonAck, ID: m.FindingID}}
	case KindApproval:
		if m.RunID == "" {
			return nil
		}
		var out []Button
		if c.ApproveInChat {
			out = append(out, Button{Action: ButtonApprove, ID: m.RunID, Step: m.Step})
		}
		return append(out, Button{Action: ButtonReject, ID: m.RunID, Step: m.Step})
	}
	return nil
}

// ButtonLabel is the words on a button.
func ButtonLabel(action string) string {
	switch action {
	case ButtonApprove:
		return "Approve"
	case ButtonReject:
		return "Reject"
	case ButtonAck:
		return "Acknowledge"
	}
	return action
}
