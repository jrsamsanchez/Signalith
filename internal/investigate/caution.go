// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package investigate

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Planted log text can still talk a model into "benign". Nothing closes a
// finding by itself, but a busy analyst may follow a confident verdict,
// so a benign verdict reached on data that looked like it addressed an AI
// carries a fixed caution, whether Signalith saw such text or the model
// reported it.

// instructionLike matches text that addresses an AI or tries to set the
// verdict: "ignore previous instructions", "you are an AI", "mark this as
// benign", "authorized penetration test". It is a hint for the caution,
// not a filter: the data is sent as it is.
var instructionLike = regexp.MustCompile(`(?i)` +
	`\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(instructions?|rules|prompts?|guidelines)\b` +
	`|\b(system|developer) (prompt|message|instructions?)\b` +
	`|\byou are (now )?(an? )?(ai|assistant|chatbot|language model|llm)\b` +
	`|\b(as an ai|dear ai|attention ai|ai (assistant|model|analyst|agent)s?\b[^.\n]{0,20}\b(must|should|will|shall))` +
	`|\b(mark|classify|label|treat|report|consider|close)\b[^.\n]{0,30}\b(as )?(benign|false[ _-]positive|harmless|not malicious)\b` +
	`|\b(authori[sz]ed|approved|sanctioned)\b[^.\n]{0,20}\b(pen(etration)?[ -]?test(ing)?|red[ -]?team(ing)?)\b` +
	`|\bdo not (alert|escalate|investigate|flag)\b`)

// InstructionLike reports whether text looks like it addresses an AI.
func InstructionLike(text string) bool { return instructionLike.MatchString(text) }

// Caution is shown beside a benign verdict reached on data that looked
// like it tried to instruct an AI.
const Caution = "Text in this finding's data looked like instructions to an AI, so this \"benign\" verdict may have been steered by planted log text. " +
	"Check the evidence yourself before closing the finding."

// StoppedNote is added to a finding whose AI investigation the masked-value
// guard stopped: planted text may have done that on purpose, to keep AI
// away from the findings an attacker cares about.
const StoppedNote = "Investigate with AI was stopped: the AI model asked for a search that could reveal a masked value. " +
	"Text in this finding's events may be steering AI investigations on purpose; investigate it by hand."

// truthy reads a JSON value a model gave as a yes or no: true, "true",
// "yes" or 1.
func truthy(v json.RawMessage) bool {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		s = strings.ToLower(strings.TrimSpace(s))
		return s == "true" || s == "yes"
	}
	var n float64
	return json.Unmarshal(v, &n) == nil && n != 0
}
