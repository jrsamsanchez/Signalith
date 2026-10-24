// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package casetemplates keeps the templates a case can be opened from: a
// severity, a description to fill in and the tasks most investigations
// of that kind need, such as "Reset the user's password" for an account
// takeover. A few come built in; admins add their own.
//
// The admins' templates live in one document of the runtime index
// (<prefix>_runtime/casetemplates), so every server and every tenant's
// server keeps its own.
package casetemplates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Limits on the admins' templates.
const (
	MaxTemplates   = 50
	MaxName        = 80
	MaxDescription = 4000
)

// Template is one kind of investigation.
type Template struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Tasks       []string `json:"tasks,omitempty"`
	// Builtin templates come with Signalith and cannot be changed.
	Builtin bool `json:"builtin,omitempty"`
}

// Builtin are the templates every server has.
var Builtin = []Template{
	{ID: "phishing", Name: "Phishing", Severity: "medium", Builtin: true,
		Description: "Who received the message, who clicked or replied, and what was entered or opened.",
		Tasks: []string{
			"Find every recipient of the message",
			"Find who clicked the link or opened the attachment",
			"Block the sender and the links at the mail gateway and proxy",
			"Reset the passwords of anyone who entered them",
			"Remove the message from every mailbox",
		}},
	{ID: "account-compromise", Name: "Account compromise", Severity: "high", Builtin: true,
		Description: "A user's account was used by someone else: since when, from where, and what it reached.",
		Tasks: []string{
			"Confirm with the user which sign-ins were theirs",
			"Disable the account or end its sessions",
			"Reset the password and the second factor",
			"Review what the account changed or reached since the first bad sign-in",
			"Check mail forwarding rules and app consents",
		}},
	{ID: "malware", Name: "Malware on a host", Severity: "high", Builtin: true,
		Description: "Malicious code ran on a host: how it got there, what it did, and whether it spread.",
		Tasks: []string{
			"Isolate the host",
			"Find how the malware arrived",
			"Collect the file hashes and look for them on other hosts",
			"Check the host's outbound connections for command and control",
			"Rebuild or clean the host and confirm it is healthy",
		}},
	{ID: "ransomware", Name: "Ransomware", Severity: "critical", Builtin: true,
		Description: "Files were encrypted or are being encrypted. Contain first, then scope.",
		Tasks: []string{
			"Isolate the affected hosts and shares",
			"Disable the accounts used to spread",
			"Find the first host and how the attacker got in",
			"Check that backups are intact and offline",
			"Tell the people your incident plan names",
			"Restore and confirm before reconnecting",
		}},
	{ID: "insider", Name: "Insider or data loss", Severity: "medium", Builtin: true,
		Description: "Data left, or may have left, through someone with access.",
		Tasks: []string{
			"Agree the scope with HR and legal before contacting the person",
			"List the data that was accessed or moved",
			"Preserve the evidence (pin events, export the case)",
			"Remove the access that is no longer needed",
		}},
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// Validate checks the admins' templates and tidies them.
func Validate(ts []Template) ([]Template, error) {
	if len(ts) > MaxTemplates {
		return nil, fmt.Errorf("keep at most %d templates", MaxTemplates)
	}
	out := make([]Template, 0, len(ts))
	ids := map[string]bool{}
	for _, b := range Builtin {
		ids[b.ID] = true
	}
	for _, t := range ts {
		t.Name, t.Description, t.Builtin = strings.TrimSpace(t.Name), strings.TrimSpace(t.Description), false
		switch {
		case !idPattern.MatchString(t.ID):
			return nil, errors.New("a template's ID must be lower-case letters, digits and dashes, at most 40")
		case ids[t.ID]:
			return nil, fmt.Errorf("there is already a template with the ID %s", t.ID)
		case t.Name == "" || utf8.RuneCountInString(t.Name) > MaxName || strings.ContainsFunc(t.Name, isControl):
			return nil, fmt.Errorf("a template needs a name of 1 to %d characters", MaxName)
		case len(t.Description) > MaxDescription:
			return nil, fmt.Errorf("template %q: the description is longer than %d characters", t.Name, MaxDescription)
		case t.Severity != "" && !slices.Contains(cases.Severities, t.Severity):
			return nil, fmt.Errorf("template %q: severity must be one of %s", t.Name, strings.Join(cases.Severities, ", "))
		case len(t.Tasks) > cases.MaxTasks:
			return nil, fmt.Errorf("template %q: at most %d tasks", t.Name, cases.MaxTasks)
		}
		for i, task := range t.Tasks {
			clean, err := cases.CleanTaskTitle(task)
			if err != nil {
				return nil, fmt.Errorf("template %q: %w", t.Name, err)
			}
			t.Tasks[i] = clean
		}
		ids[t.ID] = true
		out = append(out, t)
	}
	return out, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// Find returns a template by ID: a built-in one or one of custom.
func Find(custom []Template, id string) (Template, bool) {
	for _, t := range slices.Concat(Builtin, custom) {
		if t.ID == id {
			t.Tasks = slices.Clone(t.Tasks)
			return t, true
		}
	}
	return Template{}, false
}

// Store keeps the admins' templates.
type Store interface {
	Get(ctx context.Context) ([]Template, error)
	Put(ctx context.Context, ts []Template) error
}

// Memory keeps them in memory, for a server without OpenSearch and for
// tests.
type Memory struct {
	mu sync.Mutex
	ts []Template
}

func (m *Memory) Get(context.Context) ([]Template, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.ts), nil
}

func (m *Memory) Put(_ context.Context, ts []Template) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ts = clone(ts)
	return nil
}

func clone(ts []Template) []Template {
	out := slices.Clone(ts)
	for i := range out {
		out[i].Tasks = slices.Clone(out[i].Tasks)
	}
	return out
}

// Docs reads and writes a document with its version. *store.Client has
// it.
type Docs interface {
	cluster.Doer
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

// OpenSearch keeps them in the runtime index.
type OpenSearch struct {
	Docs   Docs
	Prefix string

	mu    sync.Mutex
	ready bool
}

const (
	kind  = "case_templates"
	docID = "casetemplates"
)

type doc struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	Body struct {
		Templates []Template `json:"templates"`
	} `json:"body"`
}

func (o *OpenSearch) index() string { return cluster.RuntimeIndex(o.Prefix) }

func (o *OpenSearch) Get(ctx context.Context) ([]Template, error) {
	ts, _, err := o.read(ctx)
	return ts, err
}

func (o *OpenSearch) read(ctx context.Context) ([]Template, store.Version, error) {
	raw, v, found, err := o.Docs.Get(ctx, o.index(), docID)
	if err != nil || !found {
		return nil, v, err
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, v, err
	}
	return d.Body.Templates, v, nil
}

// Put replaces the templates: the admin's latest list wins.
func (o *OpenSearch) Put(ctx context.Context, ts []Template) error {
	d := doc{Kind: kind, At: time.Now().UTC()}
	d.Body.Templates = ts
	var err error
	for range 3 {
		var v store.Version
		if _, v, err = o.read(ctx); err != nil {
			return err
		}
		if v.IsZero() {
			if err = o.ensure(ctx); err != nil {
				return err
			}
			_, err = o.Docs.Create(ctx, o.index(), docID, d, true)
		} else {
			_, err = o.Docs.PutIf(ctx, o.index(), docID, d, v, true)
		}
		if !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

func (o *OpenSearch) ensure(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ready {
		return nil
	}
	if err := cluster.EnsureRuntime(ctx, o.Docs, o.Prefix); err != nil {
		return err
	}
	o.ready = true
	return nil
}
