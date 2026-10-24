// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cases

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Limits on a case's tasks.
const (
	MaxTasks     = 100
	MaxTaskTitle = 200
)

// Task is one step of an investigation, such as "Reset the user's
// password": a checklist the case's people work through, often from a
// template.
type Task struct {
	ID      string     `json:"id"`
	Title   string     `json:"title"`
	Owner   string     `json:"owner,omitempty"`
	Done    bool       `json:"done,omitempty"`
	DoneBy  string     `json:"done_by,omitempty"`
	DoneAt  *time.Time `json:"done_at,omitempty"`
	Created time.Time  `json:"created"`
}

// ErrTaskNotFound is a task the case does not have.
var ErrTaskNotFound = errors.New("no such task on this case")

// TaskUpdate changes a task. Nil fields stay as they are.
type TaskUpdate struct {
	Title *string `json:"title,omitempty"`
	Owner *string `json:"owner,omitempty"`
	Done  *bool   `json:"done,omitempty"`
}

// CleanTaskTitle trims a task's title and checks it.
func CleanTaskTitle(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" || utf8.RuneCountInString(t) > MaxTaskTitle || strings.ContainsFunc(t, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("a task needs a title of 1 to %d characters on one line", MaxTaskTitle)
	}
	return t, nil
}

// AddTasks appends tasks with the titles given, recording who added them.
func (c *Case) AddTasks(titles []string, author string, now time.Time) ([]Task, error) {
	if len(c.Tasks)+len(titles) > MaxTasks {
		return nil, fmt.Errorf("a case holds at most %d tasks", MaxTasks)
	}
	added := make([]Task, 0, len(titles))
	for _, t := range titles {
		title, err := CleanTaskTitle(t)
		if err != nil {
			return nil, err
		}
		added = append(added, Task{ID: NewEntryID(), Title: title, Created: now})
	}
	if len(added) == 0 {
		return added, nil
	}
	c.Tasks = append(c.Tasks, added...)
	c.History = append(c.History, findings.Change{Author: author, Field: "tasks", To: fmt.Sprintf("%d added", len(added)), Time: now})
	c.Updated = now
	return added, nil
}

// UpdateTask changes one task and records it. It reports whether anything
// changed.
func (c *Case) UpdateTask(id string, u TaskUpdate, author string, now time.Time) (*Task, bool, error) {
	i := slices.IndexFunc(c.Tasks, func(t Task) bool { return t.ID == id })
	if i < 0 {
		return nil, false, ErrTaskNotFound
	}
	t := &c.Tasks[i]
	changed := false
	if u.Title != nil {
		title, err := CleanTaskTitle(*u.Title)
		if err != nil {
			return nil, false, err
		}
		if title != t.Title {
			t.Title, changed = title, true
		}
	}
	if u.Owner != nil {
		if o := strings.TrimSpace(*u.Owner); o != t.Owner {
			if len(o) > 200 {
				return nil, false, errors.New("the owner's name is too long")
			}
			t.Owner, changed = o, true
		}
	}
	if u.Done != nil && *u.Done != t.Done {
		t.Done, changed = *u.Done, true
		if t.Done {
			at := now
			t.DoneBy, t.DoneAt = author, &at
			c.History = append(c.History, findings.Change{Author: author, Field: "task", From: t.Title, To: "done", Time: now})
		} else {
			t.DoneBy, t.DoneAt = "", nil
			c.History = append(c.History, findings.Change{Author: author, Field: "task", From: t.Title, To: "reopened", Time: now})
		}
	}
	if changed {
		c.Updated = now
	}
	return t, changed, nil
}

// RemoveTask deletes a task.
func (c *Case) RemoveTask(id, author string, now time.Time) error {
	i := slices.IndexFunc(c.Tasks, func(t Task) bool { return t.ID == id })
	if i < 0 {
		return ErrTaskNotFound
	}
	title := c.Tasks[i].Title
	c.Tasks = slices.Delete(c.Tasks, i, i+1)
	c.History = append(c.History, findings.Change{Author: author, Field: "task", From: title, To: "removed", Time: now})
	c.Updated = now
	return nil
}

// OpenTasks counts the tasks not done.
func (c *Case) OpenTasks() int {
	n := 0
	for _, t := range c.Tasks {
		if !t.Done {
			n++
		}
	}
	return n
}
