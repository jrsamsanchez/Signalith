package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Throttles are documents, throttle:<hash of rule and group key>, in the
// runtime index. Each says which slot last raised a finding (or risk) for
// the group, until when that holds the group back, and the finding's ID.
// They are read in real time and written with versions, so a throttle
// holds across servers and restarts, and a slot that is run again (after
// a takeover or a failed write) sees its own claim and writes what is
// missing, since finding and risk IDs come from the slot.

// manualSlot is the slot of a throttle a "Run now" wrote.
const manualSlot = "manual"

// throttleDoc is a throttle as stored.
type throttleDoc struct {
	Kind        string    `json:"kind"`
	DetectionID string    `json:"detection_id"`
	GroupKey    string    `json:"group_key"`
	Slot        string    `json:"slot"`
	Until       time.Time `json:"until"`
	FindingID   string    `json:"finding_id,omitempty"`
	Epoch       int64     `json:"epoch"`
	Node        string    `json:"node,omitempty"`
}

// throttleID is the throttle document ID of a rule's group key.
func throttleID(rule, key string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + key))
	return kindThrottle + ":" + hex.EncodeToString(h[:])[:32]
}

// slotString is how a slot is written in a throttle document.
func slotString(slot time.Time) string {
	if slot.IsZero() {
		return manualSlot
	}
	return slot.UTC().Format(time.RFC3339)
}

// claim decides one result row: proceed (write its finding or risk) or
// throttled. slot is the scheduled slot, or zero for "Run now", whose
// throttle holds from now. When no throttle document exists and fallback
// is set, it is asked once whether an older finding or risk event,
// written before throttles were documents, holds the row back.
func (s *Scheduler) claim(ctx context.Context, d *Detection, key string, slot, now time.Time, w time.Duration,
	findingID string, fallback func() (bool, error)) (bool, error) {
	rs, idx := s.runStore()
	id := throttleID(d.ID, key)
	end := now
	if !slot.IsZero() {
		end = slot
	}
	ep := s.epoch()
	doc := throttleDoc{Kind: kindThrottle, DetectionID: d.ID, GroupKey: key, Slot: slotString(slot),
		Until: end.Add(w).UTC(), FindingID: findingID, Epoch: ep, Node: s.NodeID}
	asked := false
	for range 3 {
		raw, ver, found, err := rs.Get(ctx, idx, id)
		if err != nil {
			return false, err
		}
		if !found {
			if fallback != nil && !asked {
				asked = true
				held, err := fallback()
				if err != nil {
					return false, err
				}
				if held {
					return false, nil
				}
			}
			_, err := rs.Create(ctx, idx, id, doc, false)
			if errors.Is(err, store.ErrExists) {
				continue
			}
			return err == nil, err
		}
		var cur throttleDoc
		if err := json.Unmarshal(raw, &cur); err != nil {
			return false, fmt.Errorf("throttle %s cannot be read: %w", id, err)
		}
		if !slot.IsZero() && cur.Slot == doc.Slot {
			// This slot claimed it before: a run of it again.
			return true, nil
		}
		if cur.Until.After(end) {
			return false, nil
		}
		if !slot.IsZero() && cur.Slot != manualSlot && cur.Epoch > ep {
			return false, errStaleEpoch
		}
		_, err = rs.PutIf(ctx, idx, id, doc, ver, false)
		if store.IsConflict(err) || errors.Is(err, store.ErrNotFound) {
			continue
		}
		return err == nil, err
	}
	return false, fmt.Errorf("the throttle of detection %s kept changing while it was written; the run is tried again", d.ID)
}
