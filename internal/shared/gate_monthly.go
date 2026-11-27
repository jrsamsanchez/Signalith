// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

// Level 14 lets servers store a quiet data model's events in one index a
// month (<prefix>-<model>-YYYY.MM) instead of one a day. A server whose
// version reads only the level below names only daily indices when it
// narrows a search to its days, so its searches and detections would miss
// the events of a monthly index, and its retention would never delete
// one. So monthly indices are written only once every server seen lately
// reads this level, and an older version refuses to start once the
// cluster is at it.
const LevelMonthlyIndices = 14

// MonthlyIndices reports whether events may go to monthly indices: the
// cluster is at LevelMonthlyIndices.
func (rt *Runtime) MonthlyIndices() bool {
	return rt.sharedAt(LevelMonthlyIndices)
}
