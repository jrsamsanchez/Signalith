// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

// Level 11 numbers the detection run state from a counter document
// (detepoch) rather than the job lease's epoch, so the schedule can later
// be split between servers, each part with numbers of its own. The
// numbers it writes are bigger than any lease epoch: a server whose
// version reads only the level below would take its own writes for stale
// and stop running detections, so the counter is used only once every
// server seen lately reads this level, and an older version refuses to
// start once the cluster is at it.
const LevelDetectionEpochs = 11

// DetectionEpochs reports whether detection run state is numbered from
// the detepoch counter: the cluster is at LevelDetectionEpochs.
func (rt *Runtime) DetectionEpochs() bool {
	return rt.sharedAt(LevelDetectionEpochs)
}
