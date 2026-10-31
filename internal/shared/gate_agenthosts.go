// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

// Level 13 lets Signalith Agents trade their line's token for a key of
// their computer's own (POST /api/agent/enroll). A server whose version
// reads only the level below does not know those keys and refuses them,
// so an agent behind a load balancer would be cut off by it. So keys are
// handed out only once every server seen lately reads this level, and an
// older version refuses to start once the cluster is at it.
const LevelAgentHostKeys = 13

// AgentHostKeys reports whether agents may get keys of their own: the
// cluster is at LevelAgentHostKeys.
func (rt *Runtime) AgentHostKeys() bool {
	return rt.sharedAt(LevelAgentHostKeys)
}
