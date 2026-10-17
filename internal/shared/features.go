package shared

import (
	"cmp"
	"slices"
	"strings"
)

// Feature is a part of Signalith that comes with a cluster level: it is
// off until every server seen lately runs a version that reads the
// level, and the level was raised. The Servers page and the page helper
// levels.js grey out its controls meanwhile.
type Feature struct {
	// Name is the feature's id, as controls name it (data-feature), and
	// Label its name for people.
	Name, Label string
	// Level is the cluster level it needs, and On reports whether it is on
	// on a runtime.
	Level int
	On    func(*Runtime) bool
}

// Features are the features that come with a cluster level. Append-only:
// a new level's gate appends its feature here.
var Features = []Feature{
	{"shared_users", "Users and sign-in shared by every server", LevelSharedUsers, (*Runtime).SharedUsers},
	{"shared_settings", "One Settings page for every server", LevelSharedSettings, (*Runtime).SharedSettings},
	{"shared_audit", "Audit and archives across servers", LevelSharedAudit, (*Runtime).SharedAudit},
	{"shared_tls", "One certificate authority", LevelSharedTLS, (*Runtime).SharedTLS},
	{"shared_library", "Shared detections and dashboards", LevelSharedLibrary, (*Runtime).SharedLibrary},
	{"shared_lookups", "Shared asset and identity lists", LevelSharedLookups, (*Runtime).SharedLookups},
	{"key_rotation", "Rotate the cluster key", LevelKeyRotation, (*Runtime).KeyRotation},
	{"api_tokens", "API tokens", LevelAPITokens, (*Runtime).APITokens},
	{"tenants", "Tenants (multi-tenant mode)", LevelTenants, (*Runtime).Tenants},
}

// FeatureState is whether a feature is on, on this server, and if not
// why. Waiting lists the servers seen within LevelSeen whose version does
// not read the feature's level, this server left out.
type FeatureState struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Level   int    `json:"level"`
	On      bool   `json:"on"`
	Why     string `json:"why,omitempty"`
	Waiting []Peer `json:"-"`
}

// FeatureStates says, for each feature, whether it is on, why not, and
// which servers hold it back.
func (rt *Runtime) FeatureStates() []FeatureState {
	body, ok := rt.Cluster().Get()
	member := rt.SharedContent()
	level := 0
	if ok && body != nil {
		level = body.Level
	}
	peers, _ := rt.peersSeen()
	out := make([]FeatureState, 0, len(Features))
	for _, f := range Features {
		st := FeatureState{Name: f.Name, Label: f.Label, Level: f.Level, On: f.On(rt)}
		switch {
		case st.On:
		case !member:
			st.Why = "This server is not a member of a cluster"
		case level < f.Level:
			st.Why = "Available when every server runs " + cmp.Or(rt.opts.Version, "the new version") + " or later"
			for _, p := range peers {
				if p.NodeID == rt.opts.Self.NodeID || !p.Live && p.SeenAgo >= LevelSeen {
					continue
				}
				if max(p.LevelMax, LevelMin) < f.Level {
					st.Waiting = append(st.Waiting, p)
				}
			}
			slices.SortFunc(st.Waiting, func(a, b Peer) int { return strings.Compare(a.Name, b.Name) })
		default:
			founder := "the server that founded the cluster"
			if ok && body != nil && body.CreatedBy != "" {
				founder = body.CreatedBy
			}
			st.Why = "Waiting for " + founder + " to bring in its files"
		}
		out = append(out, st)
	}
	return out
}
