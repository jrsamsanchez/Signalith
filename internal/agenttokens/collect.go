package agenttokens

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Collect is what the Signalith Agents of one install line (an agent
// token made for the agent) collect, as an admin chose on the Endpoints
// page. The zero value is the default, as before there was a choice:
// everything the computer has. Each agent picks a change up the next time
// it fetches its configuration.
type Collect struct {
	// Osquery is "" (run osquery where it is installed) or "off".
	Osquery string `json:"osquery,omitempty"`
	// Sysmon is "" (read Sysmon's events where it runs) or "off".
	Sysmon string `json:"sysmon,omitempty"`
	// PowerShell is "" (read Windows PowerShell's logs) or "off".
	PowerShell string `json:"powershell,omitempty"`
	// LinuxLog is where Linux sign-ins are read from: "" (where the
	// computer writes them), "file" (auth.log or secure) or "journal"
	// (the systemd journal).
	LinuxLog string `json:"linux_log,omitempty"`
	// WebLogs is "" (read Apache's and Nginx's access logs on Linux) or
	// "off".
	WebLogs string `json:"web_logs,omitempty"`
	// AuditLog is "" (read the Linux audit log) or "off".
	AuditLog string `json:"audit_log,omitempty"`
	// Updates is "" (the agents update themselves to the signed release
	// programs the server hands out) or "off" (paused).
	Updates string `json:"updates,omitempty"`
}

// Off values.
const (
	CollectOff = "off"
	// LinuxLogFile and LinuxLogJournal are Collect.LinuxLog's choices.
	LinuxLogFile    = "file"
	LinuxLogJournal = "journal"
)

// CodeCollectInvalid is a Collect value that is not one of its choices.
const CodeCollectInvalid = "collect_invalid"

// CleanCollect checks c and returns it with each value in its stored
// form: "on" and "auto" are the default (""). The field of the first
// value that is not a choice is returned with false.
func CleanCollect(c Collect) (Collect, string, bool) {
	onOff := func(v *string) bool {
		switch strings.ToLower(strings.TrimSpace(*v)) {
		case "", "on", "auto":
			*v = ""
		case CollectOff:
			*v = CollectOff
		default:
			return false
		}
		return true
	}
	for _, f := range []struct {
		name string
		v    *string
	}{{"osquery", &c.Osquery}, {"sysmon", &c.Sysmon}, {"powershell", &c.PowerShell}, {"web_logs", &c.WebLogs}, {"audit_log", &c.AuditLog}, {"updates", &c.Updates}} {
		if !onOff(f.v) {
			return Collect{}, f.name, false
		}
	}
	switch v := strings.ToLower(strings.TrimSpace(c.LinuxLog)); v {
	case "", "auto":
		c.LinuxLog = ""
	case LinuxLogFile, LinuxLogJournal:
		c.LinuxLog = v
	default:
		return Collect{}, "linux_log", false
	}
	return c, "", true
}

func errCollectInvalid(field string) *Error {
	msg := "Use on or off."
	if field == "linux_log" {
		msg = "Use auto, file or journal."
	}
	return &Error{Status: http.StatusBadRequest, Code: CodeCollectInvalid, Field: field, Msg: msg}
}

func errNotAgent() *Error {
	return &Error{Status: http.StatusConflict, Code: CodePurposeInvalid, Field: "purpose",
		Msg: "Only a Signalith Agent install line's token has collection settings; other agents collect what their own configuration says."}
}

func errRevokedCollect() *Error {
	return &Error{Status: http.StatusConflict, Code: CodeRevoked, Msg: "This token was revoked; its agents no longer fetch settings."}
}

// Collect returns what the agents of the token id collect: the zero
// value for a token with no choice made, or one that is not known.
func (r *Registry) Collect(id string) Collect {
	if d := r.current().tokens[id]; d != nil && d.Collect != nil {
		return *d.Collect
	}
	return Collect{}
}

// SetCollect sets what the agents of the token id, an active token made
// for the Signalith Agent, collect. It returns the token and what was
// set before.
func (r *Registry) SetCollect(ctx context.Context, id string, c Collect, by string) (Token, Collect, error) {
	c, field, ok := CleanCollect(c)
	if !ok {
		return Token{}, Collect{}, errCollectInvalid(field)
	}
	if err := r.fresh(ctx); err != nil {
		return Token{}, Collect{}, err
	}
	var old Collect
	d, err := r.casToken(ctx, id, func(d *tokenDoc) (bool, error) {
		if d.Purpose != PurposeAgent {
			return false, errNotAgent()
		}
		if !isActive(d) {
			return false, errRevokedCollect()
		}
		if d.Collect != nil {
			old = *d.Collect
		}
		if old == c {
			return false, nil
		}
		d.Collect, d.CollectAt, d.CollectBy = nil, timePtr(r.now().UTC().Truncate(time.Second)), by
		if c != (Collect{}) {
			d.Collect = &c
		}
		return true, nil
	})
	if err != nil {
		return Token{}, Collect{}, err
	}
	return r.listed(ctx, d), old, nil
}
