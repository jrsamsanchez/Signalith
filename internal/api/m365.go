package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/m365"
)

// m365Keys are the settings the Microsoft 365 test reads.
var m365Keys = []string{"m365.cloud", "m365.tenant_id", "m365.client_id", "m365.client_secret"}

// m365Report is what the Microsoft 365 test found.
type m365Report struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Field is the setting a failure points at, when one does.
	Field string `json:"field,omitempty"`
	// Subscriptions are the audit logs the tenant has a subscription to,
	// by whether each is on.
	Subscriptions map[string]bool `json:"subscriptions,omitempty"`
	TookMS        int64           `json:"took_ms"`
}

// handleTestM365 signs in to Microsoft with the tenant, app and secret in
// the form, saved or not, and lists the tenant's audit log
// subscriptions.
func (s *Server) handleTestM365(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, m365Keys...)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(fields) == 0 {
		switch {
		case c.M365.TenantID == "":
			fields["m365.tenant_id"] = "Enter the tenant ID."
		case c.M365.ClientID == "":
			fields["m365.client_id"] = "Enter the application (client) ID."
		case c.M365.ClientSecret == "":
			fields["m365.client_secret"] = "Enter the client secret."
		}
	}
	if len(fields) > 0 {
		writeFieldProblems(w, fields)
		return
	}
	done, ok := s.oneTest(w)
	if !ok {
		return
	}
	defer done()
	check := s.M365Check
	if check == nil {
		check = func(ctx context.Context, st m365.Settings) (map[string]bool, error) { return m365.Check(ctx, st, nil) }
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	start := time.Now()
	subs, err := check(ctx, m365.FromConfig(c))
	rep := m365Report{TookMS: time.Since(start).Milliseconds(), Subscriptions: subs}
	if err != nil {
		rep.Message, rep.Field = explainM365(err)
	} else {
		rep.OK = true
		on := 0
		for _, ct := range m365.ContentTypes {
			if subs[ct] {
				on++
			}
		}
		rep.Message = fmt.Sprintf("Signed in, and the app can read the audit log. %d of the %d audit logs Signalith reads are subscribed to", on, len(m365.ContentTypes))
		if on < len(m365.ContentTypes) {
			rep.Message += "; Signalith starts the rest once the settings are saved"
		}
		rep.Message += "."
	}
	s.audit(r, "settings tested", "what", "m365", "tenant", c.M365.TenantID, "app", c.M365.ClientID, "ok", rep.OK)
	writeJSON(w, http.StatusOK, rep)
}

// explainM365 words a failed Microsoft 365 test, and names the setting it
// points at.
func explainM365(err error) (string, string) {
	msg := err.Error()
	var ae *m365.APIError
	if errors.As(err, &ae) {
		code := strings.ToLower(ae.Code)
		switch {
		case code == "invalid_client" || strings.Contains(ae.Message, "AADSTS7000215") || strings.Contains(ae.Message, "AADSTS7000222"):
			return "Microsoft refused the client secret: check it is the secret's Value (not its ID) and has not expired. (" + msg + ")", "m365.client_secret"
		case strings.Contains(ae.Message, "AADSTS700016"):
			return "Microsoft has no app with that application ID in the tenant. (" + msg + ")", "m365.client_id"
		case strings.Contains(ae.Message, "AADSTS90002") || strings.Contains(ae.Message, "AADSTS900023"):
			return "Microsoft has no tenant with that ID in this cloud. (" + msg + ")", "m365.tenant_id"
		case ae.Code == "AF20010" || ae.Code == "AF20011" || ae.Code == "AF20012" || ae.Code == "AF20013" ||
			ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden:
			return "Signed in, but the app may not read the audit log: give it the Office 365 Management APIs permission ActivityFeed.Read " +
				"(an application permission) and grant admin consent. Auditing must also be on in Microsoft Purview. (" + msg + ")", "m365.client_id"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Microsoft did not answer in time. Check this server can reach login.microsoftonline.com and manage.office.com (or your cloud's addresses).", ""
	}
	return sentence(msg), ""
}

// m365Status is the audit log reading as the health page shows it.
func (s *Server) m365Status(ctx context.Context) map[string]any {
	c := s.conf()
	if !c.M365On() {
		return nil
	}
	out := map[string]any{"on": true, "tenant": c.M365.TenantID}
	if s.M365Cursors == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	curs, err := s.M365Cursors(ctx, c.M365.TenantID)
	if err != nil {
		out["error"] = "could not read how far the audit log was read: " + err.Error()
		return out
	}
	types := make([]map[string]any, 0, len(curs))
	for _, cur := range curs {
		t := map[string]any{"content_type": cur.ContentType, "until": cur.Until, "last_run": cur.LastRun, "last_records": cur.LastRecords}
		if cur.LastError != "" {
			t["last_error"] = cur.LastError
		}
		types = append(types, t)
	}
	out["content_types"] = types
	return out
}
