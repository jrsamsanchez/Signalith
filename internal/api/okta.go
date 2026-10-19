// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/okta"
)

// oktaKeys are the settings the Okta test reads.
var oktaKeys = []string{"okta.domain", "okta.client_id", "okta.private_key", "okta.key_id", "okta.api_token"}

// oktaReport is what the Okta test found.
type oktaReport struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Field is the setting a failure points at, when one does.
	Field string `json:"field,omitempty"`
	// Auth is how Signalith signed in ("oauth" or "token"), and DPoP
	// whether the app requires DPoP.
	Auth   string `json:"auth,omitempty"`
	DPoP   bool   `json:"dpop,omitempty"`
	TookMS int64  `json:"took_ms"`
}

// handleTestOkta signs in to Okta with the domain and the app and key, or
// the API token, in the form, saved or not, and reads the last hour of
// the System Log.
func (s *Server) handleTestOkta(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, oktaKeys...)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(fields) == 0 {
		switch {
		case c.OktaDomain() == "":
			fields["okta.domain"] = "Enter the Okta domain."
		case c.Okta.ClientID != "" && c.Okta.PrivateKey == "":
			fields["okta.private_key"] = "Enter the app's private key."
		case c.Okta.ClientID == "" && c.Okta.PrivateKey != "":
			fields["okta.client_id"] = "Enter the app's client ID."
		case c.Okta.ClientID == "" && c.Okta.APIToken == "":
			fields["okta.client_id"] = "Enter the app's client ID and private key, or an API token."
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
	check := s.OktaCheck
	if check == nil {
		check = func(ctx context.Context, st okta.Settings) (*okta.CheckResult, error) {
			return okta.Check(ctx, st, nil)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	start := time.Now()
	st := okta.FromConfig(c)
	res, err := check(ctx, st)
	rep := oktaReport{TookMS: time.Since(start).Milliseconds()}
	if err != nil {
		rep.Message, rep.Field = explainOkta(err, st.OAuth())
	} else {
		rep.OK, rep.Auth, rep.DPoP = true, res.Auth, res.DPoP
		how := "with the app"
		if res.Auth == "token" {
			how = "with the API token"
		}
		rep.Message = fmt.Sprintf("Signed in %s, and it can read the System Log: the last hour has %s.", how, oktaEvents(res.Events))
	}
	s.audit(r, "settings tested", "what", "okta", "domain", c.OktaDomain(), "app", c.Okta.ClientID, "ok", rep.OK)
	writeJSON(w, http.StatusOK, rep)
}

// oktaEvents words a count of events, which stops at one page.
func oktaEvents(n int) string {
	switch {
	case n == 0:
		return "no events yet"
	case n == 1:
		return "1 event"
	case n >= 1000:
		return "1,000 events or more"
	}
	return fmt.Sprintf("%d events", n)
}

// explainOkta words a failed Okta test, and names the setting it points
// at.
func explainOkta(err error, oauth bool) (string, string) {
	msg := err.Error()
	secret := "okta.api_token"
	if oauth {
		secret = "okta.private_key"
	}
	var ae *okta.APIError
	if errors.As(err, &ae) {
		code := strings.ToLower(ae.Code)
		switch {
		case code == "invalid_client" && strings.Contains(strings.ToLower(ae.Message), "client_id"):
			return "Okta has no app with that client ID. (" + msg + ")", "okta.client_id"
		case code == "invalid_client":
			return "Okta refused the app's sign-in: check the app uses Public key / Private key client authentication, " +
				"that this is the private key of a public key the app has, and the key ID if the app has several. (" + msg + ")", "okta.private_key"
		case code == "invalid_scope" || code == "unauthorized_client":
			return "Okta did not grant the okta.logs.read scope: on the app's Okta API Scopes tab, grant okta.logs.read. (" + msg + ")", "okta.client_id"
		case ae.Code == "E0000011" || ae.Status == http.StatusUnauthorized:
			if oauth {
				return "Okta refused the app's token. (" + msg + ")", "okta.client_id"
			}
			return "Okta refused the API token: check it was copied whole and has not been revoked or expired. (" + msg + ")", "okta.api_token"
		case ae.Code == "E0000006" || ae.Status == http.StatusForbidden:
			if oauth {
				return "Signed in, but the app may not read the System Log: grant it the okta.logs.read scope, and give it an admin role " +
					"that can read the System Log, such as Read-only Administrator. (" + msg + ")", "okta.client_id"
			}
			return "The API token's admin may not read the System Log: make the token as an admin with at least Read-only Administrator. (" + msg + ")", "okta.api_token"
		case ae.Status == http.StatusNotFound:
			return "That Okta domain has no System Log API: check the domain is your organization's, such as example.okta.com. (" + msg + ")", "okta.domain"
		case ae.Status == http.StatusTooManyRequests:
			return "Okta's rate limit for the System Log is used up for now. Try again in a minute.", ""
		}
	}
	if strings.Contains(msg, "private key") {
		return sentence(msg), secret
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Okta did not answer in time. Check this server can reach the Okta domain over HTTPS.", "okta.domain"
	}
	return sentence(msg), ""
}

// oktaStatus is the System Log reading as the health page shows it.
func (s *Server) oktaStatus(ctx context.Context) map[string]any {
	c := s.conf()
	if !c.OktaOn() {
		return nil
	}
	out := map[string]any{"on": true, "domain": c.OktaDomain()}
	if s.OktaCursor == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cur, found, err := s.OktaCursor(ctx, c.OktaDomain())
	if err != nil {
		out["error"] = "could not read how far the System Log was read: " + err.Error()
		return out
	}
	if found {
		out["until"], out["last_run"], out["last_records"] = cur.Until, cur.LastRun, cur.LastRecords
		if cur.LastError != "" {
			out["last_error"] = cur.LastError
		}
	}
	return out
}
