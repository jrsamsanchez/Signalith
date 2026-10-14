package security

import (
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// checkBuiltinPassword: accounts.builtin_password.
func checkBuiltinPassword(f *Facts) *Check {
	a := f.Admin
	fix := &Fix{Steps: []string{"Set a password of its own for the built-in admin, then restart Signalith."},
		Commands: cmds("sudo signalith passwd"+configArg(f, "linux")+" && sudo systemctl restart signalith",
			winExe+" passwd"+configArg(f, "windows")+"; Restart-Service Signalith",
			dockerCompose+" exec signalith signalith passwd\n"+dockerCompose+" restart signalith"),
		Docs: doc(docUsersBuiltin)}
	removeEnv := "Then remove SIGNALITH_ADMIN_PASSWORD from where Signalith is started."
	switch {
	case a.Public:
		fix.Steps = append(fix.Steps, removeEnv)
		return &Check{State: Risk, Line: "The built-in admin's password is change-me-please, an example anyone can look up.", Fix: fix}
	case a.DockerFirst:
		return &Check{State: Attention, Line: "The built-in admin still has the first password the Docker setup made, which is kept as plain text in a Docker volume.", Fix: fix}
	case a.FromFile:
		fix.Steps = append(fix.Steps, "Then remove SIGNALITH_ADMIN_PASSWORD_FILE from where Signalith is started, and delete the file.")
		return &Check{State: Attention, Line: "The built-in admin's password is read from the file in SIGNALITH_ADMIN_PASSWORD_FILE, as plain text.", Fix: fix}
	case a.FromEnv:
		fix.Steps = append(fix.Steps, removeEnv)
		return &Check{State: Attention, Line: "The built-in admin's password is set in the SIGNALITH_ADMIN_PASSWORD environment variable.", Fix: fix}
	case a.WeakHash:
		return &Check{State: Attention, Line: "The built-in admin's password is stored with a weaker hash than Signalith uses now. Set it again to store it the stronger way.", Fix: fix}
	}
	name := f.Users.BuiltinName
	if name == "" && f.Config != nil {
		name = f.Config.Auth.AdminUser
	}
	line := "The built-in admin (" + name + ") has a password of its own"
	if a.SetAt != nil {
		line += ", last set " + day(*a.SetAt)
	}
	return &Check{State: Good, Line: line + "."}
}

// checkBuiltinUse: accounts.builtin_use.
func checkBuiltinUse(f *Facts) *Check {
	u := f.Users
	last := u.BuiltinLastSignIn
	if u.OtherAdmins > 0 && last != nil && f.Now.Sub(*last) <= 7*24*time.Hour {
		n := u.OtherAdmins
		return &Check{State: Attention, Line: "The built-in admin signed in " + ago(f.Now, *last) + ", though " + itoa(n) +
			plural(n, " person has an admin account of their own", " people have admin accounts of their own") + ". Keep it for emergencies.",
			Fix: &Fix{Steps: []string{"Sign in with your own admin account day to day, and keep the built-in admin for emergencies."},
				Page: &PageLink{ID: "users", Label: "Open Users"}, Docs: doc(docUsersBuiltin)}}
	}
	if u.Others > 0 || u.OtherAdmins > 0 {
		when := "The built-in admin has never signed in."
		if last != nil {
			when = "The built-in admin last signed in " + ago(f.Now, *last) + "."
		}
		return &Check{State: Good, Line: "People sign in with their own accounts. " + when}
	}
	return &Check{State: Good, Line: "Only the built-in admin signs in so far.",
		Tip: &Fix{Steps: []string{"Give yourself an admin account on the Users page and keep the built-in admin for emergencies. The audit log then shows who did what."},
			Page: &PageLink{ID: "users", Label: "Open Users"}}}
}

// checkTempPasswords: accounts.temp_passwords.
func checkTempPasswords(f *Facts) *Check {
	u := f.Users
	if !u.Local {
		return nil
	}
	if n := len(u.StaleTemporary); n > 0 {
		return &Check{State: Attention, Line: itoa(n) + plural(n, " person hasn't", " people haven't") +
			" changed the temporary password they were given over a week ago: " + shorten(u.StaleTemporary, 5) + ".",
			Fix: &Fix{Steps: []string{"Remind them to sign in and choose a password, or disable their account until they need it."},
				Page: &PageLink{ID: "users", Label: "Open Users"}, Docs: doc(docUsersLocal)}}
	}
	return &Check{State: Good, Line: "Nobody is left on a temporary password."}
}

// checkDirectory: accounts.directory.
func checkDirectory(f *Facts) *Check {
	d := f.Directory
	if d == nil || d.Enabled != nil && !*d.Enabled || strings.TrimSpace(d.URL) == "" {
		return nil
	}
	page := &PageLink{ID: "users", Tab: "directory", Label: "Open Directory sign-in"}
	var hosts []string
	ldaps := true
	for _, raw := range []string{d.URL, d.FailoverURL} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		scheme, host, _ := urlParts(raw)
		if !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
		if scheme != "ldaps" {
			ldaps = false
			if !d.StartTLS {
				return &Check{State: Risk, Line: "Directory passwords cross the network to " + host + " unencrypted: the address is ldap:// without StartTLS.",
					Fix: &Fix{Steps: []string{"Use an ldaps:// address, or turn on StartTLS."}, Page: page, Docs: doc(docUsersDirectory)}}
			}
		}
	}
	if d.TLSSkipVerify {
		return &Check{State: Risk, Line: "Signalith doesn't check the directory server's certificate, so someone on the network could pose as it and collect passwords.",
			Fix: &Fix{Steps: []string{"Give the directory's CA certificate, then turn off Skip certificate check."}, Page: page, Docs: doc(docUsersDirectory)}}
	}
	how := "LDAPS"
	if !ldaps {
		how = "StartTLS"
	}
	c := &Check{State: Good, Line: "Directory sign-in uses " + how + " to " + joinAnd(hosts) + " and checks its certificate."}
	if strings.EqualFold(d.DefaultRole, "viewer") {
		c.Details = []string{"Anyone in the directory can sign in as a viewer."}
	}
	return c
}

// checkSessions: accounts.sessions.
func checkSessions(f *Facts) *Check {
	idle := f.Config.SessionIdle()
	if idle > 24*time.Hour {
		return &Check{State: Attention, Line: "People stay signed in for up to " + span(idle) + " without using Signalith.",
			Fix: &Fix{Steps: []string{"Set Sign out after to 12h or less."}, Setting: "auth.session_timeout"}}
	}
	return &Check{State: Good, Line: "People are signed out after " + span(idle) + " without use, unless they choose Keep me signed in, which keeps them signed in for up to 7 days."}
}

// checkAgentTokens: accounts.agent_tokens.
func checkAgentTokens(f *Facts) *Check {
	t := f.AgentTokens
	if t == nil {
		t = &AgentTokenFacts{}
		for _, tok := range f.Config.Ingest.Tokens {
			t.Legacy = append(t.Legacy, LegacyTokenFact{Public: config.IsPublicIngestToken(tok), Length: len(tok)})
		}
	}
	var accepted []LegacyTokenFact
	for _, l := range t.Legacy {
		if !l.Refused {
			accepted = append(accepted, l)
		}
	}
	if len(accepted) == 0 && t.Active == 0 && !f.PublicTokenAccepted && (t.Loaded || f.AgentTokens == nil) {
		return nil
	}
	fix := &Fix{Steps: []string{
		"Open Add data and give each agent a configuration with its own token.",
		"Under Agent tokens, choose Stop accepting on the shared token once its Last used is older than the last agent you updated.",
		"That's all: a token that is no longer accepted can't be used. You may also delete it from signalith.yaml (ingest.tokens) or SIGNALITH_INGEST_TOKEN; on the Docker quick start, leave docker-compose.yml as it is.",
	}, Page: &PageLink{ID: "data", Label: "Open Add data"}, Docs: docLabeled(docTokensReplace, "Replace a shared token")}
	details := []string{"Every agent set up with a shared token uses the same secret, so a copy taken from any one of them works for all of them."}
	for _, l := range accepted {
		if l.Public {
			return &Check{State: Risk, Line: "Agents can send events with change-this-ingest-token, an example token anyone can look up.", Details: details, Fix: fix}
		}
	}
	if f.PublicTokenAccepted {
		// Accepted for agents an older Docker quick start set up, while
		// agents on plain HTTP are (see api.retiredTokenAccepted).
		why := "This Docker quick start was upgraded from an older version, whose agents all send it."
		if u := f.Config.DockerUpgrade(); u != nil && u.Index != "" {
			why = "This Docker quick start was upgraded from an older version, whose agents all send it: when it was updated, OpenSearch held events from the older version, the oldest from " + day(u.IndexMade) + "."
		}
		return &Check{State: Risk, Line: "Agents can still send events over plain HTTP with change-this-ingest-token, an example token anyone can look up.",
			Details: []string{why, "Signalith accepts it so those agents keep working, and only over plain HTTP. Refusing agents on plain HTTP ends it for good."},
			Fix: &Fix{Steps: []string{"Choose Refuse them under Agents on plain HTTP once every agent has its configuration from Add data. The Health page names any agent still sending that way."},
				Setting: "server.tls.plaintext_ingest", Page: &PageLink{ID: "data", Label: "Open Add data"}, Docs: doc(docHTTPSOldToken)}}
	}
	if f.Docker {
		details = append(details, oldTokenRefused(f.Config))
	}
	if len(accepted) > 0 {
		shortest, recent := 0, false
		for _, l := range accepted {
			if shortest == 0 || l.Length < shortest {
				shortest = l.Length
			}
			if !l.LastUsed.IsZero() && f.Now.Sub(l.LastUsed) < 7*24*time.Hour {
				recent = true
			}
		}
		if shortest < 24 {
			return &Check{State: Attention, Line: "An agent token is only " + itoa(shortest) + plural(shortest, " character", " characters") +
				" long, so it's easier to guess. Tokens Signalith makes have 56.", Details: details, Fix: fix}
		}
		if !t.Loaded {
			return &Check{State: Attention, Line: "A shared agent token is accepted; how it was used couldn't be read from OpenSearch.", Details: details, Fix: fix}
		}
		if recent {
			return &Check{State: Attention, Line: "Some agents still send with a shared token.", Details: details, Fix: fix}
		}
		if !everUsed(accepted) && (t.Active > 0 || f.Docker) {
			// A token no agent ever sent with, such as the one the Docker
			// quick start's setup makes: nothing to replace, only one
			// secret less to keep.
			return &Check{State: Good, Line: "No agent sends with a shared token, though one is still accepted.",
				Details: []string{"Signalith hasn't seen any agent send with it. New agents get their own token from Add data."},
				Tip: &Fix{Steps: []string{"Under Agent tokens on Add data, choose Stop accepting on the shared token, so a copy of it can never be used."},
					Page: &PageLink{ID: "data", Label: "Open Add data"}, Docs: docLabeled(docTokensReplace, "Replace a shared token")}}
		}
		return &Check{State: Attention, Line: "A shared agent token is still accepted, though no agent has used it in the last 7 days.", Details: details, Fix: fix}
	}
	if !t.Loaded {
		return &Check{State: Unknown, Line: "Couldn't read the agent tokens from OpenSearch."}
	}
	details = []string{"Each token is kept only as a SHA-256 fingerprint, and revoking one refuses it on every server within a few seconds."}
	if len(t.Legacy) > 0 {
		details = append(details, "The shared token in the configuration is no longer accepted, so it can't be used. Leaving it there is fine.")
	}
	if f.Docker {
		details = append(details, oldTokenRefused(f.Config))
	}
	return &Check{State: Good, Line: "Each agent group sends with its own token (" + itoa(t.Active) + " active).", Details: details,
		Tip: &Fix{Docs: doc(docTokensHow)}}
}

// everUsed reports whether any agent has sent with one of these tokens.
func everUsed(ls []LegacyTokenFact) bool {
	for _, l := range ls {
		if !l.LastUsed.IsZero() {
			return true
		}
	}
	return false
}

// oldTokenRefused says why a Docker quick start refuses the example token
// older ones gave every agent.
func oldTokenRefused(c *config.Config) string {
	const token = "The example token older Docker quick starts gave every agent, change-this-ingest-token, "
	u := c.DockerUpgrade()
	switch c.OldToken() {
	case config.OldTokenUndecided:
		return token + "is refused for now: Signalith hasn't yet been able to ask OpenSearch whether this install was upgraded from an older version. " +
			"Agents that send it keep their events and send them again."
	case config.OldTokenEnded:
		return token + "is refused for good: this install was upgraded from an older version, and agents on plain HTTP have been refused since " + day(u.Ended) + "."
	case config.OldTokenAccepted:
		return token + "is refused while agents on plain HTTP are. Refusing them ends it for good."
	}
	return token + "is refused: this install started new, so none of its agents has it."
}

// checkOpenSearchRole: accounts.opensearch_role.
func checkOpenSearchRole(f *Facts) *Check {
	o := f.OpenSearch
	if o.Anonymous == "open" || o.AuthNoPlugin || !o.AuthProbed && !o.DemoAdmin {
		return nil
	}
	fix := &Fix{Steps: []string{"Give Signalith its own OpenSearch account with the signalith_server role, ideally signing in with a certificate."}, Docs: doc(docOSRoles)}
	if o.DemoAdmin {
		return &Check{State: Risk, Line: "Signalith signs in to OpenSearch as admin with the password admin, which anyone can look up.", Fix: fix}
	}
	if o.AuthErr != "" {
		// Only a refusal of the account itself is about its roles.
		const couldnt = "Signalith couldn't ask OpenSearch what its account may do"
		c := &Check{State: Unknown, Line: couldnt + ".", Details: []string{osWhy(o.AuthErr)}}
		switch {
		case o.SecurityNotLoaded:
			c.Line, c.Details = couldnt+": OpenSearch's security settings aren't loaded, so it turns everyone away for now.", nil
			c.Fix = notLoadedFix(f)
		case !osAnswered(o.AuthErr):
			c.Fix = reachFix()
		case o.AuthRefusal == store.RefusedPermission:
			c.Fix = &Fix{Steps: []string{"Check the roles mapped to Signalith's account in OpenSearch's security settings."}, Docs: doc(docOSRoles)}
		case o.AuthRefusal == store.RefusedSignIn:
			c.Line = couldnt + ": OpenSearch doesn't accept its sign-in."
			setting := "opensearch.password"
			if f.Config.OpenSearch.Username == "" {
				setting = "opensearch.cert_file"
			}
			c.Fix = &Fix{Steps: []string{"Check the OpenSearch user name and password, or the client certificate, on the Settings page, then re-check."},
				Setting: setting, Docs: doc(docOSPoint)}
		case o.AuthRefusal == store.RefusedBusy:
			c.Line = couldnt + ": OpenSearch was too busy to answer in time."
			c.Fix = &Fix{Steps: []string{"Re-check in a few minutes. " + store.BusyFix}}
		default:
			c.Fix = &Fix{Steps: []string{"Re-check in a few minutes. If OpenSearch keeps answering this way, its log may say why. " + store.OpenSearchLog}}
		}
		return c
	}
	user := o.AuthUser
	if user == "" {
		user = "its account"
	}
	if slices.ContainsFunc(o.AuthRoles, func(r string) bool { return r == "all_access" || r == "security_manager" }) || slices.Contains(o.AuthBackend, "admin") {
		return &Check{State: Attention, Line: "Signalith signs in to OpenSearch as " + user + ", which can do anything there. If its password or key leaked, so would all of OpenSearch.", Fix: fix}
	}
	return &Check{State: Good, Line: "Signalith signs in to OpenSearch as " + user + ", an account without admin rights."}
}
