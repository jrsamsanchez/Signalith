// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/oidc"
)

// Teams sends what happens to a bot (a click, a message, the app being
// added to a team) to its messaging endpoint, with a token the Bot
// Framework signed: RS256, with one of the keys its OpenID metadata
// publishes, issued by https://api.botframework.com, for the bot's app ID,
// naming the Bot Connector address (serviceurl) the activity came from.
// https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication

// BotFrameworkMetadata is where the Bot Framework publishes its keys.
const BotFrameworkMetadata = "https://login.botframework.com/v1/.well-known/openidconfiguration"

// botIssuer issues the tokens Teams sends.
const botIssuer = "https://api.botframework.com"

// clockSkew is how far the token's times may be off.
const clockSkew = 5 * time.Minute

// keyLife is how long the Bot Framework's keys are used before they are
// read again; an unknown key ID reads them again sooner.
const keyLife = 24 * time.Hour

// BotVerifier checks the tokens Teams sends.
type BotVerifier struct {
	// Metadata is the Bot Framework's OpenID metadata address; "" is
	// BotFrameworkMetadata. Tests point it elsewhere.
	Metadata string
	// Client fetches the metadata and keys; nil is a client with a
	// timeout that follows the proxy settings and no redirects.
	Client *http.Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	keys    oidc.JWKS
	fetched time.Time
	tried   time.Time
}

func (v *BotVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *BotVerifier) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// botKey is a Bot Framework key: a JWK, and the channels it may sign for.
type botKey struct {
	oidc.JWK
	Endorsements []string `json:"endorsements"`
}

// getJSON reads a small JSON document.
func (v *BotVerifier) getJSON(ctx context.Context, address string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", address, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

// fetch reads the Bot Framework's keys that may sign for Teams.
func (v *BotVerifier) fetch(ctx context.Context) (oidc.JWKS, error) {
	meta := v.Metadata
	if meta == "" {
		meta = BotFrameworkMetadata
	}
	var md struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, meta, &md); err != nil {
		return oidc.JWKS{}, err
	}
	mu, err1 := url.Parse(meta)
	ku, err2 := url.Parse(md.JWKSURI)
	// The keys come from the same place as the metadata, over HTTPS.
	if err1 != nil || err2 != nil || ku.Scheme != mu.Scheme || !strings.EqualFold(ku.Host, mu.Host) {
		return oidc.JWKS{}, errors.New("the Bot Framework metadata names keys somewhere else")
	}
	var set struct {
		Keys []botKey `json:"keys"`
	}
	if err := v.getJSON(ctx, md.JWKSURI, &set); err != nil {
		return oidc.JWKS{}, err
	}
	var out oidc.JWKS
	for _, k := range set.Keys {
		// Only keys endorsed for Teams sign Teams tokens.
		if slices.Contains(k.Endorsements, "msteams") {
			out.Keys = append(out.Keys, k.JWK)
		}
	}
	if len(out.Keys) == 0 {
		return oidc.JWKS{}, errors.New("the Bot Framework publishes no keys for Teams")
	}
	return out, nil
}

// keySet returns the keys, read again when old, or when fresh is asked
// and they were not read in the last five minutes.
func (v *BotVerifier) keySet(ctx context.Context, fresh bool) (oidc.JWKS, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	stale := v.fetched.IsZero() || now.Sub(v.fetched) > keyLife
	if !stale && !(fresh && now.Sub(v.tried) > 5*time.Minute) {
		return v.keys, nil
	}
	if !stale {
		// Read again for a key ID the set does not hold: at most once
		// every five minutes, so forged tokens cannot make it read them
		// on every request.
		v.tried = now
	}
	ks, err := v.fetch(ctx)
	if err != nil {
		if len(v.keys.Keys) > 0 && !stale {
			return v.keys, nil
		}
		return oidc.JWKS{}, fmt.Errorf("could not read the Bot Framework's keys: %w", err)
	}
	v.keys, v.fetched = ks, now
	return ks, nil
}

// botClaims are the claims of a Bot Framework token Signalith checks.
type botClaims struct {
	Issuer     string          `json:"iss"`
	Audience   json.RawMessage `json:"aud"`
	Expires    float64         `json:"exp"`
	NotBefore  float64         `json:"nbf"`
	ServiceURL string          `json:"serviceurl"`
}

func (c botClaims) hasAudience(appID string) bool {
	var one string
	if json.Unmarshal(c.Audience, &one) == nil {
		return strings.EqualFold(one, appID)
	}
	var many []string
	if json.Unmarshal(c.Audience, &many) == nil {
		for _, a := range many {
			if strings.EqualFold(a, appID) {
				return true
			}
		}
	}
	return false
}

// Verify checks the Authorization header of a request Teams sent to the
// bot appID about an activity from serviceURL.
func (v *BotVerifier) Verify(ctx context.Context, authorization, appID, serviceURL string) error {
	scheme, token, _ := strings.Cut(authorization, " ")
	if !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return errors.New("the request has no Bot Framework token")
	}
	token = strings.TrimSpace(token)
	ks, err := v.keySet(ctx, false)
	if err != nil {
		return err
	}
	payload, err := oidc.VerifyJWS(token, ks, []string{"RS256"})
	if errors.Is(err, oidc.ErrUnknownKey) {
		// A key the Bot Framework rotated in since they were read.
		if ks, err = v.keySet(ctx, true); err != nil {
			return err
		}
		payload, err = oidc.VerifyJWS(token, ks, []string{"RS256"})
	}
	if err != nil {
		return err
	}
	var c botClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return errors.New("the token's claims are not JSON")
	}
	now := v.now()
	switch {
	case c.Issuer != botIssuer:
		return errors.New("the token is not from the Bot Framework")
	case !c.hasAudience(appID):
		return errors.New("the token is for another bot: check the channel's app ID")
	case c.Expires == 0 || now.After(time.Unix(int64(c.Expires), 0).Add(clockSkew)):
		return errors.New("the token expired")
	case c.NotBefore != 0 && now.Add(clockSkew).Before(time.Unix(int64(c.NotBefore), 0)):
		return errors.New("the token is not valid yet")
	case !sameServiceURL(c.ServiceURL, serviceURL):
		return errors.New("the token is for another Bot Connector address")
	}
	return nil
}

// sameServiceURL compares two Bot Connector addresses, ignoring a final
// slash and the case of the host.
func sameServiceURL(a, b string) bool {
	ua, err1 := url.Parse(strings.TrimRight(a, "/"))
	ub, err2 := url.Parse(strings.TrimRight(b, "/"))
	if err1 != nil || err2 != nil || a == "" {
		return false
	}
	return ua.Scheme == ub.Scheme && strings.EqualFold(ua.Host, ub.Host) && ua.Path == ub.Path
}

// activity is the part of a Bot Framework activity Signalith reads.
type activity struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	ChannelID  string `json:"channelId"`
	ServiceURL string `json:"serviceUrl"`
	Text       string `json:"text"`
	Action     string `json:"action"`
	From       struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		AADObjectID string `json:"aadObjectId"`
	} `json:"from"`
	Recipient struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"recipient"`
	Conversation struct {
		ID               string `json:"id"`
		ConversationType string `json:"conversationType"`
		TenantID         string `json:"tenantId"`
		Name             string `json:"name"`
	} `json:"conversation"`
	ChannelData struct {
		Tenant struct {
			ID string `json:"id"`
		} `json:"tenant"`
		Team struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"team"`
		Channel struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"channel"`
	} `json:"channelData"`
	MembersAdded []struct {
		ID string `json:"id"`
	} `json:"membersAdded"`
	MembersRemoved []struct {
		ID string `json:"id"`
	} `json:"membersRemoved"`
	Value struct {
		Action struct {
			Type string         `json:"type"`
			Verb string         `json:"verb"`
			Data map[string]any `json:"data"`
		} `json:"action"`
	} `json:"value"`
}

// tenant is the Microsoft Entra tenant an activity comes from.
func (a activity) tenant() string {
	if a.ChannelData.Tenant.ID != "" {
		return strings.ToLower(a.ChannelData.Tenant.ID)
	}
	return strings.ToLower(a.Conversation.TenantID)
}

// botAdded reports whether the activity says the bot was added to the
// conversation, and botRemoved that it was removed.
func (a activity) botAdded() bool {
	if a.Type == "installationUpdate" {
		return a.Action == "add" || a.Action == "add-upgrade"
	}
	return a.Type == "conversationUpdate" && slices.ContainsFunc(a.MembersAdded, func(m struct {
		ID string `json:"id"`
	}) bool {
		return m.ID == a.Recipient.ID
	})
}

func (a activity) botRemoved() bool {
	if a.Type == "installationUpdate" {
		return a.Action == "remove" || a.Action == "remove-upgrade"
	}
	return a.Type == "conversationUpdate" && slices.ContainsFunc(a.MembersRemoved, func(m struct {
		ID string `json:"id"`
	}) bool {
		return m.ID == a.Recipient.ID
	})
}

// mentionText is a message's text without the <at>...</at> mentions Teams
// puts in, and with spaces made single.
func mentionText(s string) string {
	for {
		i := strings.Index(s, "<at>")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "</at>")
		if j < 0 {
			s = s[:i]
			break
		}
		s = s[:i] + " " + s[i+j+len("</at>"):]
	}
	return strings.Join(strings.Fields(s), " ")
}
