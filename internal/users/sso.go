package users

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
)

// SSOUser is what an identity provider says about someone signing in
// with single sign-on.
type SSOUser struct {
	Username string
	Name     string
	Email    string
	// Subject is SSOSubject(issuer, sub).
	Subject string
	Role    Role
	// IDs are the person's ids at the provider (sub, and Entra ID's
	// oid), and VerifiedEmail their email address when the provider
	// vouches for it: a provisioned user's first sign-in must match one,
	// since the username claim alone may be one people can edit.
	IDs           []string
	VerifiedEmail string
}

// SSOSubject is how a single sign-on identity is kept: the issuer, a
// space, and the subject there. Issuers are URLs, which hold no spaces.
func SSOSubject(issuer, sub string) string { return issuer + " " + sub }

// SSOIssuer returns the issuer part of a Subject.
func SSOIssuer(subject string) string {
	iss, _, _ := strings.Cut(subject, " ")
	return iss
}

var (
	// ErrSSONew refuses someone signing in for the first time while new
	// users are not added.
	ErrSSONew = errors.New("you have not signed in to Signalith before, and new users are not added; ask an admin")
	// ErrSSOOther refuses a sign-in whose username belongs to someone
	// else: a local or directory user, the built-in admin, or a single
	// sign-on user with another identity at the provider.
	ErrSSOOther = errors.New("another Signalith user already has this name")
	// ErrSSOUnconfirmed refuses a first sign-in as a provisioned user
	// whose id and verified email both differ from what provisioning gave.
	ErrSSOUnconfirmed = errors.New("this sign-in does not match the provisioned user's id or verified email address")
)

// provisionedMatch reports whether the first sign-in d is the person
// provisioning added as u: their id at the provider (externalId) or their
// verified email address matches.
func provisionedMatch(u User, d SSOUser) bool {
	if u.ExternalID != "" && slices.Contains(d.IDs, u.ExternalID) {
		return true
	}
	return u.Email != "" && d.VerifiedEmail != "" && strings.EqualFold(u.Email, d.VerifiedEmail)
}

// cleanSSOName keeps a name from the provider as the Users page would
// take it: no control characters, at most 100 characters.
func cleanSSOName(name string) string {
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, name))
	if r := []rune(name); len(r) > 100 {
		name = strings.TrimSpace(string(r[:100]))
	}
	return name
}

// cleanSSOEmail drops an email address the Users page would not take.
func cleanSSOEmail(email string) string {
	email = strings.TrimSpace(email)
	if validEmail(email) != nil {
		return ""
	}
	return email
}

// SeeSSOUser records someone who just signed in with single sign-on:
// added on their first sign-in when create allows it, then kept up to
// date with the name, email and role the provider gives. Only the same
// identity at the provider (Subject) can sign in as an existing user, so
// a name taken by anyone else, or by another identity, is refused rather
// than taken over; a user provisioned ahead of their first sign-in takes
// the identity of that sign-in when its id or verified email address
// matches what provisioning gave (ErrSSOUnconfirmed otherwise). A disabled user is returned unchanged.
func (s *Store) SeeSSOUser(ctx context.Context, d SSOUser, create bool) (User, error) {
	name := NormalizeUsername(d.Username)
	if err := ValidUsername(name); err != nil {
		return User{}, err
	}
	if s.reserved(name) {
		return User{}, ErrSSOOther
	}
	d.Name, d.Email = cleanSSOName(d.Name), cleanSSOEmail(d.Email)
	for try := 1; ; try++ {
		now := s.now()
		r, err := s.b.Change(ctx, Actor(ctx), name, "", func(r *Record) error {
			// A provisioned user who has not signed in yet has no Subject:
			// their first sign-in binds it.
			if r.Source != SourceSSO || r.Subject != d.Subject && r.Subject != "" {
				return ErrSSOOther
			}
			if r.Disabled {
				return ErrNoChange
			}
			if r.Subject == "" && !provisionedMatch(r.User, d) {
				return ErrSSOUnconfirmed
			}
			u := r.User
			full, email := d.Name, d.Email
			if u.ExternalID != "" {
				// Provisioning keeps the name and email up to date too; an
				// ID token without them leaves them as provisioned.
				if full == "" {
					full = u.Name
				}
				if email == "" {
					email = u.Email
				}
			}
			changed := u.Name != full || u.Email != email || u.Role != d.Role || u.Subject != d.Subject
			u.Name, u.Email, u.Role, u.Subject = full, email, d.Role, d.Subject
			if changed {
				u.Updated = now
			}
			if s.SignIns != nil {
				// The sign-in is recorded apart.
				if !changed {
					return ErrNoChange
				}
			} else {
				if !changed && u.LastSignIn != nil && now.Sub(*u.LastSignIn) < signInWrites {
					return ErrNoChange
				}
				u.LastSignIn = &now
			}
			r.User = u
			return nil
		})
		if !errors.Is(err, ErrNotFound) {
			if err != nil {
				return User{}, err
			}
			s.signedIn(ctx, r)
			return recordUser(r), nil
		}
		if !create {
			return User{}, ErrSSONew
		}
		// Their first sign-in.
		if tenantLike(name) {
			return User{}, ErrTenantSuffix
		}
		r, err = s.b.Create(ctx, Actor(ctx), Record{User: User{Username: name, Source: SourceSSO, Name: d.Name, Email: d.Email,
			Role: d.Role, Subject: d.Subject, Created: now, Updated: now, LastSignIn: &now}, Epoch: 1})
		if errors.Is(err, ErrExists) && try < 3 {
			// Someone else added them just now: check that one.
			continue
		}
		if err != nil {
			return User{}, err
		}
		s.signedIn(ctx, r)
		return recordUser(r), nil
	}
}
