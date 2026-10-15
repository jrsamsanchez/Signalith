package users

import (
	"context"
	"errors"
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
)

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
// than taken over. A disabled user is returned unchanged.
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
			if r.Source != SourceSSO || r.Subject != d.Subject {
				return ErrSSOOther
			}
			if r.Disabled {
				return ErrNoChange
			}
			u := r.User
			changed := u.Name != d.Name || u.Email != d.Email || u.Role != d.Role
			u.Name, u.Email, u.Role = d.Name, d.Email, d.Role
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
