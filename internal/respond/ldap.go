package respond

import (
	"context"
	"errors"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// directory returns the directory settings disable_user actions use.
func (r *Runner) directory() (users.LDAPSettings, error) {
	if r.Directory == nil {
		return users.LDAPSettings{}, errors.New("this server has no directory settings")
	}
	return r.Directory(), nil
}

// accountChange is the change a disable_user action makes.
func accountChange(c Connector, login string, dryRun bool) users.AccountChange {
	return users.AccountChange{Login: login, Disable: c.Operation != OpEnable, BindDN: c.BindDN, BindPassword: c.BindPassword,
		Attribute: c.DisableAttribute, Value: c.DisableValue, DryRun: dryRun}
}

// runDisableUser disables or enables a directory account.
func (r *Runner) runDisableUser(ctx context.Context, c Connector, login string) result {
	s, err := r.directory()
	if err != nil {
		return result{err: err}
	}
	verb, done := "disable", "disabled"
	if c.Operation == OpEnable {
		verb, done = "enable", "enabled"
	}
	res, err := users.ChangeAccount(ctx, s, accountChange(c, login, false))
	if err != nil {
		var de *users.DirectoryError
		if errors.As(err, &de) {
			return result{summary: fmt.Sprintf("Could not %s %s.", verb, login), output: de.Detail(), err: errors.New(de.Message)}
		}
		return result{summary: fmt.Sprintf("Could not %s %s.", verb, login), err: err}
	}
	attr := "userAccountControl"
	if c.DisableAttribute != "" && s.Type != users.TypeActiveDirectory {
		attr = c.DisableAttribute
	}
	out := fmt.Sprintf("Account: %s\nServer: %s\n%s: %s -> %s", res.DN, res.Server, attr, orNone(res.Before), orNone(res.After))
	if !res.Changed {
		return result{summary: fmt.Sprintf("%s was already %s; nothing changed.", res.Username, done), output: out}
	}
	return result{summary: fmt.Sprintf("%s is now %s.", res.Username, done), output: out}
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
