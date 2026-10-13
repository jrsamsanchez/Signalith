package users

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Response actions can switch a directory account off and on again, with
// the same server, CA certificate and timeouts as directory sign-in. Only
// over an encrypted connection with certificate checks on: the change is
// made with an account allowed to write, whose password must never cross
// the network in the clear.

// accountDisable is Active Directory's ACCOUNTDISABLE bit of
// userAccountControl.
const accountDisable = 0x2

// AccountChange is a request to disable or enable one directory account.
type AccountChange struct {
	// Login is the account's logon name, user@domain or DOMAIN\name.
	Login string
	// Disable switches the account off; false switches it on again.
	Disable bool
	// BindDN and BindPassword are the account that makes the change. When
	// BindDN is empty the directory sign-in service account is used.
	BindDN       string
	BindPassword string
	// Attribute and Value are for directories other than Active
	// Directory: disabling sets Attribute to Value (such as nsAccountLock
	// TRUE on 389 Directory Server), enabling removes Attribute.
	Attribute string
	Value     string
	// DryRun finds the account and reports what would change, without
	// changing it.
	DryRun bool
}

// AccountResult says what happened to an account.
type AccountResult struct {
	DN       string `json:"dn"`
	Username string `json:"username"`
	Server   string `json:"server"`
	// Changed is false when the account already was as asked.
	Changed bool `json:"changed"`
	// Before and After are the value of userAccountControl (or of the
	// configured attribute) before and after the change.
	Before string `json:"before"`
	After  string `json:"after"`
}

// Domain returns the DNS domain a base DN such as DC=corp,DC=example,DC=com
// names (corp.example.com), or "".
func Domain(baseDN string) string {
	root := namingContext(baseDN)
	if root == "" {
		return ""
	}
	parsed, err := ldap.ParseDN(root)
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(parsed.RDNs))
	for _, r := range parsed.RDNs {
		parts = append(parts, strings.ToLower(r.Attributes[0].Value))
	}
	return strings.Join(parts, ".")
}

// WriteProblem says why s cannot be used to change accounts, or "" when
// it can: it needs a server address, a user base DN, and encryption with
// certificate checks on every server.
func WriteProblem(s LDAPSettings) string {
	s.Normalize()
	if s.URL == "" || s.UserBaseDN == "" {
		return "Set up the directory first: open Users, then Directory sign-in, and enter the server and the user base DN. Sign-in does not have to be on."
	}
	for _, raw := range s.servers() {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Sprintf("The directory server address %q is not valid.", raw)
		}
		if u.Scheme != "ldaps" && !s.StartTLS {
			return "Changing accounts needs an encrypted connection to the directory: use ldaps:// or turn on StartTLS under Users, Directory sign-in."
		}
	}
	if s.TLSSkipVerify {
		return "Changing accounts needs the directory's certificate checked: add its CA certificate under Users, Directory sign-in, and turn off skipping the check."
	}
	return ""
}

// accountFilter finds an account by logon name, including disabled ones,
// so a disabled account can be enabled again.
func accountFilter(s *LDAPSettings, login string) string {
	esc := ldap.EscapeFilter(login)
	if s.Type == TypeActiveDirectory {
		return "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=" + esc + ")(userPrincipalName=" + esc + ")))"
	}
	return strings.ReplaceAll(s.UserFilter, "{username}", esc)
}

// ChangeAccount disables or enables one account. On Active Directory it
// sets or clears the ACCOUNTDISABLE bit of userAccountControl after
// reading its current value, so no other flag changes; elsewhere it sets
// or removes ch.Attribute. It refuses to change the account that makes
// the change, which would lock Signalith out of the directory.
func ChangeAccount(ctx context.Context, s LDAPSettings, ch AccountChange) (*AccountResult, error) {
	s.Normalize()
	if p := WriteProblem(s); p != "" {
		return nil, errors.New(p)
	}
	if strings.TrimSpace(ch.BindDN) != "" {
		s.BindDN, s.BindPassword = strings.TrimSpace(ch.BindDN), ch.BindPassword
	}
	if s.BindDN == "" || s.BindPassword == "" {
		return nil, errors.New("changing accounts needs an account allowed to write: enter its bind DN and password in the action, or set the directory's service account")
	}
	ad := s.Type == TypeActiveDirectory
	attr := "userAccountControl"
	if !ad {
		attr = strings.TrimSpace(ch.Attribute)
		if attr == "" || !attrPattern.MatchString(attr) {
			return nil, errors.New("this directory is not Active Directory: name the attribute that switches an account off, such as nsAccountLock")
		}
		if ch.Disable && strings.TrimSpace(ch.Value) == "" {
			return nil, fmt.Errorf("enter the value that switches an account off, such as TRUE for %s", attr)
		}
	}
	login := LoginName(ch.Login)
	if !validDirectoryName(login) {
		return nil, fmt.Errorf("%q is not an account name", ch.Login)
	}
	c, err := dialAny(ctx, &s)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if c.tls == "" {
		return nil, errors.New("the connection to the directory is not encrypted, so no change was made")
	}
	if err := c.bindService(&s); err != nil {
		return nil, err
	}
	res, err := c.l.Search(ldap.NewSearchRequest(s.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, s.Timeout, false, accountFilter(&s, login), []string{attr, s.UsernameAttribute}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || (res != nil && len(res.Entries) > 1) {
		return nil, fmt.Errorf("more than one account matches %q under %s, so nothing was changed", login, s.UserBaseDN)
	}
	if err != nil {
		return nil, explain("search", c.server, err, &s)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no account named %q was found under %s", login, s.UserBaseDN)
	}
	e := res.Entries[0]
	if sameDN(e.DN, s.BindDN) {
		return nil, fmt.Errorf("%s is the account Signalith changes accounts with; it cannot change itself", login)
	}
	out := &AccountResult{DN: e.DN, Username: e.GetEqualFoldAttributeValue(s.UsernameAttribute), Server: c.server}
	if out.Username == "" {
		out.Username = login
	}
	out.Before = e.GetEqualFoldAttributeValue(attr)
	req := ldap.NewModifyRequest(e.DN, nil)
	if ad {
		uac, err := strconv.ParseInt(out.Before, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("could not read userAccountControl of %s (%q); check that the account may read it", e.DN, out.Before)
		}
		next := uac &^ accountDisable
		if ch.Disable {
			next = uac | accountDisable
		}
		out.After = strconv.FormatInt(next, 10)
		out.Changed = next != uac
		req.Replace(attr, []string{out.After})
	} else {
		switch {
		case ch.Disable:
			out.After = strings.TrimSpace(ch.Value)
			out.Changed = out.Before != out.After
			req.Replace(attr, []string{out.After})
		default:
			out.Changed = out.Before != ""
			req.Delete(attr, nil)
		}
	}
	if !out.Changed || ch.DryRun {
		return out, nil
	}
	if err := c.l.Modify(req); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			return nil, &DirectoryError{Code: "write_refused", Server: c.server, Err: err,
				Message: fmt.Sprintf("The directory refused to change %s of %s: %s is not allowed to. Delegate \"Read/Write %s\" on the account's OU to it.", attr, e.DN, s.BindDN, attr)}
		}
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode < ldap.ErrorNetwork {
			return nil, &DirectoryError{Code: "write_failed", Server: c.server, Err: err,
				Message: fmt.Sprintf("The directory did not change %s of %s: %s.", attr, e.DN, le.Err)}
		}
		return nil, explain("modify", c.server, err, &s)
	}
	return out, nil
}

// CheckWriteAccount connects and binds as the account that would change
// accounts, and finds login when it is not empty, without changing
// anything. It is the test of a disable-user action.
func CheckWriteAccount(ctx context.Context, s LDAPSettings, ch AccountChange) ([]Step, error) {
	s.Normalize()
	if p := WriteProblem(s); p != "" {
		return nil, errors.New(p)
	}
	if strings.TrimSpace(ch.BindDN) != "" {
		s.BindDN, s.BindPassword = strings.TrimSpace(ch.BindDN), ch.BindPassword
	}
	if s.BindDN == "" || s.BindPassword == "" {
		return nil, errors.New("enter the bind DN and password of an account allowed to write, or set the directory's service account")
	}
	var steps []Step
	c, err := dialAny(ctx, &s)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	steps = append(steps, Step{Step: "connect", OK: true, Message: fmt.Sprintf("Connected to %s over %s.", strings.TrimPrefix(strings.TrimPrefix(c.server, "ldaps://"), "ldap://"), c.tls)})
	if err := c.bindService(&s); err != nil {
		return steps, err
	}
	steps = append(steps, Step{Step: "bind", OK: true, Message: "Signed in as " + s.BindDN + "."})
	if strings.TrimSpace(ch.Login) == "" {
		return steps, nil
	}
	r, err := ChangeAccount(ctx, s, AccountChange{Login: ch.Login, Disable: ch.Disable, Attribute: ch.Attribute, Value: ch.Value, DryRun: true})
	if err != nil {
		return steps, err
	}
	state := "enabled"
	if r.Before != "" {
		if n, err := strconv.ParseInt(r.Before, 10, 64); err == nil && s.Type == TypeActiveDirectory && n&accountDisable != 0 {
			state = "disabled"
		} else if s.Type != TypeActiveDirectory {
			state = "switched off (" + r.Before + ")"
		}
	}
	steps = append(steps, Step{Step: "user", OK: true, Message: fmt.Sprintf("Found %s (%s); it is %s now. Nothing was changed.", r.Username, r.DN, state)})
	return steps, nil
}
