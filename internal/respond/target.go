package respond

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Target kinds. An action declares the kind it acts on; "any" takes each
// of the others.
const (
	TargetIP     = "ip"
	TargetDomain = "domain"
	TargetUser   = "user"
	TargetHost   = "host"
	TargetAny    = "any"
)

// TargetKinds lists the kinds a target can be.
var TargetKinds = []string{TargetIP, TargetDomain, TargetUser, TargetHost}

// Limits on a target's length.
const (
	maxNameLen = 253 // a DNS name
	maxUserLen = 256
)

// ValidateTarget checks a target of a kind and returns it in its usual
// form: an IP address as netip prints it, a domain or host name in lower
// case without a trailing dot, a user name trimmed. Values are checked
// strictly because they are passed to firewalls, directories and
// programs: none can start with "-" (read as an option by many programs),
// hold control characters, quotes, shell or template syntax, or be
// longer than a name can be.
//
//   - ip: an IPv4 or IPv6 address, not a range, without a zone; not
//     unspecified (0.0.0.0, ::), loopback, multicast or broadcast, which
//     are never what an analyst means to block.
//   - domain: two or more RFC 1123 labels (letters, digits and hyphens, 1
//     to 63 characters, not starting or ending with a hyphen), at most 253
//     characters, the last label not all digits. Internationalized names
//     go in their xn-- form.
//   - host: a host name (one or more such labels) or an IP address, as
//     EDR and firewall APIs take either.
//   - user: letters and digits of any script, and . _ - @ \ and single
//     spaces inside, at most 256 characters, not starting with - or a dot;
//     at most one @ and one \ (user@domain or DOMAIN\user).
func ValidateTarget(kind, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("enter the %s to act on", kindNoun(kind))
	}
	if !utf8.ValidString(v) {
		return "", fmt.Errorf("the %s is not valid text", kindNoun(kind))
	}
	switch kind {
	case TargetIP:
		return validIP(v)
	case TargetDomain:
		d, err := validName(v, true)
		if err != nil {
			return "", fmt.Errorf("%q is not a domain name: %v", v, err)
		}
		return d, nil
	case TargetHost:
		if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
			return validIP(v)
		}
		h, err := validName(v, false)
		if err != nil {
			return "", fmt.Errorf("%q is not a host name or IP address: %v", v, err)
		}
		return h, nil
	case TargetUser:
		return validUser(v)
	}
	return "", fmt.Errorf("unknown target kind %q", kind)
}

// GuessKind returns the likeliest kind of a value for an action that takes
// any: an IP address, a user (with @ or \), a domain (with a dot) or a
// host.
func GuessKind(v string) string {
	v = strings.TrimSpace(v)
	switch {
	case isIP(v):
		return TargetIP
	case strings.ContainsAny(v, `@\ `):
		return TargetUser
	case strings.Contains(strings.TrimSuffix(v, "."), "."):
		return TargetDomain
	}
	return TargetHost
}

func isIP(v string) bool {
	_, err := netip.ParseAddr(v)
	return err == nil
}

func kindNoun(kind string) string {
	switch kind {
	case TargetIP:
		return "IP address"
	case TargetDomain:
		return "domain"
	case TargetUser:
		return "user name"
	case TargetHost:
		return "host name"
	}
	return "target"
}

func validIP(v string) (string, error) {
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" {
		return "", fmt.Errorf("%q is not an IP address", v)
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return "", fmt.Errorf("%s is the unspecified address, not a real host", a)
	case a.IsLoopback():
		return "", fmt.Errorf("%s is a loopback address: it is the machine itself, wherever the action runs", a)
	case a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "", fmt.Errorf("%s is a multicast or broadcast address", a)
	}
	return a.String(), nil
}

// validName checks a DNS name by RFC 1123 label rules. domain asks for at
// least two labels and a last label that is not all digits.
func validName(v string, domain bool) (string, error) {
	v = strings.ToLower(strings.TrimSuffix(v, "."))
	if len(v) > maxNameLen {
		return "", fmt.Errorf("it is longer than %d characters", maxNameLen)
	}
	labels := strings.Split(v, ".")
	if domain && len(labels) < 2 {
		return "", fmt.Errorf("it needs at least two parts, like example.com")
	}
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("it has an empty part between dots")
		}
		if len(l) > 63 {
			return "", fmt.Errorf("the part %q is longer than 63 characters", l)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("the part %q starts or ends with a hyphen", l)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				if r > unicode.MaxASCII {
					return "", fmt.Errorf("it has the character %q; enter internationalized names in their xn-- form", r)
				}
				return "", fmt.Errorf("it has the character %q; only letters, digits, hyphens and dots are allowed", r)
			}
		}
	}
	if domain {
		last := labels[len(labels)-1]
		if strings.Trim(last, "0123456789") == "" {
			return "", fmt.Errorf("its last part %q is a number", last)
		}
	}
	return v, nil
}

func validUser(v string) (string, error) {
	if utf8.RuneCountInString(v) > maxUserLen {
		return "", fmt.Errorf("the user name is longer than %d characters", maxUserLen)
	}
	if v[0] == '-' || v[0] == '.' {
		return "", fmt.Errorf("%q starts with %q, which programs could read as something else", v, v[:1])
	}
	if strings.Count(v, "@") > 1 || strings.Count(v, `\`) > 1 {
		return "", fmt.Errorf("%q has more than one @ or \\; use user@domain or DOMAIN\\user", v)
	}
	if strings.Contains(v, "  ") {
		return "", fmt.Errorf("%q has two spaces in a row", v)
	}
	for _, r := range v {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
		case strings.ContainsRune(`._-@\ `, r):
		default:
			return "", fmt.Errorf("%q has the character %q; user names may hold letters, digits, spaces and . _ - @ \\", v, r)
		}
	}
	return v, nil
}
