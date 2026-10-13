package respond

import (
	"strings"
	"testing"
)

func TestValidateTarget(t *testing.T) {
	ok := []struct{ kind, in, want string }{
		{TargetIP, " 203.0.113.7 ", "203.0.113.7"},
		{TargetIP, "::ffff:10.1.2.3", "10.1.2.3"},
		{TargetIP, "2001:db8::1", "2001:db8::1"},
		{TargetIP, "10.0.0.5", "10.0.0.5"},
		{TargetDomain, "Bad.Example.COM.", "bad.example.com"},
		{TargetDomain, "xn--bcher-kva.example", "xn--bcher-kva.example"},
		{TargetHost, "WS-0042", "ws-0042"},
		{TargetHost, "web01.corp.example.com", "web01.corp.example.com"},
		{TargetHost, "10.20.30.40", "10.20.30.40"},
		{TargetUser, "jdoe", "jdoe"},
		{TargetUser, `CORP\jdoe`, `CORP\jdoe`},
		{TargetUser, "jane.doe@corp.example.com", "jane.doe@corp.example.com"},
		{TargetUser, "José Pérez", "José Pérez"},
		{TargetUser, "svc_backup-01", "svc_backup-01"},
	}
	for _, c := range ok {
		got, err := ValidateTarget(c.kind, c.in)
		if err != nil || got != c.want {
			t.Errorf("ValidateTarget(%s, %q) = %q, %v; want %q", c.kind, c.in, got, err, c.want)
		}
	}
	bad := []struct{ kind, in string }{
		{TargetIP, ""}, {TargetIP, "10.0.0.0/8"}, {TargetIP, "0.0.0.0"}, {TargetIP, "::"}, {TargetIP, "127.0.0.1"},
		{TargetIP, "::1"}, {TargetIP, "224.0.0.1"}, {TargetIP, "255.255.255.255"}, {TargetIP, "fe80::1%eth0"},
		{TargetIP, "1.2.3.4; rm -rf /"}, {TargetIP, "-1.2.3.4"}, {TargetIP, "1.2.3"},
		{TargetDomain, "localhost"}, {TargetDomain, "-bad.example.com"}, {TargetDomain, "bad-.example.com"},
		{TargetDomain, "a..example.com"}, {TargetDomain, "ex ample.com"}, {TargetDomain, "évil.example.com"},
		{TargetDomain, "1.2.3.4"}, {TargetDomain, "example.com/path"}, {TargetDomain, "{{.ip}}.example.com"},
		{TargetDomain, strings.Repeat("a", 64) + ".com"}, {TargetDomain, strings.Repeat("abcdefghi.", 26) + "com"},
		{TargetDomain, "a_b.example.com"}, {TargetDomain, "$(id).example.com"},
		{TargetHost, "-oProxyCommand=x"}, {TargetHost, "host name"}, {TargetHost, "host;id"}, {TargetHost, "127.0.0.1"},
		{TargetUser, "-rf"}, {TargetUser, ".hidden"}, {TargetUser, "a@b@c"}, {TargetUser, `a\b\c`}, {TargetUser, "a  b"},
		{TargetUser, "jd\noe"}, {TargetUser, "jdoe\x00"}, {TargetUser, `j"doe`}, {TargetUser, "j'doe"}, {TargetUser, "j;doe"},
		{TargetUser, "$(whoami)"}, {TargetUser, "`id`"}, {TargetUser, "{{.ip}}"}, {TargetUser, "a|b"}, {TargetUser, "a&b"},
		{TargetUser, "%PATH%"}, {TargetUser, "a*"}, {TargetUser, "(cn=*)"}, {TargetUser, strings.Repeat("a", 257)},
		{"bogus", "x"},
	}
	for _, c := range bad {
		if got, err := ValidateTarget(c.kind, c.in); err == nil {
			t.Errorf("ValidateTarget(%s, %q) = %q, want an error", c.kind, c.in, got)
		}
	}
}

func TestGuessKind(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1": TargetIP, "2001:db8::2": TargetIP, "jdoe@corp.example.com": TargetUser,
		`CORP\jdoe`: TargetUser, "bad.example.com": TargetDomain, "ws-0042": TargetHost} {
		if got := GuessKind(in); got != want {
			t.Errorf("GuessKind(%q) = %s, want %s", in, got, want)
		}
	}
}
