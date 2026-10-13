package ingest

import "testing"

// TestSSHUserNameCannotChooseSource: sshd prints the user name a client
// sent as it was sent, so an attacker can put " from <addr> port <n>" in
// it, and on a failed attempt a client can put the same in a certificate's
// key ID, which sshd prints after its own clause. The source is the
// address in the last clause when nothing but " ssh2" follows it; when
// key details follow and there is more than one clause, no source is set
// and src_ambiguous is. The whole name is kept as the user.
func TestSSHUserNameCannotChooseSource(t *testing.T) {
	cases := []struct {
		name, msg string
		want      map[string]any
	}{
		{"failed, invalid user",
			"Failed password for invalid user root from 198.51.100.7 port 22 from 203.0.113.50 port 51515 ssh2",
			map[string]any{"user": "root from 198.51.100.7 port 22", "src": "203.0.113.50", "src_port": int64(51515),
				"action": "failure", "reason": "unknown user", "authentication_method": "password"}},
		{"failed, a name that copies sshd's ending too",
			"Failed password for invalid user a from 198.51.100.7 port 22 ssh2 from 203.0.113.50 port 51515 ssh2",
			map[string]any{"user": "a from 198.51.100.7 port 22 ssh2", "src": "203.0.113.50", "src_port": int64(51515)}},
		{"failed publickey, a name that copies a key",
			"Failed publickey for invalid user x from 198.51.100.7 port 22 ssh2: RSA SHA256:fake from 203.0.113.50 port 40000 ssh2: ED25519 SHA256:real",
			map[string]any{"user": "x from 198.51.100.7 port 22 ssh2: RSA SHA256:fake", "src_ambiguous": true,
				"authentication_method": "publickey", "reason": "unknown user"}},
		{"failed publickey, a certificate key ID that copies sshd's clause",
			"Failed publickey for invalid user root from 203.0.113.50 port 51515 ssh2: ED25519-CERT SHA256:abc ID x from 198.51.100.7 port 22 (serial 1) CA ED25519 SHA256:def",
			map[string]any{"user": "root from 203.0.113.50 port 51515 ssh2: ED25519-CERT SHA256:abc ID x", "src_ambiguous": true,
				"authentication_method": "publickey", "reason": "unknown user", "action": "failure"}},
		{"failed publickey, a valid user and a certificate key ID that copies sshd's clause",
			"Failed publickey for root from 203.0.113.50 port 51515 ssh2: RSA-CERT SHA256:abc ID x from 198.51.100.7 port 22 ssh2 (serial 1) CA RSA SHA256:def",
			map[string]any{"src_ambiguous": true, "action": "failure"}},
		{"invalid user",
			"Invalid user admin from 198.51.100.7 port 22 from 203.0.113.50 port 51515",
			map[string]any{"user": "admin from 198.51.100.7 port 22", "src": "203.0.113.50", "src_port": int64(51515),
				"signature": "SSH invalid user"}},
		{"invalid user, older sshd without a port",
			"Invalid user admin from 198.51.100.7 from 203.0.113.50",
			map[string]any{"user": "admin from 198.51.100.7", "src": "203.0.113.50"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := ParseProgram("db1", "sshd", "811", c.msg, "linux:auth")
			if ev.Model != "Authentication" {
				t.Fatalf("model = %s", ev.Model)
			}
			expect(t, ev.Fields, c.want)
			if c.want["src_ambiguous"] == true {
				// The address is hidden, never chosen.
				if src, ok := ev.Fields["src"]; ok {
					t.Errorf("src = %v, want none", src)
				}
				if p, ok := ev.Fields["src_port"]; ok {
					t.Errorf("src_port = %v, want none", p)
				}
			} else if _, ok := ev.Fields["src_ambiguous"]; ok {
				t.Errorf("src_ambiguous set")
			}
			if ev.Fields["host"] != "db1" {
				t.Errorf("host = %v", ev.Fields["host"])
			}
		})
	}
}

// TestSSHLineShapes: the usual sshd lines keep parsing as they did, and a
// source that is not an IP address is not recorded as one.
func TestSSHLineShapes(t *testing.T) {
	cases := []struct {
		msg   string
		want  map[string]any
		noSrc bool
	}{
		{"Accepted publickey for deploy from 192.0.2.10 port 40200 ssh2: RSA SHA256:abc",
			map[string]any{"action": "success", "user": "deploy", "src": "192.0.2.10", "src_port": int64(40200), "authentication_method": "publickey"}, false},
		{"Accepted publickey for deploy from 192.0.2.10 port 40200 ssh2: ED25519-CERT SHA256:abc ID deploy@ci (serial 7) CA ED25519 SHA256:def",
			map[string]any{"action": "success", "user": "deploy", "src": "192.0.2.10"}, false},
		{"Accepted keyboard-interactive/pam for alice from 2001:db8::7 port 50000 ssh2",
			map[string]any{"action": "success", "user": "alice", "src": "2001:db8::7", "authentication_method": "keyboard-interactive/pam"}, false},
		{"Failed password for bob from 192.0.2.4 port 1 ssh2",
			map[string]any{"action": "failure", "user": "bob", "src": "192.0.2.4", "reason": "bad password"}, false},
		{"Failed none for invalid user  from 192.0.2.4 port 2 ssh2",
			map[string]any{"action": "failure", "user": "", "src": "192.0.2.4", "reason": "unknown user"}, false},
		{"Failed password for root from 192.0.2.4 port 22",
			map[string]any{"action": "failure", "user": "root", "src": "192.0.2.4", "src_port": int64(22)}, false},
		{"Invalid user oracle from 192.0.2.4 port 40122",
			map[string]any{"action": "failure", "user": "oracle", "src": "192.0.2.4", "src_port": int64(40122)}, false},
		{"Invalid user oracle from 192.0.2.4",
			map[string]any{"user": "oracle", "src": "192.0.2.4"}, false},
		{"Invalid user  from 192.0.2.4 port 40122",
			map[string]any{"user": "", "src": "192.0.2.4"}, false},
		{"Failed password for root from UNKNOWN port 65535 ssh2",
			map[string]any{"action": "failure", "user": "root"}, true},
		{"Invalid user root from attacker.example port 22",
			map[string]any{"user": "root"}, true},
	}
	for _, c := range cases {
		ev := ParseProgram("web1", "sshd", "811", c.msg, "linux:auth")
		if ev.Model != "Authentication" {
			t.Errorf("%q: model = %s", c.msg, ev.Model)
			continue
		}
		expect(t, ev.Fields, c.want)
		if _, ok := ev.Fields["src"]; ok == c.noSrc {
			t.Errorf("%q: src = %v", c.msg, ev.Fields["src"])
		}
		if _, ok := ev.Fields["src_ambiguous"]; ok {
			t.Errorf("%q: src_ambiguous set", c.msg)
		}
	}
}
