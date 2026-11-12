// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"opensearch unreachable at https://admin:Hunter22@os.internal:9200: dial tcp: refused": "opensearch unreachable at https://***@os.internal:9200: dial tcp: refused",
		`bad settings: password="s3cr3t pw", user=bob`:                                         `bad settings: password="***", user=bob`,
		"passphrase: SeCrEt-1, retry":                                                          "passphrase: ***, retry",
		"api_key=K3Y&format=csv":                                                               "api_key=***&format=csv",
		"sent Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc":                                  "sent Authorization: Bearer ***",
		"the server answered status code: 500":                                                 "the server answered status code: 500",
		"must_change_password=true":                                                            "must_change_password=***",
		"open /srv/signalith/keys/master.key: permission denied":                               "open /srv/signalith/keys/master.key: permission denied",
		"password must be at least 12 characters":                                              "password must be at least 12 characters",

		// JSON, quoted names and escaped quotes.
		`decode {"password":"hunter2"}`:                       `decode {"password":"***"}`,
		`body: {"user": "bob", "api_key": "x", "n": 1}`:       `body: {"user": "bob", "api_key": "***", "n": 1}`,
		`{"client_secret":"a\"b,c","ok":true}`:                `{"client_secret":"***","ok":true}`,
		`{"token":12345}`:                                     `{"token":***}`,
		"settings: {'password': 'hunter2'}":                   "settings: {'password': '***'}",
		"sent Authorization: Token 9944b09199c62bcf9418ad846": "sent Authorization: Token ***",
		"sent Authorization:\tBearer\teyJhbGciOiJIUzI1NiJ9":   "sent Authorization:\tBearer ***",

		// Tabs, and unquoted values with spaces, to the end of the field.
		"password\thunter2":                     "password\t***",
		"password:\thunter2":                    "password:\t***",
		"password=hunter 2":                     "password=***",
		"password=hunter 2; user=bob":           "password=***; user=bob",
		"passphrase: SeCrEt-1 is too short":     "passphrase: ***",
		"token=a b c&x=1\nnext line":            "token=***&x=1\nnext line",
		"secret=one two}":                       "secret=***}",
		"Token validation failed for key: none": "Token validation failed for key: ***",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q)\n = %q\nwant %q", in, got, want)
		}
		if got := Text(Text(in)); got != want {
			t.Errorf("Text twice (%q)\n = %q\nwant %q", in, got, want)
		}
	}
}

// TestTextWhitespaceValue: a secret's name followed by nothing but spaces
// is left as it is rather than panicking (ING-208).
func TestTextWhitespaceValue(t *testing.T) {
	for _, in := range []string{"password= ", "password=  ", "request failed: pwd=\t", "api_key: ", "password= \n", "error for user x: secret=\t\t"} {
		if got := Text(in); got != in {
			t.Errorf("Text(%q) = %q", in, got)
		}
	}
}

// TestTextHidesWhatURLHides: Text hides the secret names URL hides, as
// well as one-time codes, PEM private keys and user:password@host:port
// written without a scheme (ING-219).
func TestTextHidesWhatURLHides(t *testing.T) {
	for in, want := range map[string]string{
		"signature=abc123":                            "signature=***",
		"sessionid=abcdef123456":                      "sessionid=***",
		"jwt: eyJhbGciOiJIUzI1NiJ9.e30.x":             "jwt: ***",
		"otp=123456&pin=0000":                         "otp=***&pin=***",
		"user:pass@host:9200":                         "***@host:9200",
		"dial admin:Hunter22@os.internal:9200 failed": "dial ***@os.internal:9200 failed",
		"bad key -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY----- here": "bad key -----BEGIN RSA PRIVATE KEY----- *** -----END RSA PRIVATE KEY----- here",
		"cut -----BEGIN PRIVATE KEY-----\nMIIEpAIB":                                                     "cut -----BEGIN PRIVATE KEY----- *** ",

		// Words that only look like the names stay.
		"the server answered status code: 500": "the server answered status code: 500",
		"auth: failed for bob":                 "auth: failed for bob",
		"signalith_sender: 10.0.0.1":           "signalith_sender: 10.0.0.1",
		"mapping: keyword":                     "mapping: keyword",
		"spin=3":                               "spin=3",
		"at 12:00 on 2026-01-02":               "at 12:00 on 2026-01-02",
		"bob@example.com: no such user":        "bob@example.com: no such user",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q)\n = %q\nwant %q", in, got, want)
		}
		if got := Text(Text(in)); got != want {
			t.Errorf("Text twice (%q)\n = %q\nwant %q", in, got, want)
		}
	}
	for _, n := range secretNames {
		if !SecretName(n) {
			t.Errorf("URL does not hide %q, which Text hides", n)
		}
	}
}
