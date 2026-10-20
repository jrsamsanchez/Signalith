// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"opensearch unreachable at https://admin:Hunter22@os.internal:9200: dial tcp: refused": "opensearch unreachable at https://***@os.internal:9200: dial tcp: refused",
		`bad settings: password="s3cr3t pw", user=bob`:                                         `bad settings: password=***, user=bob`,
		"passphrase: SeCrEt-1 is too short":                                                    "passphrase: *** is too short",
		"api_key=K3Y&format=csv":                                                               "api_key=***&format=csv",
		"sent Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc":                                  "sent Authorization: Bearer ***",
		"the server answered status code: 500":                                                 "the server answered status code: 500",
		"must_change_password=true":                                                            "must_change_password=***",
		"open /srv/signalith/keys/master.key: permission denied":                               "open /srv/signalith/keys/master.key: permission denied",
		"password must be at least 12 characters":                                              "password must be at least 12 characters",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q)\n = %q\nwant %q", in, got, want)
		}
	}
}
