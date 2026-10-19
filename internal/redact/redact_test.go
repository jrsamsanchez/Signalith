// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

func TestURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"http://127.0.0.1:9200": "http://127.0.0.1:9200",
		"https://admin:OsAdm1nPass@os.internal:9200":                             "https://***@os.internal:9200",
		"https://tokenonly@os.internal":                                          "https://***@os.internal",
		"https://feeds.example/api/explore.php?q=risk%3Dhigh&key=URL-SECRET-KEY": "https://feeds.example/api/explore.php?key=***&q=risk%3Dhigh",
		"https://x.example/f?apikey=s1&format=csv":                               "https://x.example/f?apikey=***&format=csv",
		"https://bucket.s3.example/o?X-Amz-Signature=abc&X-Amz-Credential=AK":    "https://bucket.s3.example/o?X-Amz-Credential=***&X-Amz-Signature=***",
		"https://h.example/cb#access_token=abc":                                  "https://h.example/cb#***",
		"http://u:p@[::1]:9200/path":                                             "http://***@[::1]:9200/path",
		"http://user:pa ss@host:9200/%zz":                                        "http://***@host:9200",
		"not a url with secret\x7f":                                              "***",
		// No scheme: the parser takes the user name for one.
		"admin:S3CR3T@opensearch.corp:9200":          "***@opensearch.corp:9200",
		"admin:p@ss/S3CR3T@opensearch.corp:9200/x?y": "***@opensearch.corp:9200",
		"S3CR3T@opensearch.corp":                     "***@opensearch.corp",
	} {
		got := URL(in)
		if got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
		for _, secret := range []string{"OsAdm1nPass", "URL-SECRET-KEY", "s1&", "tokenonly", "abc", "S3CR3T"} {
			if strings.Contains(got, secret) {
				t.Errorf("URL(%q) = %q still shows %q", in, got, secret)
			}
		}
	}
}

func TestStrip(t *testing.T) {
	out, user, pw, ok := Strip("https://signalith:S3cr3t@os.internal:9200/")
	if !ok || out != "https://os.internal:9200/" || user != "signalith" || pw != "S3cr3t" {
		t.Errorf("Strip = %q %q %q %v", out, user, pw, ok)
	}
	if out, _, _, ok := Strip("http://127.0.0.1:9200"); ok || out != "http://127.0.0.1:9200" {
		t.Errorf("no userinfo: %q %v", out, ok)
	}
}
