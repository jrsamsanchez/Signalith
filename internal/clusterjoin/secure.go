// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"errors"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// ErrNotSecured is what join, approval, the token API and import-key
// answer when OpenSearch is not secured: a second member must never be
// added to an OpenSearch without https and sign-in.
var ErrNotSecured = errors.New("Multi-server needs OpenSearch with security turned on. See Add a server → Prepare OpenSearch.")

// RequireSecured checks that the OpenSearch o (and each of the further
// addresses urls, opensearch.urls once it exists) is secured: every
// address is https with its certificate checked (opensearch.ca_file, or
// the system's authorities; never tls_skip_verify), and Signalith signs
// in with a password or a client certificate. Otherwise it returns
// ErrNotSecured.
func RequireSecured(o config.OpenSearch, urls ...string) error {
	addrs := append([]string{o.URL}, urls...)
	for _, a := range addrs {
		u, err := url.Parse(strings.TrimSpace(a))
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return ErrNotSecured
		}
	}
	if o.TLSSkipVerify {
		return ErrNotSecured
	}
	password := o.Username != "" && o.Password != ""
	cert := o.CertFile != "" && o.KeyFile != ""
	if !password && !cert {
		return ErrNotSecured
	}
	return nil
}
