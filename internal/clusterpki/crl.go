package clusterpki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// The revocation list (opensearch.crl_file): OpenSearch checks every
// client certificate against it (plugins.security.ssl.http.crl.*, which
// reads the file again on each connection), so a server removed from the
// cluster loses its access at once rather than when its certificate
// expires. Each server that has it set writes it from the osca document
// whenever the revoked certificates change, and checks it on every round:
// OpenSearch refuses every certificate, the admin's included, while the
// list it checks is missing, unreadable or expired.

// crlWarnBefore is how long before it expires an existing list is worth a
// warning.
const crlWarnBefore = 30 * 24 * time.Hour

// syncCRL writes the revocation list when this server can and it is not
// the one the osca document calls for, then checks the file, whoever
// wrote it. Nil when opensearch.crl_file is not set.
func (i *Identity) syncCRL() *cluster.CRLStatus {
	path := i.o.CRLFile
	if path == "" {
		return nil
	}
	now := i.now()
	conn := i.o.Conn()
	st := &cluster.CRLStatus{File: path}
	cas := readCerts(conn.CAFile)
	if len(cas) == 0 {
		st.Problem = "opensearch.crl_file is set, but opensearch.ca_file holds no certificate authority to check the revocation list against."
		return st
	}
	var wrote error
	if b, ok := i.o.OSCA.Get(); ok {
		if ca, err := b.Cert(); err == nil {
			want := b.RevokedSerials(now)
			if Trusted(conn.CAFile, ca) == nil && i.o.OSCA.Opens() == nil {
				// A list that already names every revoked certificate is
				// kept, even when it names more: a server whose copy of
				// the osca document is behind must not take any off.
				// Certificates leave the list only once they expire.
				cur, err := ospki.ReadCRL(path, ca, now)
				if err != nil || countIn(want, ospki.CRLSerials(cur)) < len(want) || cur.NextUpdate.Before(ca.NotAfter) {
					wrote = i.writeCRL(path, now, len(want))
				}
			}
			// Checked whether or not this server can write it: a list
			// another server or bootstrap-docker wrote may be behind too.
			if cur, err := readCRLAgainst(path, cas, now); err == nil {
				if missing := len(want) - countIn(want, ospki.CRLSerials(cur)); missing > 0 {
					st.Problem = fmt.Sprintf("OpenSearch's revocation list %s does not name %d revoked %s yet, so %s still %s OpenSearch.",
						path, missing, plural(missing, "certificate", "certificates"), plural(missing, "it", "they"), plural(missing, "opens", "open"))
					if wrote != nil {
						st.Problem += " This server could not update it: " + wrote.Error()
					}
				}
			}
		}
	}
	l, err := readCRLAgainst(path, cas, now)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		st.Problem = "OpenSearch's revocation list " + path + " is missing. While OpenSearch checks it, it refuses every certificate sign-in, this server's included." + crlFix(wrote)
	case err != nil:
		st.Problem = "OpenSearch's revocation list " + path + " cannot be used: " + err.Error() + ". While OpenSearch checks it, it refuses every certificate sign-in, this server's included." + crlFix(wrote)
	default:
		st.Revoked = len(l.RevokedCertificateEntries)
		if !l.NextUpdate.IsZero() {
			t := l.NextUpdate.UTC()
			st.NextUpdate = &t
			if st.Problem == "" && t.Sub(now) < crlWarnBefore {
				st.Problem = "OpenSearch's revocation list " + path + " expires on " + t.Format(time.DateOnly) + ", and OpenSearch then refuses every certificate sign-in. Make OpenSearch's certificates again from a new certificate authority before then (bootstrap-docker -new-ca in Docker)."
			}
		}
		if st.Problem == "" && wrote != nil {
			st.Problem = "This server could not update OpenSearch's revocation list " + path + ": " + wrote.Error()
		}
	}
	return st
}

// crlFix says what to do about a missing or broken list.
func crlFix(wrote error) string {
	s := " This server writes it again when the cluster keeps OpenSearch's certificate authority; in Docker, docker compose -f deploy/docker/docker-compose.yml up -d writes it too."
	if wrote != nil {
		s = " This server could not write it: " + wrote.Error() + "." + s
	}
	return s
}

// writeCRL writes the osca document's revocation list to path, readable
// by OpenSearch, which runs as another user.
func (i *Identity) writeCRL(path string, now time.Time, revoked int) error {
	b, err := i.o.OSCA.CRL(now)
	if err != nil {
		return err
	}
	if err := replacePublic(path, b); err != nil {
		return err
	}
	i.o.Log.Info("wrote OpenSearch's revocation list", "audit", true, "file", path, "revoked", revoked)
	return nil
}

// replacePublic writes b to path in one step, readable by everyone: a
// revocation list holds no secret, and OpenSearch reads it as its own
// user.
func replacePublic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".crl-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readCRLAgainst reads the revocation list at path, signed by one of
// cas.
func readCRLAgainst(path string, cas []*x509.Certificate, now time.Time) (*x509.RevocationList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var first error
	for _, ca := range cas {
		l, err := ospki.ParseCRL(b, ca, now)
		if err == nil {
			return l, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

// readCerts reads the certificates of a PEM file.
func readCerts(path string) []*x509.Certificate {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []*x509.Certificate
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func countIn(want, have []string) int {
	n := 0
	for _, s := range want {
		if slices.Contains(have, s) {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
