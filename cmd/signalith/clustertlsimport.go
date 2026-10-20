// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// maxKeyFile caps a key or certificate file signalith cluster tls import
// reads: a PEM key or certificate is a few kilobytes.
const maxKeyFile = 64 << 10

// readPlainFile reads path, which must be a regular file and not a link,
// of at most maxKeyFile bytes. It is opened without following a link and
// without blocking (openPlain), and the file opened is checked to be a
// regular file and the one looked at, so a link, FIFO or device put in
// its place meanwhile is refused too.
func readPlainFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (a link or a folder is not read)", path)
	}
	if fi.Size() > maxKeyFile {
		return nil, fmt.Errorf("%s is %d bytes, too large for a key or certificate", path, fi.Size())
	}
	f, err := openPlain(path)
	if err != nil {
		return nil, fmt.Errorf("%s could not be opened as a plain file: %w", path, err)
	}
	defer f.Close()
	open, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !open.Mode().IsRegular() || !os.SameFile(fi, open) {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > maxKeyFile {
		clear(data)
		return nil, fmt.Errorf("%s is too large for a key or certificate", path)
	}
	return data, nil
}

// tlsImport gives the cluster its certificate authority's key again, from
// keyFile: the tls/ca.key of an export --to-files folder, or the one the
// founder kept before the cluster took it. Its certificate is certFile,
// or ca.pem next to the key when there is one; either must be the
// cluster's.
func (x *clusterCLI) tlsImport(ctx context.Context, keyFile, certFile string, yes bool) error {
	data, err := readPlainFile(keyFile)
	if err != nil {
		return err
	}
	key, err := clustertls.ParseKey(data)
	clear(data)
	if err != nil {
		return fmt.Errorf("%s: %w", keyFile, err)
	}
	var certPEM []byte
	if certFile != "" {
		if certPEM, err = readPlainFile(certFile); err != nil {
			return err
		}
	} else if def := filepath.Join(filepath.Dir(keyFile), tlsauto.CAFile); fileThere(def) {
		if certPEM, err = readPlainFile(def); err != nil {
			return err
		}
	}
	rt, st, _, err := x.tlsReport(ctx)
	if err != nil {
		return err
	}
	if !st.Published {
		return errors.New("the cluster has no certificate authority yet, so there is no key to give back (signalith cluster tls shows the servers' own)")
	}
	if err := rt.Writable(); err != nil {
		return err
	}
	q := fmt.Sprintf("Give the cluster the key of its certificate authority (%s) again, sealed with the cluster key?", st.CA.CASHA256)
	if !st.CA.KeyLost {
		q = fmt.Sprintf("The cluster still holds a key for its certificate authority (%s). Seal this one in its place?", st.CA.CASHA256)
	}
	if err := x.confirm(q, yes); err != nil {
		return err
	}
	done, err := x.tls.tls.ImportKey(ctx, x.by, certPEM, key)
	if err != nil {
		return err
	}
	if !done {
		fmt.Fprintf(x.out, "The cluster already holds this key for its certificate authority (%s). Nothing was changed.\n", st.CA.CASHA256)
		return nil
	}
	x.audit("gave the cluster its certificate authority's key again", "ca_sha256", st.CA.CASHA256, "was_lost", st.CA.KeyLost)
	fmt.Fprintf(x.out, "The cluster holds its certificate authority's key again (%s), sealed with the cluster key.\n", st.CA.CASHA256)
	fmt.Fprintln(x.out, "Every server renews its HTTPS certificate from it again within seconds.")
	fmt.Fprintf(x.out, "Keep %s offline, or delete it: anyone who holds it can make certificates every agent trusts.\n", keyFile)
	return nil
}

// fileThere reports whether path is there, without following a link.
func fileThere(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
