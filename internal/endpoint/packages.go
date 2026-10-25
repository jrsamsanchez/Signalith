// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Package is one installed deb or rpm package, as a Linux host's package
// snapshot lists it.
type Package struct {
	Name string `json:"n"`
	// Version is the exact distribution version: 1:8.9p1-3ubuntu0.10
	// (deb) or 1:3.0.7-27.el9 (rpm, with its epoch when it has one).
	Version string `json:"v"`
	// Source is the source package it was built from, as dpkg (openssh,
	// or "openssl (3.0.11-1)" when its version differs) or rpm
	// (openssh-8.0p1-19.el8_8.src.rpm) names it.
	Source string `json:"s,omitempty"`
	Type   string `json:"t"` // deb or rpm
}

// PackageList is a host's installed packages and its system.
type PackageList struct {
	// OS is osquery's platform, such as ubuntu, debian, rhel, rocky or
	// almalinux, and OSVersion its major.minor version, such as 22.4.
	OS        string    `json:"os"`
	OSVersion string    `json:"os_version"`
	OSLike    string    `json:"os_like,omitempty"`
	At        time.Time `json:"at"`
	Packages  []Package `json:"packages"`
}

// HostPackages is the latest package list of one host.
type HostPackages struct {
	NodeID   string   `json:"node_id"`
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ips,omitempty"`
	// Hash changes when the packages or the system do.
	Hash string `json:"hash"`
	// Changed is when the list last changed; At (in PackageList) when
	// the host last sent it.
	Changed time.Time `json:"changed"`
	PackageList
}

// Limits on one host's package list.
const (
	maxPackages     = 20000
	maxPackageField = 200
)

// packageList reads a package snapshot (packagesSQL).
func packageList(rows []map[string]any, at time.Time) *PackageList {
	pl := &PackageList{At: at, Packages: []Package{}}
	for _, c := range rows {
		name, ver := strings.TrimSpace(str(c, "name")), strings.TrimSpace(str(c, "version"))
		switch t := str(c, "type"); t {
		case "os":
			pl.OS, pl.OSVersion, pl.OSLike = cut(strings.ToLower(name), 64), cut(ver, 32), cut(str(c, "source"), 128)
		case "deb", "rpm":
			if name == "" || ver == "" || len(pl.Packages) >= maxPackages {
				continue
			}
			pl.Packages = append(pl.Packages, Package{Name: cut(name, maxPackageField), Version: cut(ver, maxPackageField),
				Source: cut(strings.TrimSpace(str(c, "source")), maxPackageField), Type: t})
		}
	}
	sort.Slice(pl.Packages, func(i, j int) bool {
		a, b := pl.Packages[i], pl.Packages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return pl
}

func (pl *PackageList) hash() string {
	h := sha256.New()
	h.Write([]byte(pl.OS + "\x00" + pl.OSVersion + "\x00"))
	for _, p := range pl.Packages {
		h.Write([]byte(p.Name + "\x00" + p.Version + "\x00" + p.Source + "\x00" + p.Type + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func packagesDocID(nodeID string) string { return "pkg:" + nodeID }

// SavePackages keeps a host's package list. An unchanged list only moves
// its time, so the whole list is written only when it changes.
func (s *Store) SavePackages(ctx context.Context, n *Node, pl *PackageList) error {
	id := packagesDocID(n.ID)
	hash := pl.hash()
	src, v, found, err := s.Docs.Get(ctx, s.Index, id)
	if err != nil {
		return err
	}
	if found {
		var old HostPackages
		if json.Unmarshal(src, &old) == nil && old.Hash == hash && old.Hostname == n.Hostname && strings.Join(old.IPs, ",") == strings.Join(n.IPs, ",") {
			_, err = s.Docs.Update(ctx, s.Index, id, map[string]any{"at": pl.At.UTC()}, false)
			return err
		}
	}
	body := struct {
		Kind string `json:"kind"`
		HostPackages
	}{kindPackages, HostPackages{NodeID: n.ID, Hostname: n.Hostname, IPs: n.IPs, Hash: hash, Changed: s.now().UTC(), PackageList: *pl}}
	body.At = pl.At.UTC()
	if found {
		_, err = s.Docs.PutIf(ctx, s.Index, id, body, v, false)
	} else {
		_, err = s.Docs.Create(ctx, s.Index, id, body, false)
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
		// Another server saved the same host's list at the same time.
		return nil
	}
	return err
}

// HostPackages returns the package list of every Linux host that sent
// one, read one host at a time.
func (s *Store) HostPackages(ctx context.Context) ([]*HostPackages, error) {
	nodes, err := s.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []*HostPackages
	for _, n := range nodes {
		if n.Platform != Linux {
			continue
		}
		src, _, found, err := s.Docs.Get(ctx, s.Index, packagesDocID(n.ID))
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		var hp HostPackages
		if json.Unmarshal(src, &hp) != nil || hp.NodeID != n.ID {
			continue
		}
		// The name and addresses as the host has them now.
		hp.Hostname, hp.IPs = n.Hostname, n.IPs
		out = append(out, &hp)
	}
	return out, nil
}

// dropPackages deletes a removed host's package list.
func (s *Store) dropPackages(ctx context.Context, nodeID string) {
	if _, v, found, err := s.Docs.Get(ctx, s.Index, packagesDocID(nodeID)); err == nil && found {
		_ = s.Docs.DeleteIf(ctx, s.Index, packagesDocID(nodeID), v, false)
	}
}
