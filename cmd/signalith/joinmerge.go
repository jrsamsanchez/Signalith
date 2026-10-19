// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// signalith join --merge: a server that kept its own files (it served
// alone, or waited to join) adds to the cluster what the cluster lacks
// (clustercfg.Merge) and keeps a migration report of what differs, signed
// in the shared settings, for an admin to decide. Nothing the cluster has
// is changed, and differing retention policies hold retention until an
// admin confirms them.

// merge merges this server's files, with the configuration at path as
// join wrote it, into the cluster's shared settings.
func (j *joiner) merge(ctx context.Context, path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	x := &clusterCLI{c: c, log: newLogger(io.Discard), self: j.id, in: os.Stdin, out: j.env.out, errOut: j.env.errOut, by: joinBy}
	x.cl = newStore(c)
	defer x.cl.CloseIdleConnections()
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return fmt.Errorf("this server cannot use the cluster's shared settings (%s)", cmp.Or(why, m.Text()))
	}
	rep, err := clustercfg.Merge(ctx, x.docs, x.files(), joinBy, clustercfg.MergeOptions{Users: rt.SharedUsers(), Settings: rt.SharedSettings()})
	if err != nil {
		return err
	}
	if own, cl := pemSHA256(j.ownCAPEM), pemSHA256([]byte(j.bundle.ClusterCAPEM)); own != "" && cl != "" && own != cl {
		rep.Differ = append(rep.Differ, clustercfg.MergeItem{Kind: clustercfg.MergeAgents, ID: "sha256:" + own,
			Detail: "this server now uses the cluster's certificate authority: agents set up with its own need a new configuration (the Agents page lists them)"})
	}
	if err := x.reports.Save(ctx, joinBy, rep); err != nil {
		return fmt.Errorf("the migration report: %w", err)
	}
	newLogger(j.env.errOut).Info("cluster.merged: this server's own files were merged into the cluster's shared settings", "audit", true, "by", joinBy,
		"node_id", j.id.NodeID, "server", j.id.Name, "added", len(rep.Added), "differ", len(rep.Differ), "retention_held", rep.Held)
	j.printMerge(rep)
	return nil
}

// pemSHA256 is the hex SHA-256 of the first certificate in b, "" for
// none.
func pemSHA256(b []byte) string {
	blk, _ := pem.Decode(bytes.TrimSpace(b))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}

// printMerge says what the merge added and what differs.
func (j *joiner) printMerge(rep *clustercfg.MigrationReport) {
	if len(rep.Added) == 0 {
		j.printf("Merged: the cluster had everything this server's own files hold.\n")
	} else {
		j.printf("Merged into the cluster, from this server's own files:\n")
		for _, it := range rep.Added {
			j.printf("  added %-9s %s\n", it.Kind, it.ID)
		}
	}
	if len(rep.Differ) == 0 {
		return
	}
	j.printf("These differ from the cluster's, which are kept (they are in this server's migration report on the Servers page):\n")
	for _, it := range rep.Differ {
		j.printf("  %-9s %s: %s\n", it.Kind, it.ID, it.Detail)
	}
	if rep.Held {
		j.printf("Retention waits for an admin to confirm the policies on the Data retention page: nothing but the disk guard deletes until then.\n")
	}
}
