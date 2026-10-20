// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"slices"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/sample"
)

// demoOffJobs are the background jobs a public demo (demo.enabled; see
// docs/demo.md) never runs: they download from or send to other systems
// (threat intel feeds, notifications, playbooks, Jira and ServiceNow) or
// take events in (Microsoft 365 and Okta).
var demoOffJobs = []string{"threat intel feeds", "notifications", "playbooks", "ticketing", "microsoft 365 audit log", "okta system log"}

// demoSampleJob is the background job that keeps a public demo's sample
// data loaded and recent.
const demoSampleJob = "demo sample data"

// demoJobs returns the background jobs of a server started with c: in
// demo mode, without demoOffJobs and with the job that loads the sample
// data again every day; otherwise jobs as they are.
func demoJobs(c *config.Config, jobs []cluster.Job, loader *sample.Loader, log *slog.Logger) []cluster.Job {
	if !c.DemoOn() {
		return jobs
	}
	out := slices.DeleteFunc(slices.Clone(jobs), func(j cluster.Job) bool { return slices.Contains(demoOffJobs, j.Name) })
	return append(out, cluster.Job{Name: demoSampleJob, Run: func(ctx context.Context) {
		sample.KeepFresh(ctx, loader, sample.FreshEvery, log)
	}})
}

// logDemo says at startup what demo mode turns off.
func logDemo(c *config.Config, log *slog.Logger) {
	if !c.DemoOn() {
		return
	}
	log.Warn("this server is a public demo (demo.enabled): visitors sign in as a read-only analyst, and event intake, syslog, the AI assistant, " +
		"notifications, ticketing, chat buttons, response actions, playbooks, vulnerability scans, threat intel downloads, Microsoft 365, Okta, " +
		"single sign-on, SCIM and tenants are off; the sample data is loaded again every day")
	if n := len(c.DemoAdminNetworks()); n == 0 {
		log.Warn("demo mode: password sign-in is off from every address (demo.admin_networks is empty); manage this server from its shell")
	} else {
		log.Info("demo mode: password sign-in works only from demo.admin_networks", "networks", n)
	}
}
