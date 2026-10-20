// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"errors"
	"strings"
	"testing"
)

func TestOTelGCP(t *testing.T) {
	a, err := Generate(Options{OS: "gcp", ServerURL: "https://siem:8080", Token: "t", CA: "x",
		GCPProject: "prod-logs-1", GCPSubscription: "audit-to-siem"})
	if err != nil {
		t.Fatal(err)
	}
	m := otelConfig(t, a)
	r := "receivers"
	if dig(m, r, "googlecloudpubsub/signalith", "project") != "prod-logs-1" ||
		dig(m, r, "googlecloudpubsub/signalith", "subscription") != "projects/prod-logs-1/subscriptions/audit-to-siem" ||
		dig(m, r, "googlecloudpubsub/signalith", "encoding") != "text_encoding/signalith" ||
		dig(m, "extensions", "text_encoding/signalith", "encoding") != "utf8" {
		t.Errorf("config:\n%s", a.Config)
	}
	// Only the subscription: no host logs, and no OTLP listener.
	if recv, _ := dig(m, "service", "pipelines", "logs/signalith", "receivers").([]any); len(recv) != 1 || recv[0] != "googlecloudpubsub/signalith" {
		t.Errorf("pipeline receivers = %v", recv)
	}
	if ext, _ := dig(m, "service", "extensions").([]any); len(ext) != 2 {
		t.Errorf("extensions = %v", ext)
	}
	steps := strings.Join(a.Steps, "\n")
	for _, want := range []string{
		`--log-filter='logName:"cloudaudit.googleapis.com"'`, "pubsub.googleapis.com/projects/prod-logs-1/topics/signalith-audit",
		"gcloud pubsub subscriptions create audit-to-siem --topic=signalith-audit --project=prod-logs-1",
		"--member=serviceAccount:signalith-collector@prod-logs-1.iam.gserviceaccount.com --role=roles/pubsub.subscriber",
		"GOOGLE_APPLICATION_CREDENTIALS=/etc/otelcol-contrib/signalith-gcp-key.json", "0.132 or later",
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	if strings.Contains(steps, "Enter your project") || strings.Contains(steps, "usermod") {
		t.Errorf("steps = %s", steps)
	}

	// The subscription's full name names its project.
	a, err = Generate(Options{OS: "gcp", CollectorOS: "windows", ServerURL: "https://siem:8080", Token: "t",
		GCPSubscription: "projects/prod-logs-1/subscriptions/audit-to-siem"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "subscription: projects/prod-logs-1/subscriptions/audit-to-siem") ||
		!strings.Contains(strings.Join(a.Steps, "\n"), `GOOGLE_APPLICATION_CREDENTIALS=C:\Program Files\OpenTelemetry Collector\signalith-gcp-key.json`) ||
		strings.Contains(a.Config, "windowseventlog") {
		t.Errorf("windows:\n%s\n%q", a.Config, a.Steps)
	}
	// Until the page has them, examples stand in, and a step says so.
	a, err = Generate(Options{OS: "gcp", ServerURL: "https://siem:8080", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "projects/"+gcpProjectExample+"/subscriptions/"+gcpSubscriptionExample) ||
		!strings.HasPrefix(a.Steps[0], "Enter your project ID and subscription above. Until") {
		t.Errorf("no subscription:\n%s\n%q", a.Config, a.Steps)
	}
	for _, o := range []Options{{GCPProject: "Bad_Project"}, {GCPProject: "ab"}, {GCPSubscription: "goog-sub"},
		{GCPSubscription: "projects/x"}, {GCPProject: "prod-logs-2", GCPSubscription: "projects/prod-logs-1/subscriptions/s1"},
		{GCPSubscription: "sub\nx: 1"}, {GCPSubscription: "projects/p\nx/subscriptions/s1"}} {
		o.OS, o.ServerURL, o.Token = "gcp", "https://siem:8080", "t"
		var fe *FieldError
		if _, err := Generate(o); !errors.As(err, &fe) {
			t.Errorf("%+v: %v", o, err)
		}
	}
}
