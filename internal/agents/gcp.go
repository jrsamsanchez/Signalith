package agents

import (
	"errors"
	"regexp"
	"strings"
)

// The Google Cloud option: an OpenTelemetry Collector that reads the audit
// log entries a log sink publishes to a Pub/Sub topic and sends them to
// Signalith. The Collector's googlecloudpubsub receiver pulls the topic's
// subscription and, with the text encoding extension, passes each
// message's data (one LogEntry, as JSON) on as a log record's body. The
// Collector runs anywhere it can reach Google Cloud and Signalith, with a
// service account that may pull the subscription: the one attached to a
// Compute Engine VM, or a key file it reads from its environment, so the
// configuration does not hold the key.

// Placeholders written into the config until the page has the project and
// subscription.
const (
	gcpProjectExample      = "my-project"
	gcpSubscriptionExample = "signalith-audit"
)

// gcpTopicName is the Pub/Sub topic, and the log sink, the steps have the
// admin create.
const gcpTopicName = "signalith-audit"

// gcpAccountName is the service account the steps have the admin create
// for the Collector.
const gcpAccountName = "signalith-collector"

// gcpKeyFile is the name of the service account's key file.
const gcpKeyFile = "signalith-gcp-key.json"

var (
	// A project ID: 6 to 30 lower-case letters, digits and hyphens,
	// starting with a letter.
	gcpProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	// A subscription's name: 3 to 255 letters, digits and - _ . ~ + %,
	// starting with a letter.
	gcpSubscriptionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$`)
)

// gcpSource is the subscription a Google Cloud Collector pulls, and the
// project it is in.
type gcpSource struct {
	project, subscription, placeholders string
}

// gcpOptions checks the project and subscription, or puts examples in
// their place when they are not given yet (placeholders names them). The
// subscription may be its full name (projects/p/subscriptions/s), which
// names the project too.
func gcpOptions(o Options) (gcpSource, error) {
	s := gcpSource{project: strings.TrimSpace(o.GCPProject), subscription: strings.TrimSpace(o.GCPSubscription)}
	if rest, ok := strings.CutPrefix(s.subscription, "projects/"); ok {
		p, name, ok := strings.Cut(rest, "/subscriptions/")
		if !ok {
			return s, &FieldError{Field: "gcp_subscription", Err: errors.New("that is not a subscription's name; copy it from the subscription's page in the Google Cloud console, such as " + gcpSubscriptionExample)}
		}
		if s.project != "" && s.project != p {
			return s, &FieldError{Field: "gcp_subscription", Err: errors.New("that subscription is in project " + p + ", not " + s.project)}
		}
		s.project, s.subscription = p, name
	}
	var missing []string
	if s.project == "" {
		s.project = gcpProjectExample
		missing = append(missing, "project ID")
	} else if !gcpProjectID.MatchString(s.project) {
		return s, &FieldError{Field: "gcp_project", Err: errors.New("that is not a project ID: 6 to 30 lower-case letters, digits and hyphens, starting with a letter, such as " + gcpProjectExample)}
	}
	if s.subscription == "" {
		s.subscription = gcpSubscriptionExample
		missing = append(missing, "subscription")
	} else if !gcpSubscriptionName.MatchString(s.subscription) || strings.HasPrefix(strings.ToLower(s.subscription), "goog") {
		return s, &FieldError{Field: "gcp_subscription", Err: errors.New("that is not a subscription's name: 3 to 255 letters, digits and - _ . ~ + %, starting with a letter, such as " + gcpSubscriptionExample)}
	}
	s.placeholders = strings.Join(missing, " and ")
	return s, nil
}

// extension is the text encoding extension of the Collector's config,
// which makes each message's data a log record's body as it is.
func (s gcpSource) extension() string {
	return "  text_encoding/signalith:\n    encoding: utf8\n"
}

// receiver is the googlecloudpubsub receiver of the Collector's config.
func (s gcpSource) receiver() string {
	return "  googlecloudpubsub/signalith:\n" +
		"    project: " + s.project + "\n" +
		"    subscription: projects/" + s.project + "/subscriptions/" + s.subscription + "\n" +
		"    encoding: text_encoding/signalith\n"
}

// account is the service account's email address.
func (s gcpSource) account() string {
	return gcpAccountName + "@" + s.project + ".iam.gserviceaccount.com"
}

// steps are the Google Cloud side of the setup, before the Collector's
// own. Each is a gcloud command, which Cloud Shell runs as it is.
func (s gcpSource) steps() []string {
	var out []string
	if s.placeholders != "" {
		out = append(out, "Enter your project ID and subscription above. Until you do, the configuration below and these steps have examples in their place ("+s.placeholders+").")
	}
	p := " --project=" + s.project
	return append(out,
		"In Google Cloud, open Cloud Shell (or a terminal with the gcloud CLI signed in as a project owner) and create a Pub/Sub topic for the audit logs: gcloud pubsub topics create "+gcpTopicName+p,
		"Create a log sink that sends the project's audit log entries to the topic: gcloud logging sinks create "+gcpTopicName+" pubsub.googleapis.com/projects/"+s.project+"/topics/"+gcpTopicName+p+` --log-filter='logName:"cloudaudit.googleapis.com"'`+
			". For a whole organization, run it with --organization=ORGANIZATION_ID --include-children in place of"+p+".",
		"Let the sink publish to the topic, as the writer identity it was given: gcloud pubsub topics add-iam-policy-binding "+gcpTopicName+p+" --role=roles/pubsub.publisher --member=$(gcloud logging sinks describe "+gcpTopicName+p+" --format='value(writerIdentity)')"+
			". For an organization's sink, the describe command takes --organization=ORGANIZATION_ID in place of"+p+".",
		"Create a pull subscription the Collector reads, which keeps entries for 7 days while it is away: gcloud pubsub subscriptions create "+s.subscription+" --topic="+gcpTopicName+p+" --ack-deadline=60 --message-retention-duration=7d",
		"Create a service account for the Collector and let it pull the subscription, and nothing else: gcloud iam service-accounts create "+gcpAccountName+p+
			" && gcloud pubsub subscriptions add-iam-policy-binding "+s.subscription+p+" --member=serviceAccount:"+s.account()+" --role=roles/pubsub.subscriber",
		"On a Compute Engine VM, attach that service account to the VM (with the Cloud Platform access scope) and skip the key. Elsewhere, make a key file for it, which the Collector gets in a later step, and keep it private, as it lets anyone read your audit logs: gcloud iam service-accounts keys create "+gcpKeyFile+" --iam-account="+s.account())
}
