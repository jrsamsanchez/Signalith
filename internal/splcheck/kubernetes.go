package splcheck

import (
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// KubernetesNode is the node of Kubernetes audit events (the kube_audit
// macro). A search names no event code. Its fields are the Event's own
// as Splunk reads its JSON (verb, objectRef.resource, user.username,
// sourceIPs{}, requestObject.spec.type), which Signalith keeps by the
// same names but the user object's, kept as kube_user (kube_user.username),
// and the CIM fields Signalith gives each event.
const KubernetesNode = "Kubernetes"

// kubeSource is the macro of Kubernetes audit events.
const kubeSource = "kube_audit"

// kubeCIM are the CIM fields of a Kubernetes event, with the Signalith
// field each is stored as.
var kubeCIM = map[string]string{
	"action": "action", "status": "status", "result": "result", "user": "user", "src_user": "src_user", "src": "src",
	"src_ip": "src", "signature": "signature", "command": "command", "app": "app", "user_agent": "user_agent",
	"http_user_agent": "http_user_agent", "reason": "reason", "object": "object", "object_category": "object_category",
	"object_id": "object_id", "object_path": "object_path", "change_type": "change_type",
	"vendor_product": "vendor_product", "sourcetype": "sourcetype", "source": "source",
}

// kubeField is the stored field of a Kubernetes search's field: the
// Event's user object is kube_user.
func kubeField(name string) (string, bool) {
	if f, ok := kubeCIM[name]; ok {
		return f, true
	}
	if rest, ok := strings.CutPrefix(name, "user."); ok {
		name = "kube_user." + rest
	}
	return name, ingest.KubernetesField(name)
}

// kubeRecord turns a field-level event into the Kubernetes audit Event
// that carries it: CIM fields back to the Event's fields they come from.
func kubeRecord(ev map[string]string) sigmacheck.Case {
	data := map[string]string{}
	set := func(k, v string) {
		if v != "" && data[k] == "" {
			data[k] = v
		}
	}
	for k, v := range ev {
		if _, cim := kubeCIM[k]; !cim && ingest.KubernetesField(k) {
			data[k] = v
		}
	}
	set("kube_user.username", ev["user"])
	set("kube_user.username", ev["src_user"])
	set("sourceIPs{}", ev["src"])
	set("userAgent", ev["user_agent"])
	set("userAgent", ev["http_user_agent"])
	set("verb", ev["command"])
	set("objectRef.resource", ev["object_category"])
	set("objectRef.name", ev["object"])
	set("objectRef.uid", ev["object_id"])
	set("requestURI", ev["object_path"])
	set("responseStatus.code", ev["result"])
	set("responseStatus.reason", ev["reason"])
	switch strings.ToLower(ev["status"]) {
	case "success":
		set("responseStatus.code", "200")
	case "failure":
		set("responseStatus.code", "403")
	}
	return sigmacheck.Case{Channel: sigmacheck.KubernetesChannel, EventID: "audit", Data: data}
}
