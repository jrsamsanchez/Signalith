package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A pod created with kubectl apply, at the RequestResponse level, as the
// API server writes it.
const kubePodCreated = `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse",
	"auditID": "3b8f6c1e-8f2a-4d1b-9c7e-2a5f0e6d1c34", "stage": "ResponseComplete",
	"requestURI": "/api/v1/namespaces/default/pods?fieldManager=kubectl-client-side-apply", "verb": "create",
	"user": {"username": "jane@example.com", "uid": "u-1", "groups": ["developers", "system:authenticated"],
		"extra": {"authentication.kubernetes.io/credential-id": ["X509SHA256=ab"]}},
	"sourceIPs": ["203.0.113.7", "10.0.0.2"], "userAgent": "kubectl/v1.30.2 (linux/amd64) kubernetes/3968350",
	"objectRef": {"resource": "pods", "namespace": "default", "name": "debug", "apiVersion": "v1"},
	"responseStatus": {"metadata": {}, "code": 201},
	"requestObject": {"kind": "Pod", "apiVersion": "v1",
		"metadata": {"name": "debug", "namespace": "default", "labels": {"app.kubernetes.io/name": "debug", "run": "debug"},
			"annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"spec\":{\"containers\":[{\"securityContext\":{\"privileged\":true}}]}}\n"}},
		"spec": {"hostNetwork": true, "volumes": [{"name": "root", "hostPath": {"path": "/", "type": ""}}],
			"containers": [{"name": "shell", "image": "alpine:3.20", "command": ["sh", "-c", "sleep 1d"],
				"securityContext": {"privileged": true, "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]}}}]}},
	"responseObject": {"kind": "Pod", "metadata": {"name": "debug", "uid": "p-1"}, "status": {"phase": "Pending"}},
	"requestReceivedTimestamp": "2026-10-11T09:12:31.415123Z", "stageTimestamp": "2026-10-11T09:12:31.432000Z",
	"annotations": {"authorization.k8s.io/decision": "allow",
		"authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding \"devs\" of ClusterRole \"edit\" to Group \"developers\"",
		"pod-security.kubernetes.io/enforce-policy": "privileged:latest"}}`

// An anonymous request the API server refused.
const kubeAnonymous = `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
	"auditID": "4c9f7d2f-9a3b-4e2c-8d8f-3b6a1f7e2d45", "stage": "ResponseComplete", "requestURI": "/api/v1/secrets",
	"verb": "list", "user": {"username": "system:anonymous", "groups": ["system:unauthenticated"]},
	"sourceIPs": ["198.51.100.4"], "userAgent": "curl/8.5.0",
	"objectRef": {"resource": "secrets", "apiVersion": "v1"},
	"responseStatus": {"metadata": {}, "status": "Failure", "message": "forbidden: User \"system:anonymous\" cannot list resource \"secrets\"",
		"reason": "Forbidden", "details": {"kind": "secrets"}, "code": 403},
	"requestReceivedTimestamp": "2026-10-11T10:00:00.000000Z", "stageTimestamp": "2026-10-11T10:00:00.001000Z",
	"annotations": {"authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": ""}}`

// A request without valid credentials.
const kubeUnauthenticated = `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
	"auditID": "5d0a8e3a-ab4c-4f3d-9e9a-4c7b2a8f3e56", "stage": "ResponseStarted", "requestURI": "/api",
	"verb": "get", "user": {}, "sourceIPs": ["192.0.2.10"], "userAgent": "kube-hunter",
	"responseStatus": {"metadata": {}, "status": "Failure", "message": "Unauthorized", "reason": "Unauthorized", "code": 401},
	"requestReceivedTimestamp": "2026-10-11T11:00:00.000000Z", "stageTimestamp": "2026-10-11T11:00:00.000500Z"}`

func TestKubernetesChange(t *testing.T) {
	ev := Normalize(KubernetesTag, decode(t, kubePodCreated), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": "_json", "source": "kubernetes", "vendor_product": "Kubernetes",
		"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "stage": "ResponseComplete", "verb": "create",
		"auditID": "3b8f6c1e-8f2a-4d1b-9c7e-2a5f0e6d1c34", "userAgent": "kubectl/v1.30.2 (linux/amd64) kubernetes/3968350",
		"kube_user.username": "jane@example.com", "kube_user.uid": "u-1",
		"objectRef.resource": "pods", "objectRef.namespace": "default", "objectRef.name": "debug",
		"responseStatus.code":                                   "201",
		"annotations.authorization.k8s.io/decision":             "allow",
		"annotations.pod-security.kubernetes.io/enforce-policy": "privileged:latest",
		"requestObject.kind":                                    "Pod", "requestObject.spec.hostNetwork": "true",
		"requestObject.metadata.annotations." + lastApplied: `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"securityContext":{"privileged":true}}]}}`,
		"requestObject.metadata.labels.run":                 "debug",
		"responseObject.status.phase":                       "Pending",
		"action":                                            "created", "status": "success", "change_type": "Kubernetes", "command": "create",
		"signature": "create pods", "object": "debug", "object_category": "pods", "user": "jane@example.com", "src_user": "jane@example.com",
		"src": "203.0.113.7", "user_agent": "kubectl/v1.30.2 (linux/amd64) kubernetes/3968350", "app": "Kubernetes", "result": "201",
		"@timestamp": "2026-10-11T09:12:31.415123Z",
	})
	expectLists(t, ev, map[string][]any{
		"kube_user.groups{}": {"developers", "system:authenticated"}, "sourceIPs{}": {"203.0.113.7", "10.0.0.2"},
		"requestObject.spec.containers{}.image": {"alpine:3.20"}, "requestObject.spec.containers{}.command{}": {"sh", "-c", "sleep 1d"},
		"requestObject.spec.containers{}.securityContext.privileged":         {"true"},
		"requestObject.spec.containers{}.securityContext.capabilities.add{}": {"SYS_ADMIN", "NET_ADMIN"},
		"requestObject.spec.volumes{}.hostPath.path":                         {"/"},
	})
	for _, k := range []string{"user.username", "kube_user.extra", "requestObject.metadata.labels.app.kubernetes.io/name"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("%s became a field", k)
		}
	}
	if ev.ID == "" {
		t.Error("no document ID: the same event sent twice would be stored twice")
	}
}

func TestKubernetesReadsAndRefusals(t *testing.T) {
	ev := Normalize(KubernetesTag, decode(t, kubeAnonymous), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Other", "verb": "list", "status": "failure", "result": "403", "reason": "Forbidden",
		"responseStatus.reason": "Forbidden", "responseStatus.status": "Failure", "user": "system:anonymous",
		"signature": "list secrets", "object": "secrets", "annotations.authorization.k8s.io/decision": "forbid",
	})
	expectLists(t, ev, map[string][]any{"kube_user.groups{}": {"system:unauthenticated"}})
	if _, ok := ev.Fields["annotations.authorization.k8s.io/reason"]; ok {
		t.Error("an empty annotation became a field")
	}
	ev = Normalize("anything", decode(t, kubeUnauthenticated), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "action": "failure", "status": "failure", "src": "192.0.2.10", "sourcetype": "_json",
		"stage": "ResponseStarted", "signature": "get",
	})
	if _, ok := ev.Fields["user"]; ok {
		t.Errorf("user = %v", ev.Fields["user"])
	}
}

// The webhook backend posts an EventList; an array of events or one
// event sent with the kubernetes tag is read the same way.
func TestKubernetesRecords(t *testing.T) {
	list := `{"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "metadata": {}, "items": [` + kubePodCreated + ",\n" + kubeAnonymous + `]}`
	for name, body := range map[string]string{
		"list": list, "array": "[" + kubePodCreated + "," + kubeAnonymous + `, {"kind": "Event"}, null]`,
	} {
		recs, err := KubernetesRecords([]byte(body))
		if err != nil || len(recs) != 2 {
			t.Fatalf("%s: %d records, %v", name, len(recs), err)
		}
	}
	if recs, err := KubernetesRecords([]byte(kubeAnonymous)); err != nil || len(recs) != 1 {
		t.Fatalf("one event: %d records, %v", len(recs), err)
	}
	deep := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	deepEvent := strings.Replace(kubeAnonymous, `"details": {"kind": "secrets"}`, `"details": `+strings.Repeat(`{"a": `, MaxDepth)+"1"+strings.Repeat("}", MaxDepth), 1)
	for _, bad := range []string{"", "x", `"text"`, "[" + deep + "]", deepEvent} {
		if _, err := KubernetesRecords([]byte(bad)); err == nil {
			t.Errorf("%.40q was read", bad)
		}
	}
	for _, body := range []string{list, "[" + kubePodCreated + "," + kubeAnonymous + "]"} {
		fb := &fakeBulk{}
		p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
		if _, err := p.IngestBody(context.Background(), KubernetesTag, []byte(body)); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, d := range fb.docs {
			if d.Doc["sourcetype"] == KubernetesSourcetype && d.Doc["source"] == KubernetesSource {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%d Kubernetes events, want 2", n)
		}
	}
	// A line Fluent Bit read from the audit log file is decoded, but only
	// within the depth limit.
	line := Normalize(KubernetesTag, map[string]any{"log": strings.ReplaceAll(kubeAnonymous, "\n", "")}, now)
	if line.Fields["sourcetype"] != KubernetesSourcetype || line.Fields["verb"] != "list" {
		t.Errorf("line: %v", line.Fields)
	}
	if deep := Normalize(KubernetesTag, map[string]any{"log": deepEvent}, now); deep.Fields["sourcetype"] == KubernetesSourcetype {
		t.Error("a line nested past the depth limit was read")
	}
	// An EventList over the size of one record is still read: its events
	// are the records.
	var items []string
	for i := range 700 {
		items = append(items, strings.Replace(kubePodCreated, "3b8f6c1e", fmt.Sprintf("%08x", i), 1))
	}
	big := `{"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": [` + strings.Join(items, ",") + "]}"
	if len(big) <= MaxRecordBytes {
		t.Fatalf("the list is %d bytes", len(big))
	}
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	if res, err := p.IngestBody(context.Background(), KubernetesTag, []byte(big)); err != nil || res.Indexed != 700 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, ok := kubeEventListItems([]byte(`{"kind": "EventList", "apiVersion": "v1", "items": []}`)); ok {
		t.Error("a list of other events read as audit events")
	}
}

// The Collector passes an event on as the body's text, or as a map.
func TestKubernetesFromOTLP(t *testing.T) {
	docs := otlpDocs(t, tRes{attrs: []tKV{{"host.name", "node1"}}, recs: []tRec{
		{observed: uint64(now.UnixNano()), body: strings.ReplaceAll(kubeAnonymous, "\n", "")},
		{observed: uint64(now.UnixNano()), body: `{"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": [` +
			strings.ReplaceAll(kubePodCreated+","+kubeUnauthenticated, "\n", "") + "]}"},
		{observed: uint64(now.UnixNano()), body: `{"auditID": "x", "apiVersion": "audit.k8s.io/v1"}`},
	}})
	if len(docs) != 4 {
		t.Fatalf("%d documents, want 4", len(docs))
	}
	expect(t, docs[0], map[string]any{"datamodel": "Other", "sourcetype": KubernetesSourcetype, "host": "node1",
		"@timestamp": "2026-10-11T10:00:00Z"})
	expect(t, docs[1], map[string]any{"datamodel": "Change", "sourcetype": KubernetesSourcetype})
	if docs[3]["sourcetype"] == KubernetesSourcetype {
		t.Errorf("not an event: %v", docs[3])
	}
	deep := `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "y", "verb": "get", "stage": "x", "requestObject": ` +
		strings.Repeat(`{"a": `, 1000) + "1" + strings.Repeat("}", 1000) + `}`
	if kubernetesFromOTLP(deep) != nil {
		t.Error("a 1,000-deep OTLP body was read")
	}
}

func TestKubernetesFieldsKept(t *testing.T) {
	for _, s := range []string{kubePodCreated, kubeAnonymous, kubeUnauthenticated} {
		ev := Normalize(KubernetesTag, decode(t, s), now)
		for k := range ev.Fields {
			if !KnownField(k) && !KubernetesField(k) {
				t.Errorf("field %s is neither mapped in the index template nor an event's", k)
			}
		}
	}
	// A top-level field the Event schema does not have stays in the
	// message: it could otherwise take one of Signalith's own names.
	r := decode(t, kubeAnonymous)
	r["user_name"] = "mallory"
	r["src"] = "192.0.2.99"
	ev := Normalize(KubernetesTag, r, now)
	if ev.Fields["user_name"] != nil || ev.Fields["src"] != "198.51.100.4" {
		t.Errorf("user_name = %v, src = %v", ev.Fields["user_name"], ev.Fields["src"])
	}
}

// No field a Kubernetes event keeps sits under a name the index template
// maps as a value, where OpenSearch would refuse the document: the
// Event's user object is kept as kube_user, as user is text.
func TestKubernetesFieldsUnderNoMappedValue(t *testing.T) {
	for _, s := range []string{kubePodCreated, kubeAnonymous, kubeUnauthenticated} {
		ev := Normalize(KubernetesTag, decode(t, s), now)
		for k := range ev.Fields {
			name := strings.ReplaceAll(k, "{}", "")
			for i := range len(name) {
				if name[i] == '.' {
					if typ, ok := knownFields[name[:i]]; ok && typ != "object" {
						t.Errorf("%s is under %s, mapped as %s", k, name[:i], typ)
					}
				}
			}
			if knownObjects[k] {
				t.Errorf("%s is a value where the known fields have an object", k)
			}
		}
	}
	for name, want := range map[string]string{
		"user.username": "kube_user.username", "user.groups": "kube_user.groups{}", "sourceIPs": "sourceIPs{}",
		"objectref.resource": "objectRef.resource", "apiGroup": "objectRef.apiGroup", "verb": "verb",
		"hostPath": "requestObject.spec.volumes{}.hostPath.path", "sourceIPs{}": "sourceIPs{}",
		"requestObject.spec.jobTemplate.spec.template.spec.containers{}.image": "requestObject.spec.jobTemplate.spec.template.spec.containers{}.image",
		"responseStatus.details.kind":                                          "responseStatus.details.kind",
	} {
		if got, ok := KubernetesSigmaField(name); !ok || got != want {
			t.Errorf("KubernetesSigmaField(%s) = %s, %v", name, got, ok)
		}
	}
	if f, ok := KubernetesSigmaField("CommandLine"); ok {
		t.Errorf("CommandLine is %s", f)
	}
}

// An event with another event's auditID but other content is stored as
// its own, and the same event sent twice once.
func TestKubernetesDocumentID(t *testing.T) {
	a := Normalize(KubernetesTag, decode(t, kubeAnonymous), now)
	if again := Normalize(KubernetesTag, decode(t, kubeAnonymous), now.Add(time.Hour)); again.ID != a.ID || a.ID == "" {
		t.Errorf("IDs %q and %q", a.ID, again.ID)
	}
	forged := decode(t, kubeAnonymous)
	forged["verb"] = "get"
	if Normalize(KubernetesTag, forged, now).ID == a.ID {
		t.Error("a changed copy took the event's ID")
	}
}

// However large an event's objects, it becomes a bounded number of
// fields and values, and its objects are walked a bounded number of
// steps: the counts show it, whatever the machine's speed.
func TestKubernetesHugeEventBounded(t *testing.T) {
	spec := map[string]any{}
	for i := range 20000 {
		spec[fmt.Sprintf("k%05d", i)] = i
	}
	args := make([]any, 100)
	for j := range args {
		args[j] = fmt.Sprint(j)
	}
	containers := make([]any, 2000)
	for i := range containers {
		containers[i] = map[string]any{"image": fmt.Sprintf("img%d", i), "args": args,
			"securityContext": map[string]any{"capabilities": map[string]any{"add": args}}}
	}
	spec["containers"] = containers
	ann := map[string]any{}
	for i := range 5000 {
		ann[fmt.Sprintf("example.com/a%d", i)] = "x"
	}
	groups := make([]any, 10000)
	for i := range groups {
		groups[i] = fmt.Sprintf("g%d", i)
	}
	r := decode(t, kubeAnonymous)
	r["requestObject"] = map[string]any{"kind": "Pod", "spec": spec, "metadata": map[string]any{"annotations": ann}}
	r["responseObject"] = map[string]any{"spec": spec}
	r["annotations"] = ann
	r["user"] = map[string]any{"username": "u", "groups": groups}
	w := &kubeWalk{left: kubeMaxVisits, out: map[string]any{}}
	w.walk("requestObject", r["requestObject"])
	if w.left != 0 || len(w.out) > kubeMaxVisits {
		t.Errorf("walk left %d steps, made %d names", w.left, len(w.out))
	}
	ev := ParseKubernetes(r)
	if len(ev.Fields) > maxFieldsPerEvent {
		t.Errorf("%d fields", len(ev.Fields))
	}
	for k, v := range ev.Fields {
		if l, ok := v.([]any); ok && len(l) > max(kubeMaxListValues, azureMaxListValues) {
			t.Errorf("%s has %d values", k, len(l))
		}
		if s, ok := v.(string); ok && len(s) > MaxValueLen && k != "message" {
			t.Errorf("%s is %d bytes", k, len(s))
		}
	}
	if l, _ := ev.Fields["requestObject.spec.containers{}.image"].([]any); len(l) != kubeMaxListValues {
		t.Errorf("%d images", len(l))
	}
	if b, _ := json.Marshal(ev.Document()); len(b) > 2*MaxRecordBytes {
		t.Errorf("document is %d bytes", len(b))
	}
}

// Sigma's names for an event's fields build a test event that keeps them.
func TestKubernetesRecord(t *testing.T) {
	data := map[string]string{
		"verb": "create", "objectRef.resource": "pods", "objectRef.subresource": "exec", "user.groups": "system:masters",
		"hostPath": "/etc", "capabilities": "SYS_ADMIN", "apiGroup": "apps", "responseStatus.code": "403",
		"requestObject.metadata.annotations." + lastApplied:                    `{"spec":{"hostNetwork":true}}`,
		"requestObject.spec.jobTemplate.spec.template.spec.containers{}.image": "evil:latest",
		"annotations.authorization.k8s.io/decision":                            "forbid",
	}
	ev := Normalize(KubernetesTag, KubernetesRecord("h1", now, data), now)
	expect(t, ev.Document(), map[string]any{
		"host": "h1", "verb": "create", "objectRef.resource": "pods", "objectRef.subresource": "exec", "objectRef.apiGroup": "apps",
		"responseStatus.code": "403", "status": "failure", "datamodel": "Change", "kube_user.username": "jane@example.com",
		"requestObject.metadata.annotations." + lastApplied: `{"spec":{"hostNetwork":true}}`,
		"annotations.authorization.k8s.io/decision":         "forbid",
	})
	expectLists(t, ev, map[string][]any{
		"kube_user.groups{}": {"system:masters"}, "requestObject.spec.volumes{}.hostPath.path": {"/etc"},
		"requestObject.spec.containers{}.securityContext.capabilities.add{}":   {"SYS_ADMIN"},
		"requestObject.spec.jobTemplate.spec.template.spec.containers{}.image": {"evil:latest"},
	})
	other := Normalize(KubernetesTag, KubernetesRecord("h1", now, map[string]string{"verb": "list"}), now)
	if other.ID == ev.ID {
		t.Error("two test events share a document ID")
	}
	if base := Normalize(KubernetesTag, KubernetesRecord("h1", now, nil), now); base.Model != "Other" || base.Fields["verb"] != "get" {
		t.Errorf("base event %s %v", base.Model, base.Fields["verb"])
	}
}

func TestKubernetesChangeAction(t *testing.T) {
	for verb, want := range map[string]string{
		"create": "created", "update": "modified", "patch": "modified", "delete": "deleted", "deletecollection": "deleted",
		"get": "", "list": "", "watch": "",
	} {
		if got := KubernetesChangeAction(verb); got != want {
			t.Errorf("%s: %q, want %q", verb, got, want)
		}
	}
}

// Credentials an audit event can carry are never kept, in its fields or
// its message.
func TestKubernetesCredentialsRedacted(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiJ9.c2VjcmV0LXRva2Vu.c2lnbmF0dXJl"
	for name, s := range map[string]string{
		"token review": `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "auditID": "a1",
			"stage": "ResponseComplete", "verb": "create", "requestURI": "/apis/authentication.k8s.io/v1/tokenreviews",
			"user": {"username": "system:serviceaccount:kube-system:metrics-server"}, "sourceIPs": ["10.0.0.5"],
			"objectRef": {"resource": "tokenreviews", "apiGroup": "authentication.k8s.io", "apiVersion": "v1"},
			"responseStatus": {"code": 201},
			"requestObject": {"kind": "TokenReview", "apiVersion": "authentication.k8s.io/v1", "spec": {"token": "` + jwt + `"}},
			"responseObject": {"kind": "TokenReview", "spec": {"token": "` + jwt + `"}, "status": {"authenticated": true}},
			"requestReceivedTimestamp": "2026-10-16T12:00:00.000000Z", "stageTimestamp": "2026-10-16T12:00:00.010000Z"}`,
		"token request": `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "auditID": "a2",
			"stage": "ResponseComplete", "verb": "create", "requestURI": "/api/v1/namespaces/default/serviceaccounts/app/token",
			"user": {"username": "system:node:node-1"}, "sourceIPs": ["10.0.0.6"],
			"objectRef": {"resource": "serviceaccounts", "subresource": "token", "namespace": "default", "name": "app", "apiVersion": "v1"},
			"responseStatus": {"code": 201},
			"requestObject": {"kind": "TokenRequest", "spec": {"audiences": ["api"]}},
			"responseObject": {"kind": "TokenRequest", "status": {"token": "` + jwt + `", "expirationTimestamp": "2026-10-16T13:00:00Z"}},
			"requestReceivedTimestamp": "2026-10-16T12:00:00.000000Z", "stageTimestamp": "2026-10-16T12:00:00.010000Z"}`,
		"secret": `{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "auditID": "a3",
			"stage": "ResponseComplete", "verb": "create", "requestURI": "/api/v1/namespaces/default/secrets",
			"user": {"username": "admin"}, "sourceIPs": ["10.0.0.7"],
			"objectRef": {"resource": "secrets", "namespace": "default", "name": "db", "apiVersion": "v1"},
			"responseStatus": {"code": 201},
			"requestObject": {"kind": "Secret", "metadata": {"name": "db", "annotations": {
				"kubectl.kubernetes.io/last-applied-configuration": "{\"stringData\":{\"password\":\"` + jwt + `\"}}"}},
				"data": {"password": "` + jwt + `"}, "stringData": {"user": "` + jwt + `"}},
			"responseObject": {"kind": "SecretList", "items": [{"metadata": {"name": "db"}, "data": {"password": "` + jwt + `"}}]},
			"requestReceivedTimestamp": "2026-10-16T12:00:00.000000Z", "stageTimestamp": "2026-10-16T12:00:00.010000Z"}`,
	} {
		r := decode(t, s)
		ev := Normalize(KubernetesTag, r, now)
		doc, _ := json.Marshal(ev.Document())
		if strings.Contains(string(doc), jwt) || strings.Contains(string(doc), "c2VjcmV0LXRva2Vu") {
			t.Errorf("%s: the credential was kept: %s", name, doc)
		}
		if !strings.Contains(string(doc), kubeRedacted) {
			t.Errorf("%s: nothing says a value was left out", name)
		}
		if !strings.Contains(fmt.Sprint(r), jwt) {
			t.Errorf("%s: the record passed in was changed", name)
		}
	}
}
