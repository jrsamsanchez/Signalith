package ingest

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kubernetes's API server records what it is asked to do in its audit
// log: who asked (user.username, user.groups), from where (sourceIPs),
// with what (userAgent), to do what (verb) to which object (objectRef:
// resource, namespace, name, subresource), how it was answered
// (responseStatus.code), and, at the Request and RequestResponse audit
// levels, the object sent (requestObject) and returned (responseObject).
// Each is an audit.k8s.io/v1 Event, which the API server writes to a file
// (--audit-log-path) or posts to a webhook (--audit-webhook-config-file)
// as an EventList.
//
// Each event becomes an event with the Event's own field names flattened
// with dots (objectRef.resource, responseStatus.code,
// requestObject.spec.containers{}.image), as Splunk reads the JSON
// (sourcetype _json, source kubernetes, which Splunk's kube_audit macro
// searches), and a list's values by Splunk's names for them
// (sourceIPs{}). The user object is kept as kube_user.* (kube_user.username,
// kube_user.groups{}), since Signalith's user field holds text and cannot
// also hold an object. Every value is kept as text. Of the objects sent
// and returned, which can be whole manifests, only the fields rules read
// and a bounded number of others are kept as fields; all of it stays in
// the message. The CIM fields: a request to create, change or delete an
// object is a Change event, a request refused as unauthenticated (401) an
// Authentication event, and the rest (reads, watches) Other.
//
// Events come under the kubernetes tag as JSON (one Event, an array of
// them, or the EventList the webhook backend posts), by their shape under
// any tag, or through the OpenTelemetry Collector as a log record whose
// body is one (see kubernetesFromOTLP).

// KubernetesTag is the tag of Kubernetes audit events sent as JSON.
const KubernetesTag = "kubernetes"

// KubernetesSourcetype and KubernetesSource are what Splunk's own test
// data for its Kubernetes detections is stored as, and what its
// kube_audit macro searches (source="kubernetes").
const (
	KubernetesSourcetype = "_json"
	KubernetesSource     = "kubernetes"
)

// KubernetesVendor is the vendor_product of Kubernetes audit events.
const KubernetesVendor = "Kubernetes"

// KubernetesChannel names Kubernetes audit events in test events
// (sigmacheck.Case), as a Windows channel names Windows events.
const KubernetesChannel = "kubernetes"

// KubernetesService is the Sigma product of Kubernetes audit logs
// (product: kubernetes, service: audit), whose rules Signalith converts.
const KubernetesService = "kubernetes"

// Limits on what one event becomes, whatever its size: the fields its
// objects' leaves become beyond kubeFields, the nodes of requestObject
// and responseObject walked, the values kept of one list, the audit
// annotations kept, and the items of one list read on a named path.
const (
	kubeMaxLeaves      = 80
	kubeMaxVisits      = 2000
	kubeMaxListValues  = 50
	kubeMaxAnnotations = 30
	kubeMaxListItems   = 100
)

// kubeTop are an Event's top-level text fields, kept by name when set.
var kubeTop = []string{
	"kind", "apiVersion", "level", "auditID", "stage", "requestURI", "verb", "userAgent", "requestReceivedTimestamp",
	"stageTimestamp",
}

// kubeObjects are an Event's objects and lists, whose fields are kept
// each as its own field (objectRef.resource, sourceIPs{}). The objects
// sent and returned and the audit annotations are read apart.
var kubeObjects = []string{"user", "impersonatedUser", "objectRef", "responseStatus", "sourceIPs"}

// kubeStored is the name an event keeps an Event object's fields under:
// its own, but kube_user for user, as Signalith's user field holds text
// and cannot also hold an object.
func kubeStored(obj string) string {
	if obj == "user" {
		return "kube_user"
	}
	return obj
}

// kubeRaw is the Event's name of a stored object (kube_user is user).
func kubeRaw(obj string) string {
	if obj == "kube_user" {
		return "user"
	}
	return obj
}

// lastApplied is the annotation kubectl apply writes on an object it
// creates or changes: the whole object as JSON text, which Splunk's rules
// search for "privileged":true.
const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// kubeFields are the fields of an event kept by name whenever it has
// them, before the rest of its objects' fields (kubeMaxLeaves).
var kubeFields = []string{
	"kube_user.username", "kube_user.uid", "kube_user.groups", "kube_user.groups{}",
	"impersonatedUser.username", "impersonatedUser.groups{}",
	"sourceIPs", "sourceIPs{}",
	"objectRef.resource", "objectRef.namespace", "objectRef.name", "objectRef.uid", "objectRef.apiGroup",
	"objectRef.apiVersion", "objectRef.resourceVersion", "objectRef.subresource",
	"responseStatus.code", "responseStatus.status", "responseStatus.reason", "responseStatus.message",
	"annotations.authorization.k8s.io/decision", "annotations.authorization.k8s.io/reason",
}

// kubeRequestFields are the fields of the objects sent and returned that
// rules read or a search of a cluster's changes wants first, kept
// whenever an event has them, however deep (a CronJob's containers are
// eight levels down).
var kubeRequestFields = []string{
	"requestObject.kind", "requestObject.apiVersion", "requestObject.metadata.name", "requestObject.metadata.namespace",
	"requestObject.metadata.annotations." + lastApplied,
	"requestObject.message", "requestObject.reason", "requestObject.type",
	"requestObject.involvedObject.kind", "requestObject.involvedObject.name", "requestObject.involvedObject.namespace",
	"requestObject.spec.type", "requestObject.spec.schedule", "requestObject.spec.hostNetwork", "requestObject.spec.hostPID",
	"requestObject.spec.hostIPC", "requestObject.spec.serviceAccountName", "requestObject.spec.nodeName",
	"requestObject.spec.containers{}.image", "requestObject.spec.containers{}.command{}",
	"requestObject.spec.containers{}.securityContext.privileged",
	"requestObject.spec.containers{}.securityContext.allowPrivilegeEscalation",
	"requestObject.spec.containers{}.securityContext.capabilities.add{}",
	"requestObject.spec.initContainers{}.image", "requestObject.spec.volumes{}.hostPath.path",
	"requestObject.spec.template.spec.containers{}.image", "requestObject.spec.template.spec.hostNetwork",
	"requestObject.spec.jobTemplate.spec.template.spec.containers{}.image",
	"requestObject.subjects{}.kind", "requestObject.subjects{}.name", "requestObject.roleRef.kind",
	"requestObject.roleRef.name", "requestObject.rules{}.verbs{}", "requestObject.rules{}.resources{}",
	"responseObject.kind", "responseObject.metadata.name", "responseObject.metadata.namespace",
}

// kubernetesMapped are the fields the index template maps (see
// knownFields): what a Kubernetes search reads first, and the fields
// deeper than a sender's names may go.
var kubernetesMapped = append([]string{"kind", "auditID", "stage", "requestURI", "verb", "requestReceivedTimestamp"},
	append(slices.Clone(kubeFields), kubeRequestFields...)...)

// IsKubernetesRecord reports whether a decoded object is a Kubernetes
// audit Event: its kind and API version say so, and it has an ID, a verb
// and a stage.
func IsKubernetesRecord(r map[string]any) bool {
	text := func(k string) string { s, _ := r[k].(string); return s }
	return text("kind") == "Event" && strings.HasPrefix(text("apiVersion"), "audit.k8s.io/") && text("auditID") != "" &&
		text("verb") != "" && text("stage") != ""
}

// KubernetesRecords decodes Kubernetes audit Events from JSON text: one
// Event, an array of them, or an EventList as the webhook backend posts
// them. Objects that are not Events are left out; text that is none of
// these, or nests deeper than MaxDepth (each Event counted from itself),
// is an error.
func KubernetesRecords(b []byte) ([]map[string]any, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > MaxBodyBytes {
		return nil, fmt.Errorf("Kubernetes audit events must be 1 byte to %d MB of JSON", MaxBodyBytes>>20)
	}
	if b[0] != '{' && b[0] != '[' {
		return nil, errors.New("not a JSON object or array")
	}
	// An EventList's events are two levels down; an array's, one.
	d := depth(b)
	if d > MaxDepth+2 {
		return nil, fmt.Errorf("the JSON nests more than %d levels deep", MaxDepth)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var list []any
	if b[0] == '{' {
		var r map[string]any
		if err := dec.Decode(&r); err != nil {
			return nil, err
		}
		if kind, _ := r["kind"].(string); kind == "EventList" {
			list, _ = r["items"].([]any)
		} else {
			if d > MaxDepth {
				return nil, fmt.Errorf("the JSON nests more than %d levels deep", MaxDepth)
			}
			list = []any{r}
		}
	} else {
		if d > MaxDepth+1 {
			return nil, fmt.Errorf("the JSON nests more than %d levels deep", MaxDepth)
		}
		if err := dec.Decode(&list); err != nil {
			return nil, err
		}
	}
	var out []map[string]any
	for _, x := range list {
		if r, ok := x.(map[string]any); ok && IsKubernetesRecord(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// kubeEventListItems returns the events of an EventList as a JSON array,
// for IngestBody, which reads a body's records one by one; false when the
// body is not one. The EventList's own depth is checked, so the array's
// records are each checked as any other.
func kubeEventListItems(body []byte) ([]byte, bool) {
	b := bytes.TrimSpace(body)
	if len(b) == 0 || b[0] != '{' || !bytes.Contains(b, []byte(`"EventList"`)) || depth(b) > MaxDepth+2 {
		return nil, false
	}
	var l struct {
		Kind       string          `json:"kind"`
		APIVersion string          `json:"apiVersion"`
		Items      json.RawMessage `json:"items"`
	}
	if json.Unmarshal(b, &l) != nil || l.Kind != "EventList" || !strings.HasPrefix(l.APIVersion, "audit.k8s.io/") {
		return nil, false
	}
	items := bytes.TrimSpace(l.Items)
	if len(items) == 0 || items[0] != '[' {
		return nil, false
	}
	return items, true
}

// isKubernetesTag reports whether a tag is the kubernetes tag, or one
// under it (kubernetes.audit).
func isKubernetesTag(tag string) bool {
	return tag == KubernetesTag || strings.HasPrefix(tag, KubernetesTag+".")
}

// kubeLine is the Event a record under the kubernetes tag holds: the
// record itself, or the line Fluent Bit read from the audit log file
// ({"log": "<one Event>"}), decoded. The line sat inside a string, past
// the body's own depth check; KubernetesRecords checks it.
func kubeLine(r map[string]any) map[string]any {
	if IsKubernetesRecord(r) {
		return r
	}
	line, ok := r["log"].(string)
	if !ok || len(line) > MaxRecordBytes || !strings.Contains(line, `"auditID"`) {
		return r
	}
	recs, err := KubernetesRecords([]byte(line))
	if err != nil || len(recs) != 1 {
		return r
	}
	return recs[0]
}

// kubernetesFromOTLP returns the audit Events of an OTLP log record whose
// body is one, an array or an EventList: text, as the filelog receiver
// reads a line of the audit log, or a map.
func kubernetesFromOTLP(body any) []map[string]any {
	switch b := body.(type) {
	case string:
		if len(b) > MaxRecordBytes || !strings.Contains(b, `"auditID"`) || !strings.Contains(b, `audit.k8s.io/`) {
			return nil
		}
		// The text sat inside a string, past the body's own depth check;
		// KubernetesRecords checks it.
		recs, err := KubernetesRecords([]byte(b))
		if err != nil || len(recs) == 0 {
			return nil
		}
		return recs
	case map[string]any:
		if IsKubernetesRecord(b) {
			return []map[string]any{b}
		}
	}
	return nil
}

// kubeWalk flattens what an event's objects sent and returned hold, with
// a budget of nodes, so a manifest of any size costs at most
// kubeMaxVisits steps and makes at most that many names.
type kubeWalk struct {
	left int
	out  map[string]any
}

func (w *kubeWalk) walk(name string, v any) {
	if w.left <= 0 {
		return
	}
	w.left--
	switch x := v.(type) {
	case map[string]any:
		if strings.Count(name, ".")+1 >= maxFieldDepth {
			return
		}
		for _, k := range slices.Sorted(maps.Keys(x)) {
			if w.left <= 0 {
				return
			}
			if k != "" && !strings.ContainsAny(k, ".{}") {
				w.walk(name+"."+k, x[k])
			}
		}
	case []any:
		for i, e := range x {
			if w.left <= 0 || i >= kubeMaxListItems {
				return
			}
			w.walk(name+"{}", e)
		}
	default:
		kubeSet(w.out, name, v)
	}
}

// kubeSet keeps a scalar under name: a list's value when the name is a
// list's ({} in it), at most kubeMaxListValues of them.
func kubeSet(out map[string]any, name string, v any) {
	s := o365Text(v)
	if s == "" {
		return
	}
	if !strings.Contains(name, "{}") {
		out[name] = CapValue(s)
		return
	}
	if l, _ := out[name].([]any); len(l) < kubeMaxListValues {
		out[name] = append(l, CapValue(s))
	}
}

// kubePath keeps the scalars at a stored path of an event (parts of
// requestObject.spec.containers{}.image, with the annotation key whole),
// reading at most kubeMaxListItems of each list on the way.
func kubePath(name string, v any, parts []string, out map[string]any) {
	if len(parts) == 0 {
		switch v.(type) {
		case map[string]any, []any:
		default:
			kubeSet(out, name, v)
		}
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	p, list := strings.CutSuffix(parts[0], "{}")
	next := m[p]
	if !list {
		kubePath(name, next, parts[1:], out)
		return
	}
	l, _ := next.([]any)
	for i, e := range l {
		if i >= kubeMaxListItems {
			break
		}
		if len(parts) == 1 {
			kubeSet(out, name, e)
		} else {
			kubePath(name, e, parts[1:], out)
		}
	}
}

// kubeSplit splits a stored name into the parts of its path in the Event:
// by dots, but an annotation's key (after annotations.) whole, and
// kube_user as user.
func kubeSplit(name string) []string {
	var parts []string
	rest := name
	for rest != "" {
		p, after, more := strings.Cut(rest, ".")
		parts = append(parts, p)
		if !more {
			break
		}
		if p == "annotations" {
			parts = append(parts, after)
			break
		}
		rest = after
	}
	if len(parts) > 0 {
		parts[0] = kubeRaw(parts[0])
	}
	return parts
}

// ParseKubernetes maps a Kubernetes audit Event (decoded JSON) onto an
// event.
func ParseKubernetes(r map[string]any) Event {
	if !IsKubernetesRecord(r) {
		return parseGeneric(r)
	}
	r = kubeRedact(r)
	flat := map[string]any{}
	for _, k := range kubeTop {
		if s := o365Text(r[k]); s != "" {
			flat[k] = CapValue(s)
		}
	}
	for _, k := range kubeObjects {
		if v, ok := r[k]; ok {
			flattenO365(kubeStored(k), v, flat)
		}
	}
	// The audit annotations, by their keys (authorization.k8s.io/decision),
	// as many as kubeMaxAnnotations.
	if ann, ok := r["annotations"].(map[string]any); ok {
		n := 0
		for _, k := range slices.Sorted(maps.Keys(ann)) {
			name := "annotations." + k
			if n >= kubeMaxAnnotations {
				break
			}
			if s := o365Text(ann[k]); s != "" && validFieldName(name) {
				flat[name] = CapValue(s)
				n++
			}
		}
	}
	// What was sent and returned: some nodes of each, then the fields
	// rules read, however deep.
	for _, k := range []string{"requestObject", "responseObject"} {
		if v, ok := r[k].(map[string]any); ok {
			w := &kubeWalk{left: kubeMaxVisits, out: flat}
			w.walk(k, v)
		}
	}
	for _, k := range kubeRequestFields {
		delete(flat, k)
		kubePath(k, r, kubeSplit(k), flat)
	}
	f := map[string]any{"sourcetype": KubernetesSourcetype, "source": KubernetesSource, "vendor_product": KubernetesVendor}
	// The named fields, then the rest in order, as far as kubeMaxLeaves.
	// No value takes the name of an object the known fields make
	// (requestObject.spec), or a name under a known value.
	leaves := 0
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		known := slices.Contains(kubernetesMapped, k)
		switch {
		case knownObjects[k] || !known && (!validFieldName(k) || knownPrefix(strings.Split(k, "."))):
		case known || slices.Contains(kubeTop, k):
			f[k] = flat[k]
		case leaves < kubeMaxLeaves:
			f[k] = flat[k]
			leaves++
		}
	}
	raw, rawErr := json.Marshal(r)
	if rawErr == nil {
		f["message"] = truncateUTF8(string(raw), MaxRecordBytes)
	}
	set := func(k, v string) {
		if v != "" {
			f[k] = CapValue(v)
		}
	}
	// The machine that sent the event, when it says (the API server's
	// webhook names none).
	if h, ok := r["hostname"].(string); ok {
		set("host", h)
	}
	user, _ := r["user"].(map[string]any)
	ref, _ := r["objectRef"].(map[string]any)
	status, _ := r["responseStatus"].(map[string]any)
	verb := o365Text(r["verb"])
	resource := o365Text(ref["resource"])
	code := o365Text(status["code"])
	set("id", o365Text(r["auditID"]))
	set("user", o365Text(user["username"]))
	set("src_user", o365Text(user["username"]))
	if ips, ok := r["sourceIPs"].([]any); ok && len(ips) > 0 {
		set("src", o365Address(o365Text(ips[0])))
	}
	set("user_agent", o365Text(r["userAgent"]))
	set("http_user_agent", o365Text(r["userAgent"]))
	set("app", KubernetesVendor)
	set("command", verb)
	what := resource
	if sub := o365Text(ref["subresource"]); sub != "" && what != "" {
		what += "/" + sub
	}
	set("signature", strings.TrimSpace(verb+" "+what))
	set("object", cmp.Or(o365Text(ref["name"]), resource))
	set("object_category", resource)
	set("object_id", o365Text(ref["uid"]))
	set("object_path", o365Text(r["requestURI"]))
	set("reason", cmp.Or(o365Text(status["reason"]), o365Text(status["message"])))
	set("result", code)
	if n, err := strconv.Atoi(code); err == nil {
		if n < 400 {
			f["status"] = "success"
		} else {
			f["status"] = "failure"
		}
	}

	ev := Event{Fields: f, Model: "Other"}
	for _, k := range []string{"requestReceivedTimestamp", "stageTimestamp"} {
		if t, err := time.Parse(time.RFC3339Nano, o365Text(r[k])); err == nil {
			ev.Time = t.UTC()
			break
		}
	}
	// An event read twice (a webhook batch sent again) is stored once. The
	// ID covers the whole event, not just its auditID, which each stage of
	// a request shares, so a copy sent with a real event's auditID cannot
	// take its place.
	if rawErr == nil {
		ev.ID = sensorDocID("kubernetes", o365Text(r["auditID"])+"\n"+string(raw))
	}
	switch {
	case KubernetesChangeAction(verb) != "":
		ev.Model = "Change"
		f["action"] = KubernetesChangeAction(verb)
		set("change_type", KubernetesVendor)
	case code == "401":
		// A request without valid credentials.
		ev.Model = "Authentication"
		f["action"] = "failure"
	}
	return ev
}

// KubernetesChangeAction is what a request with a verb does to an
// object: created (create), deleted (delete, deletecollection) or
// modified (update, patch); "" for a verb that changes nothing (get,
// list, watch).
func KubernetesChangeAction(verb string) string {
	switch strings.ToLower(verb) {
	case "create":
		return "created"
	case "delete", "deletecollection":
		return "deleted"
	case "update", "patch":
		return "modified"
	}
	return ""
}

// kubeSchema are the fields of an Event that Sigma's and Splunk's rules
// may name, by the stored names, which a rule may also write in lower
// case (objectref.resource).
var kubeSchema = func() map[string]string {
	m := map[string]string{}
	for _, k := range kubernetesMapped {
		m[strings.ToLower(k)] = k
	}
	return m
}()

// kubeSigmaNames are the fields SigmaHQ's Kubernetes rules name that are
// not an Event's own names, and the Event's field each means: the API
// group of the object (only objectRef has one), and a pod's hostPath
// volumes and its containers' added Linux capabilities.
var kubeSigmaNames = map[string]string{
	"apigroup":     "objectRef.apiGroup",
	"hostpath":     "requestObject.spec.volumes{}.hostPath.path",
	"capabilities": "requestObject.spec.containers{}.securityContext.capabilities.add{}",
}

// KubernetesField reports whether a Kubernetes event keeps a field of an
// Event by its stored name: a top-level field (verb), or one under the
// Event's objects (objectRef.resource, kube_user.groups{},
// annotations.authorization.k8s.io/decision, requestObject.spec.type).
func KubernetesField(name string) bool {
	if slices.Contains(kubeTop, name) || slices.Contains(kubernetesMapped, name) {
		return true
	}
	if !validFieldName(name) {
		return false
	}
	for _, obj := range append(slices.Clone(kubeObjects), "annotations", "requestObject", "responseObject") {
		obj = kubeStored(obj)
		if strings.HasPrefix(name, obj+".") || strings.HasPrefix(name, obj+"{}") || name == obj {
			return true
		}
	}
	return false
}

// KubernetesSigmaField returns the field a Kubernetes event keeps for a
// field of a Sigma rule of product kubernetes, or false when it keeps
// none. Sigma names an Event's fields as Kubernetes does (user.username,
// objectRef.resource), and a list's without its {} (sourceIPs,
// user.groups), in any case.
func KubernetesSigmaField(name string) (string, bool) {
	if f, ok := kubeSigmaNames[strings.ToLower(name)]; ok {
		return f, true
	}
	if rest, ok := strings.CutPrefix(name, "user."); ok {
		name = "kube_user." + rest
	}
	// A list's values (sourceIPs{}) before the list's JSON text.
	if f, ok := kubeSchema[strings.ToLower(name)+"{}"]; ok && !strings.HasSuffix(name, "{}") {
		return f, true
	}
	if f, ok := kubeSchema[strings.ToLower(name)]; ok {
		return f, true
	}
	if KubernetesField(name) {
		return name, true
	}
	return "", false
}

// KubernetesRecord is a Kubernetes audit Event with the fields data
// names, by a rule's names for them (verb, objectRef.resource,
// user.groups) or the stored ones (kube_user.groups{}), for test events
// (Normalize with KubernetesTag), as host sent it: unless data says
// otherwise, a developer reading a ConfigMap with kubectl, which no rule
// is about.
func KubernetesRecord(host string, t time.Time, data map[string]string) map[string]any {
	at := t.UTC().Format("2006-01-02T15:04:05.000000Z")
	r := map[string]any{
		"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/app/configmaps/settings", "verb": "get",
		"user": map[string]any{
			"username": "jane@example.com", "uid": "5c1b8f0e-2d43-4a8e-9a57-3b4f0d6c2e19",
			"groups": []any{"developers", "system:authenticated"},
		},
		"sourceIPs": []any{"203.0.113.7"}, "userAgent": "kubectl/v1.30.2 (linux/amd64) kubernetes/3968350",
		"objectRef": map[string]any{
			"resource": "configmaps", "namespace": "app", "name": "settings", "apiVersion": "v1",
		},
		"responseStatus":           map[string]any{"metadata": map[string]any{}, "code": json.Number("200")},
		"requestReceivedTimestamp": at, "stageTimestamp": at,
		"annotations": map[string]any{
			"authorization.k8s.io/decision": "allow",
			"authorization.k8s.io/reason":   `RBAC: allowed by RoleBinding "developers/app" of Role "reader" to Group "developers"`,
		},
		"hostname": host,
	}
	reset := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		f, ok := KubernetesSigmaField(k)
		if !ok {
			continue
		}
		v := data[k]
		var val any = v
		switch {
		case f == "responseStatus.code":
			if _, err := strconv.Atoi(v); err == nil {
				val = json.Number(v)
			}
		case strings.HasPrefix(f, "requestObject.") && (v == "true" || v == "false"):
			val = v == "true"
		}
		kubePut(r, kubeSplit(f), val, reset)
	}
	// Each test event its own auditID, as the same event is stored once.
	h := sha256.New()
	fmt.Fprintln(h, host, t.UnixNano())
	for _, k := range slices.Sorted(maps.Keys(data)) {
		fmt.Fprintln(h, k, data[k])
	}
	sum := hex.EncodeToString(h.Sum(nil))
	r["auditID"] = sum[:8] + "-" + sum[8:12] + "-" + sum[12:16] + "-" + sum[16:20] + "-" + sum[20:32]
	return r
}

// kubePut sets the field of a test event at a path's parts, making the
// objects on the way, as gcpPut does. A list named first here
// (user.groups) is replaced, not added to, so a rule's value is the
// list's only one.
func kubePut(r map[string]any, parts []string, v any, reset map[string]bool) {
	m := r
	path := ""
	for i, p := range parts {
		name, list := strings.CutSuffix(p, "{}")
		path += "." + name
		last := i == len(parts)-1
		if list {
			l, _ := m[name].([]any)
			if !reset[path] {
				l, reset[path] = nil, true
			}
			if last {
				m[name] = append(l, v)
				return
			}
			if len(l) == 0 {
				l = []any{map[string]any{}}
			}
			next, ok := l[0].(map[string]any)
			if !ok {
				next = map[string]any{}
				l[0] = next
			}
			m[name] = l
			m = next
			continue
		}
		if last {
			m[name] = v
			return
		}
		next, ok := m[name].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[name] = next
		}
		m = next
	}
}
