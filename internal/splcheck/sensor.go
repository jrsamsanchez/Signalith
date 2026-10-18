package splcheck

import (
	"regexp"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// Network rules (security_content's detections/network) read the
// network data models from any source: connections (Network_Traffic)
// and DNS lookups (Network_Resolution), which a network sensor's Zeek
// logs fill. Their nodes are the sensor nodes below; their test events
// are Zeek log lines. Network rules over web requests use the Web node,
// as the web rules do (web server access log lines for test events).

// The sensor nodes.
const (
	SensorTrafficNode = "Sensor_Traffic"
	SensorDNSNode     = "DNS"
)

// ParseOptions changes how Parse reads a rule.
type ParseOptions struct {
	// Network reads a tstats search over Network_Traffic or
	// Network_Resolution as one over a sensor node.
	Network bool
	// Lookups are the tables a lookup stage may read, by their names in
	// security_content, and LookupErrors why others cannot be read.
	Lookups      map[string]*Lookup
	LookupErrors map[string]error
}

// IsSensorNode reports whether a node is a sensor node.
func IsSensorNode(node string) bool {
	_, ok := sensorModels[node]
	return ok
}

// sensorModels are the sensor nodes' data models.
var sensorModels = map[string]string{
	SensorTrafficNode: "Network_Traffic", SensorDNSNode: "Network_Resolution",
}

// nodePrefixes are the field prefixes of nodes not named as their prefix:
// a sensor connection's fields are All_Traffic's.
var nodePrefixes = map[string]string{SensorTrafficNode: "All_Traffic"}

// nodePrefix is the prefix of a node's fields in a where clause.
func nodePrefix(node string) string {
	if p, ok := nodePrefixes[node]; ok {
		return p
	}
	return node
}

// tstatsNetRe is a tstats search over a network data model, with or
// without its node (datamodel=Network_Traffic.All_Traffic, or
// datamodel=Network_Traffic and All_Traffic.dest_port in the where
// clause).
var tstatsNetRe = regexp.MustCompile(`(?is)^\|\s*tstats\s+(.*?)\s*\bfrom\s+datamodel\s*=\s*(Network_Traffic|Network_Resolution)(?:\.(All_Traffic|DNS))?\s+where\s+(.*?)\s+by\s+([^|]*)$`)

// sensorNode returns the sensor node of a tstats search over a network
// data model, with the parts tstatsRe returns.
func sensorNode(first string) (node string, m []string, ok bool) {
	n := tstatsNetRe.FindStringSubmatch(first)
	if n == nil {
		return "", nil, false
	}
	for node, model := range sensorModels {
		if strings.EqualFold(model, n[2]) {
			return node, []string{n[0], n[1], n[2], node, n[4], n[5]}, true
		}
	}
	return "", nil, false
}

func init() {
	// The CIM fields a sensor's events carry, as Signalith stores them.
	Nodes[SensorTrafficNode] = []string{
		"action", "app", "bytes", "bytes_in", "bytes_out", "dest", "dest_ip", "dest_port", "direction",
		"duration", "packets_in", "packets_out", "src", "src_ip", "src_port", "transport",
	}
	Nodes[SensorDNSNode] = []string{"query", "answer", "record_type", "reply_code", "reply_code_id", "src", "dest", "transport"}
	// A connection's addresses are dest and src; a lookup's record type
	// is query_type and its resolver dest_ip.
	NodeRenames[SensorTrafficNode] = map[string]string{"dest_ip": "dest", "src_ip": "src"}
	NodeRenames[SensorDNSNode] = map[string]string{"record_type": "query_type", "dest": "dest_ip"}
	for node, model := range sensorModels {
		NodeModel[node] = model
		// A sensor's events have no event code.
		NodeEvents[node] = []string{""}
	}
}

// sensorRecords turns a field-level event into the Zeek log line that
// carries it: conn.log for a connection, dns.log for a lookup.
func sensorRecords(node string, ev map[string]string) []sigmacheck.Case {
	z := map[string]string{"id.orig_h": "192.0.2.10", "id.orig_p": "50123", "id.resp_h": "93.184.216.34"}
	set := func(k, v string) {
		if v != "" {
			z[k] = v
		}
	}
	set("id.orig_h", ev["src"])
	set("id.orig_p", ev["src_port"])
	set("id.resp_h", ev["dest"])
	set("id.resp_p", ev["dest_port"])
	var log string
	switch node {
	case SensorTrafficNode:
		log = "conn"
		z["proto"], z["conn_state"], z["id.resp_p"] = "tcp", "SF", "443"
		set("id.resp_p", ev["dest_port"])
		set("proto", ev["transport"])
		set("service", ev["app"])
		set("orig_bytes", ev["bytes_out"])
		set("resp_bytes", ev["bytes_in"])
		set("orig_pkts", ev["packets_out"])
		set("resp_pkts", ev["packets_in"])
		set("duration", ev["duration"])
		if ev["action"] == "failed" {
			z["conn_state"] = "S0"
		}
	case SensorDNSNode:
		log = "dns"
		z["proto"], z["id.resp_p"], z["query"], z["qtype_name"], z["rcode"], z["rcode_name"] = "udp", "53", "updates.example.com", "A", "0", "NOERROR"
		set("id.resp_h", ev["dest_ip"])
		set("proto", ev["transport"])
		set("query", ev["query"])
		set("qtype_name", ev["query_type"])
		set("answers", ev["answer"])
		set("rcode", ev["reply_code_id"])
		if rc := ev["reply_code"]; rc != "" {
			z["rcode_name"] = strings.ToUpper(rc)
		}
	default:
		return nil
	}
	return []sigmacheck.Case{{Channel: sigmacheck.ZeekChannelPrefix + log, Data: z}}
}
