// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package summary keeps summary indexes: per data model and 5-minute
// slot, how many events had each combination of the model's main fields
// (its dimensions), with sums of a few numeric fields. Searches that only
// count or sum by those fields read the summaries for whole slots and raw
// events for the rest, so dashboards and long stats stay fast as data
// grows (Splunk ES calls this data model acceleration).
package summary

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// Slot is the length of one summary row's time bucket.
const Slot = 5 * time.Minute

// Field names of a summary row. Every other field of a row is a
// dimension or a measure under the event field's own name, so one search
// can read events and summary rows together.
const (
	// CountField holds how many events a row stands for. An event has
	// no such field (the name is reserved), so sum(CountField) with
	// missing 1 counts events and rows alike.
	CountField = "signalith_count"
	// ModelField names the data model a row summarizes; events never
	// have it.
	ModelField = "signalith_summary"
	// GenField is the build that wrote the row.
	GenField = "signalith_summary_gen"
)

// commonDims are the dimensions of every model.
var commonDims = []string{"host", "sourcetype", "source", "vendor_product", "signature_id", "signature", datamodel.SampleField}

// modelDims are each model's own dimensions: the fields its dashboards
// and detections count by, not the ones unique to almost every event
// (process IDs, paths, hashes, URLs), which would make a row per event.
var modelDims = map[string][]string{
	"Authentication":      {"action", "app", "user", "src_user", "user_domain", "src", "dest", "authentication_method", "logon_type", "reason", "dest_port", "direction"},
	"Endpoint":            {"action", "user", "dest", "process_name", "parent_process_name", "process_integrity_level", "original_file_name"},
	"Network_Traffic":     {"action", "src", "dest", "dest_port", "transport", "app", "direction", "conn_state", "user"},
	"Change":              {"action", "object_category", "change_type", "user", "dest", "status", "object", "vendor_account"},
	"Malware":             {"type", "action", "category", "severity", "dest", "user", "threat_id", "file_name", "detection_source"},
	"Filesystem":          {"action", "user", "dest", "process_name", "file_name", "share_name"},
	"Registry":            {"action", "user", "dest", "process_name", "registry_value_name"},
	"Network_Resolution":  {"query", "query_type", "reply_code", "src", "dest", "transport"},
	"Intrusion_Detection": {"action", "ids_type", "category", "severity", "src", "dest", "dest_port", "transport", "app", "direction", "mitre"},
	"Web":                 {"http_method", "status", "url_domain", "src", "dest", "dest_port", "user", "app", "direction"},
	"Certificates":        {"ssl_version", "ssl_server_name", "ssl_issuer_common_name", "ssl_validation_status", "ssl_self_signed", "ja3", "ja4", "src", "dest", "dest_port"},
	"File_Transfers":      {"app", "mime_type", "src", "dest", "direction", "file_name"},
	"Industrial":          {"app", "ot_function", "category", "type", "src", "dest", "dest_port", "direction"},
	"Image_Load":          {"loaded_file_name", "signed", "signature_status", "process_name", "user", "dest"},
	"Script":              {"user", "dest"},
	"Inventory":           {"inventory_type", "action", "dest", "os", "name", "vendor", "status"},
	"Configuration_Check": {"dest", "check_id", "result", "severity", "benchmark", "os"},
	"Alerts":              {"app", "severity", "type", "dest", "src", "user"},
	"Vulnerabilities":     {"category", "dest", "severity", "cve", "known_exploited", "product"},
	"Risk":                {"risk_object", "risk_object_type", "risk_priority", "detection_id", "mitre_tactic"},
	"Other":               {"app"},
}

// modelMeasures are the numeric fields a row sums, so sum(bytes) by src
// reads summaries too.
var modelMeasures = map[string][]string{
	"Network_Traffic": {"bytes", "bytes_in", "bytes_out", "packets_in", "packets_out"},
	"Web":             {"bytes_in", "bytes_out"},
	"File_Transfers":  {"file_size"},
	"Risk":            {"risk_score"},
}

// Dims returns a model's dimensions, the common ones first; nil for a
// model that is not summarized.
func Dims(model string) []string {
	own, ok := modelDims[model]
	if !ok {
		return nil
	}
	out := slices.Clone(commonDims)
	for _, d := range own {
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// Measures returns the fields a model's rows sum.
func Measures(model string) []string { return modelMeasures[model] }

// Models lists the summarized data models in datamodel.Models order.
func Models() []string {
	var out []string
	for _, m := range datamodel.Models {
		if _, ok := modelDims[m.Name]; ok {
			out = append(out, m.Name)
		}
	}
	return out
}

// IsDim reports whether field is one of model's dimensions. datamodel
// is one for every model: a row is of exactly one.
func IsDim(model, field string) bool {
	return field == "datamodel" || slices.Contains(Dims(model), field)
}

// IsMeasure reports whether model's rows sum field.
func IsMeasure(model, field string) bool { return slices.Contains(modelMeasures[model], field) }

// layout is a fingerprint of a model's dimensions and measures: when
// they change, the model's summaries are built again from the start.
func layout(model string) string {
	h := sha256.Sum256([]byte(strings.Join(Dims(model), ",") + "|" + strings.Join(Measures(model), ",")))
	return hex.EncodeToString(h[:8])
}
