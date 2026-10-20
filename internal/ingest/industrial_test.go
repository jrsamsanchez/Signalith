// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

func TestZeekModbus(t *testing.T) {
	d := zeekDocs(t, "modbus")
	expect(t, d[0], map[string]any{
		"datamodel": "Industrial", "app": "modbus", "ot_function": "READ_HOLDING_REGISTERS", "category": "read",
		"type": "request", "ot_unit": "1", "src": "192.168.50.11", "dest": "192.168.50.41", "dest_port": int64(502),
		"direction": "internal", "session_id": "CmbRead1aBcDeFgHi", "signature": "MODBUS READ_HOLDING_REGISTERS",
		"reason": nil, "zeek_func": "READ_HOLDING_REGISTERS", "zeek_tid": int64(17),
	})
	// Zeek before 7.0 has no pdu_type or unit.
	expect(t, d[1], map[string]any{"ot_function": "WRITE_SINGLE_REGISTER", "category": "write", "type": nil, "ot_unit": nil})
	expect(t, d[2], map[string]any{"category": "read", "type": "response", "reason": "ILLEGAL_DATA_ADDRESS", "ot_unit": "3"})
}

func TestZeekDNP3(t *testing.T) {
	d := zeekDocs(t, "dnp3")
	expect(t, d[0], map[string]any{"datamodel": "Industrial", "app": "dnp3", "ot_function": "READ", "category": "read",
		"type": "request", "dest_port": int64(20000), "zeek_fc_reply": "RESPONSE"})
	expect(t, d[1], map[string]any{"ot_function": "COLD_RESTART", "category": "control", "src": "203.0.113.77", "direction": "inbound"})
}

func TestZeekS7comm(t *testing.T) {
	d := zeekDocs(t, "s7comm")
	expect(t, d[0], map[string]any{"datamodel": "Industrial", "app": "s7comm", "ot_function": "PLC_STOP", "category": "control",
		"signature_id": "0x29", "type": "request", "src": "192.168.70.9", "dest": "192.168.70.30", "reason": nil})
	// No id.*: a response's sender is the controller, which is dest.
	expect(t, d[1], map[string]any{"type": "response", "src": "192.168.70.9", "src_port": int64(49200),
		"dest": "192.168.70.30", "dest_port": int64(102), "reason": "0x04", "direction": "internal"})
}

func TestZeekCIP(t *testing.T) {
	d := zeekDocs(t, "cip")
	expect(t, d[0], map[string]any{"datamodel": "Industrial", "app": "cip", "ot_function": "SET_ATTRIBUTE_SINGLE",
		"category": "write", "signature_id": "0x10", "object": "TCP/IP Interface", "type": "request"})
	expect(t, d[1], map[string]any{"type": "response", "reason": nil})
	id := zeekDocs(t, "cip_identity")[0]
	expect(t, id, map[string]any{"datamodel": "Industrial", "app": "cip", "ot_function": "LIST_IDENTITY",
		"category": "discovery", "product": "1756-L83E/B", "zeek_vendor_name": "Rockwell Automation/Allen-Bradley"})
}

func TestZeekBACnet(t *testing.T) {
	d := zeekDocs(t, "bacnet")
	expect(t, d[0], map[string]any{"datamodel": "Industrial", "app": "bacnet", "ot_function": "WHO_IS",
		"category": "discovery", "type": "request", "reason": nil})
	expect(t, d[1], map[string]any{"ot_function": "REINITIALIZE_DEVICE", "category": "control"})
}

func TestZeekICSNPPMore(t *testing.T) {
	dc := zeekDocs(t, "bacnet_device_control")[0]
	expect(t, dc, map[string]any{"datamodel": "Industrial", "ot_function": "DEVICE_COMMUNICATION_CONTROL", "category": "control",
		"zeek_device_state": "disable", "zeek_password": nil})
	if strings.Contains(dc["message"].(string), "Sup3rSecret") {
		t.Error("the device password was stored")
	}
	for _, k := range []string{"user_password", "Passwd", "client_secret", "identity.password"} {
		r := map[string]any{"ts": 1.0, "uid": "C1", k: "Sup3rSecret", "keep": "x"}
		ev := ParseZeek("opcua_binary_activate_session", r, "")
		if strings.Contains(ev.Fields["message"].(string), "Sup3rSecret") || ev.Fields["zeek_keep"] != "x" {
			t.Errorf("%s: %v", k, ev.Fields)
		}
	}
	md := zeekDocs(t, "modbus_detailed")[0]
	expect(t, md, map[string]any{"ot_function": "DIAGNOSTICS", "category": "diagnostic", "type": "request", "ot_unit": "1",
		"object": "FORCE_LISTEN_ONLY_MODE", "reason": nil, "zeek_request_subfunction_code": "FORCE_LISTEN_ONLY_MODE"})
}

func TestSuricataIndustrial(t *testing.T) {
	var docs []map[string]any
	for _, l := range sensorLines(t, "suricata", "industrial.json") {
		ev := Normalize("suricata.eve", map[string]any{"log": l, "hostname": "nsm-01"}, now)
		docs = append(docs, ev.Document())
	}
	expect(t, docs[0], map[string]any{"datamodel": "Industrial", "app": "modbus", "ot_function": "WRITE_MULTIPLE_REGISTERS",
		"signature_id": "16", "category": "write", "type": "request", "ot_unit": "1", "object": "40",
		"reason": "IllegalDataAddress", "session_id": "1111", "transport": "tcp", "sourcetype": "suricata:modbus"})
	expect(t, docs[1], map[string]any{"datamodel": "Industrial", "app": "dnp3", "ot_function": "DIRECT_OPERATE",
		"category": "control", "type": "request", "ot_unit": "10"})
	expect(t, docs[2], map[string]any{"datamodel": "Industrial", "app": "enip", "ot_function": "LIST_IDENTITY",
		"category": "discovery", "reason": nil})
	for _, d := range docs {
		if d["suricata_detail"] == nil {
			t.Errorf("%v: no suricata_detail", d["app"])
		}
	}
}

func TestOTCategory(t *testing.T) {
	for name, want := range map[string]string{
		"READ_WRITE_MULTIPLE_REGISTERS": "write", "UNSOLICITED_RESPONSE": "other", "DISABLE_UNSOLICITED": "control",
		"PLC_CONTROL": "control", "REQUEST_DOWNLOAD": "program", "PROGRAM_UMAS": "program", "DIAGNOSTICS": "diagnostic",
		"REPORT_SLAVE_ID": "discovery", "GET_ATTRIBUTE_ALL": "read", "READ_VAR": "read", "WRITE_VAR": "write",
		"FORWARD_OPEN": "other", "": "other", "THREAD": "other", "I_AM": "discovery", "WARM_RESTART": "control",
	} {
		if got := otCategory(name); got != want {
			t.Errorf("otCategory(%q) = %q, want %q", name, got, want)
		}
	}
	for in, want := range map[string]string{
		"PLC Stop": "PLC_STOP", "ListIdentity": "LIST_IDENTITY", "who-is": "WHO_IS", "Get_Attribute_Single": "GET_ATTRIBUTE_SINGLE",
		"READ_COILS": "READ_COILS", "  ": "", "42": "", "Read  Var!": "READ_VAR",
	} {
		if got := otName(in); got != want {
			t.Errorf("otName(%q) = %q, want %q", in, got, want)
		}
	}
	if otFunctionName("modbus", "0x83") != "READ_HOLDING_REGISTERS" || otFunctionName("dnp3", "18") != "STOP_APPL" || otFunctionName("bacnet", "1") != "" ||
		otFunctionName("modbus", "08") != "DIAGNOSTICS" || otFunctionName("s7comm", "0x1A") != "REQUEST_DOWNLOAD" || otFunctionName("dnp3", "-1") != "" {
		t.Error("otFunctionName")
	}
}

func TestIndustrialFieldsAreInTheModel(t *testing.T) {
	m, ok := datamodel.Get(IndustrialModel)
	if !ok {
		t.Fatal("no Industrial model")
	}
	in := map[string]bool{}
	for _, f := range m.Fields {
		in[f.Name] = true
	}
	for _, k := range []string{"app", "ot_function", "ot_unit", "signature_id", "category", "type", "object", "reason", "product",
		"src", "src_port", "dest", "dest_port", "transport", "direction", "session_id", "community_id"} {
		if !in[k] {
			t.Errorf("Industrial has no %s", k)
		}
		if !KnownField(k) {
			t.Errorf("%s is not a known field", k)
		}
	}
}
