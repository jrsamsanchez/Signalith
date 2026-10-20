// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strconv"
	"strings"
	"unicode"
)

// Industrial protocols seen by a network sensor: Zeek's own modbus.log
// and dnp3.log, the logs of CISA's ICSNPP analyzers for Zeek (S7comm,
// EtherNet/IP and CIP, BACnet, OPC UA, PROFINET and more), and Suricata's
// modbus, dnp3 and enip events. Each message is mapped onto the
// Industrial data model with one vocabulary whichever tool saw it: the
// protocol in app, the function as an upper-case name (Zeek's spelling,
// READ_HOLDING_REGISTERS, DIRECT_OPERATE), and what kind of function it
// is in category, so a search or rule can ask for every write or
// control command on any protocol. Only ot_function and ot_unit are new
// field names; the rest reuse names other models have (category, type,
// object, reason, product, signature_id). The logs' own keys stay as zeek_<key>
// (zeekGeneric) and suricata_detail.

// IndustrialModel is the data model industrial protocol messages go to.
const IndustrialModel = "Industrial"

// The kinds of function category names, from the most to the least
// consequential.
const (
	otProgram    = "program"    // a program or logic sent to or read from a controller
	otControl    = "control"    // a controller or outstation told to start, stop, restart or operate
	otWrite      = "write"      // a value, setting or object changed
	otDiagnostic = "diagnostic" // diagnostics and counters
	otDiscovery  = "discovery"  // asking devices who they are
	otRead       = "read"       // a value read
	otOther      = "other"
)

// maxOTValue caps each Industrial field taken from a message.
const maxOTValue = 256

// otLog says where one log type keeps what the Industrial model needs.
// Each list is tried in order; ICSNPP's field names changed between
// releases, so some name both spellings.
type otLog struct {
	proto string
	// fn names the function, code its number, unit the device or
	// station addressed, object the register, point, class or tag (or a
	// diagnostic's subfunction), exc an error or exception, msg whether
	// the message is a request or a response, device the product a device
	// says it is.
	fn, code, unit, object, exc, msg, device []string
	// name names the function when the log has no field for it, and
	// category, when set, is the category of every message of the log.
	name, category string
}

// zeekOTLogs are the Zeek and ICSNPP log types mapped onto Industrial.
var zeekOTLogs = map[string]otLog{
	// Zeek's own.
	"modbus": {proto: "modbus", fn: []string{"func"}, unit: []string{"unit"}, exc: []string{"exception"}, msg: []string{"pdu_type"}},
	"dnp3":   {proto: "dnp3", fn: []string{"fc_request", "fc_reply"}},
	// ICSNPP Modbus (some of its logs spell unit "uint").
	"modbus_detailed": {proto: "modbus", fn: []string{"func"}, unit: []string{"unit", "uint"},
		object: []string{"request_subfunction_code", "address"}, exc: []string{"exception_code"}, msg: []string{"request_response"}},
	"modbus_mask_write_register": {proto: "modbus", fn: []string{"func"}, unit: []string{"uint", "unit"},
		object: []string{"address"}, msg: []string{"request_response"}},
	"modbus_read_write_multiple_registers": {proto: "modbus", fn: []string{"func"}, unit: []string{"uint", "unit"},
		object: []string{"write_start_address"}, msg: []string{"request_response"}},
	"modbus_read_device_identification": {proto: "modbus", name: "READ_DEVICE_IDENTIFICATION", unit: []string{"uint", "unit"},
		object: []string{"object_id"}, msg: []string{"request_response"}, category: otDiscovery},
	// ICSNPP DNP3.
	"dnp3_control": {proto: "dnp3", fn: []string{"function_code"}, object: []string{"index_number"},
		exc: []string{"status_code"}, category: otControl},
	"dnp3_objects": {proto: "dnp3", fn: []string{"function_code"}, object: []string{"object_type"}},
	// ICSNPP S7comm (Siemens).
	"s7comm": {proto: "s7comm", fn: []string{"function_name", "subfunction_name"}, code: []string{"function_code"},
		exc: []string{"error_code", "error_class"}, msg: []string{"rosctr_name"}},
	"s7comm_plus": {proto: "s7comm_plus", fn: []string{"function_name"}, code: []string{"function_code"},
		msg: []string{"opcode_name"}},
	"s7comm_read_szl": {proto: "s7comm", name: "READ_SZL", object: []string{"szl_id_name", "szl_id"},
		exc: []string{"return_code_name"}, msg: []string{"method"}, category: otDiscovery},
	"s7comm_upload_download": {proto: "s7comm", code: []string{"function_code"}, object: []string{"filename", "block_type"},
		msg: []string{"rosctr"}, name: "UPLOAD_DOWNLOAD", category: otProgram},
	// ICSNPP EtherNet/IP and CIP.
	"enip": {proto: "enip", fn: []string{"enip_command"}, code: []string{"enip_command_code"}, exc: []string{"enip_status"}},
	"cip": {proto: "cip", fn: []string{"cip_service"}, code: []string{"cip_service_code"},
		object: []string{"class_name", "class_id"}, exc: []string{"cip_status"}, msg: []string{"direction"}},
	"cip_identity": {proto: "cip", name: "LIST_IDENTITY", device: []string{"product_name"}, category: otDiscovery},
	"cip_io":       {proto: "cip", name: "IO", object: []string{"connection_id"}, category: otRead},
	// ICSNPP BACnet.
	"bacnet": {proto: "bacnet", fn: []string{"pdu_service"}, exc: []string{"result_code"}, msg: []string{"pdu_type"}},
	"bacnet_discovery": {proto: "bacnet", fn: []string{"pdu_service"}, object: []string{"object_type"},
		device: []string{"vendor"}, category: otDiscovery},
	"bacnet_property": {proto: "bacnet", fn: []string{"pdu_service"}, object: []string{"object_type"}},
	"bacnet_device_control": {proto: "bacnet", fn: []string{"pdu_service"}, exc: []string{"result_code"},
		category: otControl},
	// ICSNPP OPC UA, PROFINET, GE SRTP, Omron FINS and HART-IP.
	"opcua_binary":       {proto: "opcua", fn: []string{"identifier_str", "msg_type"}, exc: []string{"reason"}},
	"profinet_io_cm":     {proto: "profinet", code: []string{"operation_num"}, msg: []string{"packet_type"}},
	"ge_srtp_general":    {proto: "ge_srtp", fn: []string{"service_request_code", "message_type"}, exc: []string{"status_code"}},
	"omron_fins_general": {proto: "omron_fins", fn: []string{"command_code"}, exc: []string{"response_code"}},
	"omron_fins_detail":  {proto: "omron_fins", fn: []string{"command_code"}, exc: []string{"response_code"}},
	"hart_ip":            {proto: "hart_ip"},
}

// IsZeekIndustrial reports whether a Zeek log type is an industrial
// protocol's, mapped onto Industrial.
func IsZeekIndustrial(lt string) bool { return isZeekOT(lt) }

// isZeekOT reports whether a Zeek log type is an industrial protocol's.
func isZeekOT(lt string) bool {
	_, ok := zeekOTLogs[lt]
	return ok
}

// zeekIndustrial maps one industrial protocol log line onto Industrial.
// zeekGeneric has already kept its keys as zeek_<key>.
func zeekIndustrial(lt string, r, f map[string]any) {
	l := zeekOTLogs[lt]
	// ICSNPP writes the sender and receiver of each message as
	// source_h/destination_h, and only some releases add the id.* of the
	// connection. src is the connection's originator, as in the other
	// network models, so a response's sender is dest.
	if _, ok := f["src"]; !ok {
		src, srcPort, dest, destPort := wstr(r["source_h"]), r["source_p"], wstr(r["destination_h"]), r["destination_p"]
		if orig, known := zeekBool(wstr(r["is_orig"])); known && !orig {
			src, srcPort, dest, destPort = dest, destPort, src, srcPort
		}
		setStr(f, "src", src)
		setInt(f, "src_port", srcPort)
		setStr(f, "dest", dest)
		setInt(f, "dest_port", destPort)
		if src != "" && dest != "" {
			f["direction"] = netDirection(src, dest, "", "")
		}
	}
	msg := otMessage(otFirst(r, l.msg))
	if msg == "" {
		if b, known := zeekBool(wstr(r["is_orig"])); known {
			msg = map[bool]string{true: "request", false: "response"}[b]
		}
	}
	setOT(f, l, otFirst(r, l.fn), otFirst(r, l.code), otFirst(r, l.unit), otFirst(r, l.object), otFirst(r, l.exc), msg, otFirst(r, l.device))
	if lt == "dnp3" {
		// dnp3.log holds a request and its reply on one line.
		if req, reply := wstr(r["fc_request"]), wstr(r["fc_reply"]); req != "" {
			f["type"] = "request"
		} else if reply != "" {
			f["type"] = "response"
		}
	}
}

// otFirst returns the first of keys r has a value for, as text.
func otFirst(r map[string]any, keys []string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(wstr(zget(r, k))); s != "" && s != "-" {
			return s
		}
	}
	return ""
}

// setOT fills the Industrial fields of one message.
func setOT(f map[string]any, l otLog, fn, code, unit, object, exc, msg, device string) {
	f["app"] = l.proto
	name := otName(fn)
	if name == "" && code != "" {
		name = otFunctionName(l.proto, code)
	}
	if name == "" {
		name = l.name
	}
	if name != "" {
		f["ot_function"] = capLen(name, maxOTValue)
	}
	if code != "" {
		f["signature_id"] = capLen(code, maxOTValue)
	}
	cat := l.category
	if cat == "" {
		cat = otCategory(name)
	}
	f["category"] = cat
	if msg != "" {
		f["type"] = msg
	}
	if unit != "" {
		f["ot_unit"] = capLen(unit, maxOTValue)
	}
	if object != "" {
		f["object"] = capLen(object, maxOTValue)
	}
	if exc != "" && !otSuccess(exc) {
		f["reason"] = capLen(exc, maxOTValue)
	}
	if device != "" {
		f["product"] = capLen(device, maxOTValue)
	}
	sig := strings.ToUpper(l.proto)
	if name != "" {
		sig += " " + name
	}
	f["signature"] = capLen(sig, maxOTValue)
}

// otMessage reads whether a message is a request or a response from the
// protocols' own words for it.
func otMessage(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "":
		return ""
	case strings.HasPrefix(s, "req"), s == "job", strings.HasSuffix(s, "_request"):
		return "request"
	case strings.HasPrefix(s, "resp"), strings.HasPrefix(s, "reply"), s == "ack_data", s == "ack",
		strings.HasSuffix(s, "_ack"), strings.HasSuffix(s, "_response"):
		return "response"
	}
	return ""
}

// otSuccess reports whether an exception or status field says nothing
// went wrong.
func otSuccess(s string) bool {
	switch strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(s)), " ", "_") {
	case "", "-", "0", "0X00", "0X0", "0X0000", "NONE", "SUCCESS", "OK", "NO_ERROR", "GOOD", "F", "FALSE":
		return true
	}
	return false
}

// otName turns a function name into Zeek's spelling: upper case, words
// joined by _ ("Read Var" and "ReadVar" are READ_VAR). A number stays as
// it is, for otFunctionName.
func otName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, err := strconv.Atoi(s); err == nil {
		return ""
	}
	var b strings.Builder
	prev := rune(0)
	under := false
	for _, c := range s {
		switch {
		case unicode.IsLetter(c) || unicode.IsDigit(c):
			if unicode.IsUpper(c) && (unicode.IsLower(prev) || unicode.IsDigit(prev)) && !under && b.Len() > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToUpper(c))
			under = false
		default:
			if b.Len() > 0 && !under {
				b.WriteByte('_')
				under = true
			}
		}
		prev = c
		if b.Len() >= maxOTValue {
			break
		}
	}
	return strings.TrimRight(b.String(), "_")
}

// modbusFunctions and dnp3Functions name the function codes, as Zeek
// does, for tools that log only the number (Suricata).
var modbusFunctions = map[int]string{
	1: "READ_COILS", 2: "READ_DISCRETE_INPUTS", 3: "READ_HOLDING_REGISTERS", 4: "READ_INPUT_REGISTERS",
	5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER", 7: "READ_EXCEPTION_STATUS", 8: "DIAGNOSTICS",
	11: "GET_COMM_EVENT_COUNTER", 12: "GET_COMM_EVENT_LOG", 15: "WRITE_MULTIPLE_COILS",
	16: "WRITE_MULTIPLE_REGISTERS", 17: "REPORT_SLAVE_ID", 20: "READ_FILE_RECORD", 21: "WRITE_FILE_RECORD",
	22: "MASK_WRITE_REGISTER", 23: "READ_WRITE_MULTIPLE_REGISTERS", 24: "READ_FIFO_QUEUE",
	43: "ENCAP_INTERFACE_TRANSPORT",
	// Vendor functions that read or change a controller's program.
	90: "PROGRAM_UMAS", 125: "PROGRAM_584_984_2", 126: "PROGRAM_584_984",
}

// s7Functions names S7comm's job functions, and profinetFunctions the
// PROFINET IO context manager's operations.
var s7Functions = map[int]string{
	0x04: "READ_VAR", 0x05: "WRITE_VAR", 0x1a: "REQUEST_DOWNLOAD", 0x1b: "DOWNLOAD_BLOCK",
	0x1c: "DOWNLOAD_ENDED", 0x1d: "START_UPLOAD", 0x1e: "UPLOAD", 0x1f: "END_UPLOAD",
	0x28: "PLC_CONTROL", 0x29: "PLC_STOP", 0xf0: "SETUP_COMMUNICATION",
}

var profinetFunctions = map[int]string{0: "CONNECT", 1: "RELEASE", 2: "READ", 3: "WRITE", 4: "CONTROL", 5: "READ_IMPLICIT"}

var dnp3Functions = map[int]string{
	0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE",
	6: "DIRECT_OPERATE_NR", 7: "IMMED_FREEZE", 8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR",
	10: "FREEZE_CLEAR_NR", 11: "FREEZE_AT_TIME", 12: "FREEZE_AT_TIME_NR", 13: "COLD_RESTART",
	14: "WARM_RESTART", 15: "INITIALIZE_DATA", 16: "INITIALIZE_APPL", 17: "START_APPL",
	18: "STOP_APPL", 19: "SAVE_CONFIG", 20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
	22: "ASSIGN_CLASS", 23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME", 25: "OPEN_FILE",
	26: "CLOSE_FILE", 27: "DELETE_FILE", 28: "GET_FILE_INFO", 29: "AUTHENTICATE_FILE",
	30: "ABORT_FILE", 31: "ACTIVATE_CONFIG", 32: "AUTHENTICATE_REQ", 33: "AUTH_REQ_NO_ACK",
	129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP",
}

// otFunctionName names a protocol's function code (decimal or 0x hex), or "" when it has no
// table or the code is not in it.
func otFunctionName(proto, code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	base := 10
	if h, ok := strings.CutPrefix(code, "0x"); ok {
		code, base = h, 16
	}
	n, err := strconv.ParseInt(code, base, 32)
	if err != nil || n < 0 {
		return ""
	}
	switch proto {
	case "modbus":
		// A Modbus exception reply sets the code's top bit.
		return modbusFunctions[int(n)&0x7f]
	case "dnp3":
		return dnp3Functions[int(n)]
	case "s7comm":
		return s7Functions[int(n)]
	case "profinet":
		return profinetFunctions[int(n)]
	}
	return ""
}

// otWords sort function names into categories: the first list with a
// word in the name wins, so READ_WRITE_MULTIPLE_REGISTERS is a write and
// PLC_STOP a control command.
var otWords = []struct {
	cat   string
	words []string
}{
	{otProgram, []string{"PROGRAM", "DOWNLOAD", "UPLOAD", "UMAS", "ACTIVATE_CONFIG", "SAVE_CONFIG"}},
	{otControl, []string{"STOP", "START", "RESTART", "RESET", "RUN", "OPERATE", "SELECT", "INITIALIZE",
		"ENABLE_UNSOLICITED", "DISABLE_UNSOLICITED", "FREEZE", "PLC_CONTROL", "PI_SERVICE", "REINITIALIZE", "COMMUNICATION_CONTROL", "SHUTDOWN", "KILL"}},
	{otWrite, []string{"WRITE", "WR", "SET_ATTRIBUTE", "FORCE", "PRESET", "CREATE", "DELETE", "ADD_LIST",
		"REMOVE_LIST", "ASSIGN", "OPEN_FILE", "CLOSE_FILE", "RECORD_CURRENT_TIME", "TIME_SYNC"}},
	{otDiagnostic, []string{"DIAGNOSTIC", "COMM_EVENT", "EXCEPTION_STATUS", "DELAY_MEASURE", "ECHO"}},
	{otDiscovery, []string{"LIST_IDENTITY", "LIST_SERVICES", "LIST_INTERFACES", "WHO_IS", "I_AM", "WHO_HAS",
		"I_HAVE", "REPORT_SLAVE_ID", "ENCAP_INTERFACE_TRANSPORT", "DEVICE_IDENTIFICATION", "SZL", "IDENTIFY",
		"BROWSE", "FIND_SERVERS", "GET_ENDPOINTS"}},
	{otRead, []string{"READ", "RD", "GET_ATTRIBUTE", "GET_FILE_INFO", "FIFO", "IO"}},
}

// otCategory sorts a function name into a category.
func otCategory(name string) string {
	if name == "" {
		return otOther
	}
	parts := "_" + name + "_"
	for _, c := range otWords {
		for _, w := range c.words {
			if strings.Contains(parts, "_"+w+"_") || strings.Contains(parts, "_"+w) && len(w) > 4 {
				return c.cat
			}
		}
	}
	return otOther
}

// suricataOT are Suricata's industrial event types, by the protocol name
// the Industrial model uses.
var suricataOT = map[string]string{"modbus": "modbus", "dnp3": "dnp3", "enip": "enip"}

// eveIndustrial maps Suricata's modbus, dnp3 and enip events onto
// Industrial. eveGeneric has already kept the event's own object.
func eveIndustrial(t string, r, f map[string]any) {
	l := otLog{proto: suricataOT[t]}
	obj, _ := r[t].(map[string]any)
	var fn, code, unit, object, exc, msg string
	switch t {
	case "modbus":
		// One event holds the request and its response.
		req, _ := obj["request"].(map[string]any)
		resp, _ := obj["response"].(map[string]any)
		m := req
		msg = "request"
		if m == nil {
			m, msg = resp, "response"
		}
		code = wstr(m["function_raw"])
		if code == "" {
			fn = wstr(m["function_code"])
		}
		unit = wstr(m["unit_id"])
		object = wstr(wget(m, "read", "address"))
		if object == "" {
			object = wstr(wget(m, "write", "address"))
		}
		for _, x := range []map[string]any{resp, req} {
			if e := wstr(wget(x, "exception", "code")); e != "" && exc == "" {
				exc = e
			}
			if e := wstr(x["error_flags"]); e != "" && !otSuccess(e) && exc == "" {
				exc = e
			}
		}
		if exc == "" {
			// An exception reply carries the request's code with the top bit set.
			if n, err := strconv.Atoi(wstr(resp["function_raw"])); err == nil && n >= 0x80 {
				exc = strconv.Itoa(n)
			}
		}
	case "dnp3":
		msg = otMessage(wstr(obj["type"]))
		code = wstr(wget(obj, "application", "function_code"))
		unit = wstr(obj["dst"])
	case "enip":
		m, _ := obj["request"].(map[string]any)
		msg = "request"
		if m == nil {
			m, _ = obj["response"].(map[string]any)
			msg = "response"
		}
		fn = wstr(wget(m, "cip", "service"))
		if fn == "" {
			fn = wstr(m["command"])
		}
		object = wstr(wget(m, "cip", "class"))
		exc = wstr(m["status"])
	}
	setOT(f, l, fn, code, unit, object, exc, msg, "")
}
