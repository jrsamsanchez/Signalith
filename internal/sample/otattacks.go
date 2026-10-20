// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"fmt"
	"time"
)

// The plant floor seen by the network sensor: the industrial protocol
// messages Zeek and its ICSNPP analyzers log, which go through the real
// parsers into the Industrial data model.

// otModbus adds a modbus.log line for one request on fl.
func (g *gen) otModbus(fl sensorFlow, t time.Time, fn string, unit int) {
	g.b.zeek("modbus", t, fl.ids(map[string]any{"tid": 1 + g.rng.intn(65000), "unit": unit, "func": fn, "pdu_type": "REQ"}))
}

// plantIntrusion: the malware on the engineering workstation eng-ws-02
// (see dnsTunnel) moves onto the plant network the next day. It asks
// every address on the controller subnet who it is, probes plc-01's
// registers until the device refuses 30 requests, writes set points on
// plc-02, downloads a new program to plc-03 and stops it, and finally
// forces plc-01 into Modbus listen-only mode so its HMI can no longer
// reach it.
func (g *gen) plantIntrusion() {
	ws := g.org.host("eng-ws-02")
	plc1, plc2, plc3 := g.org.host("plc-01"), g.org.host("plc-02"), g.org.host("plc-03")
	t0 := g.day(2, 14, 20)

	// Discovery: EtherNet/IP List Identity to the 12 addresses of the
	// controller range, a second apart.
	for i := 0; i < 12; i++ {
		dest := fmt.Sprintf("%s%d", netCompany, 230+i)
		fl := g.newFlow(ws.IP, dest, 44818)
		g.b.zeek("enip", t0.Add(time.Duration(i)*time.Second), fl.ids(map[string]any{
			"is_orig": true, "enip_command_code": "0x0063", "enip_command": "List Identity", "enip_status": "Success",
		}))
	}

	// Probing: reads of addresses plc-01 does not have.
	tp := t0.Add(2 * time.Minute)
	probe := g.newFlow(ws.IP, plc1.IP, 502)
	for i := 0; i < 30; i++ {
		g.b.zeek("modbus", tp.Add(time.Duration(i*2)*time.Second), probe.ids(map[string]any{
			"tid": 100 + i, "unit": 1, "func": "READ_HOLDING_REGISTERS", "pdu_type": "RESP", "exception": "ILLEGAL_DATA_ADDRESS",
		}))
	}

	// Writes: new set points on plc-02.
	tw := tp.Add(90 * time.Second)
	wr := g.newFlow(ws.IP, plc2.IP, 502)
	for i := 0; i < 4; i++ {
		g.otModbus(wr, tw.Add(time.Duration(i*3)*time.Second), "WRITE_MULTIPLE_REGISTERS", 1)
	}

	// A new program for plc-03 over S7comm, then a stop.
	ts := tw.Add(time.Minute)
	s7 := g.newFlow(ws.IP, plc3.IP, 102)
	for i, fn := range []struct{ code, name string }{
		{"0xf0", "Setup communication"}, {"0x1a", "Request download"}, {"0x1b", "Download block"},
		{"0x1c", "Download ended"}, {"0x29", "PLC Stop"},
	} {
		g.b.zeek("s7comm", ts.Add(time.Duration(i*5)*time.Second), s7.ids(map[string]any{
			"is_orig": true, "rosctr_code": "0x01", "rosctr_name": "Job", "pdu_reference": 512 + i,
			"function_code": fn.code, "function_name": fn.name, "error_class": "-", "error_code": "-",
		}))
	}

	// Listen-only mode on plc-01 (ICSNPP's modbus_detailed.log).
	tl := ts.Add(40 * time.Second)
	lo := g.newFlow(ws.IP, plc1.IP, 502)
	g.b.zeek("modbus_detailed", tl, lo.ids(map[string]any{
		"is_orig": true, "tid": 200, "unit": 1, "func": "DIAGNOSTICS", "request_subfunction_code": "FORCE_LISTEN_ONLY_MODE",
		"matched": false, "exception_code": "-",
	}))

	g.story(Story{
		ID:    "plant-intrusion",
		Title: "Malware reaches the plant network",
		Summary: fmt.Sprintf("The malware on %s moves onto the plant network: it asks 12 addresses who they are over EtherNet/IP, probes %s until the controller refuses 30 requests, writes new set points to %s, downloads a program to %s and stops it, and forces %s into Modbus listen-only mode so its HMI can no longer reach it. Seen only by the network sensor.",
			ws.Name, plc1.Name, plc2.Name, plc3.Name, plc1.Name),
		Detections: []string{"ot-device-discovery", "ot-exception-burst", "ot-program-transfer", "ot-controller-stop-start", "ot-modbus-listen-only"},
	}, tl.Add(2*time.Minute), ws.Name, ws.IP, plc1.Name, plc2.Name, plc3.Name)
}

// exposedPLC: plc-02's Modbus port was left reachable from the internet
// through a port forward, and a host outside writes to a coil.
func (g *gen) exposedPLC() {
	plc := g.org.host("plc-02")
	t0 := g.day(5, 3, 12)
	const outsider = "203.0.113.88"
	fl := g.newFlow(outsider, plc.IP, 502)
	g.otModbus(fl, t0, "READ_COILS", 1)
	g.otModbus(fl, t0.Add(4*time.Second), "WRITE_SINGLE_COIL", 1)
	g.story(Story{
		ID:         "exposed-plc",
		Title:      "A controller answers the internet",
		Summary:    fmt.Sprintf("A port forward left %s's Modbus port open to the internet, and %s reads its coils and then switches one at night. Industrial protocols have no sign-in, so anyone who finds the port can do this.", plc.Name, outsider),
		Detections: []string{"ot-command-from-outside"},
	}, t0.Add(2*time.Minute), plc.Name, outsider)
}
