package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// The status line status.sh writes (testdata/sensor/status.json, which
// deploy's TestSensorStatusLine keeps in step with the script) becomes an
// Other event with the sensor's values, and its values go to Result.Sensor.
func TestSensorStatus(t *testing.T) {
	line := sensorLines(t, "sensor", "status.json")[0]
	ev := Normalize(SensorStatusTag, map[string]any{"log": line, "hostname": "nsm-01"}, now)
	doc := ev.Document()
	expect(t, doc, map[string]any{
		"datamodel": "Other", "sourcetype": "sensor:status", "vendor_product": "Signalith sensor", "signature": "Sensor status",
		"host": "nsm-01", "dvc": "nsm-01", "@timestamp": "2026-10-15T12:00:00Z",
		"sensor_role": "sensor", "sensor_version": "1.6.0", "zeek_version": "8.0.4", "suricata_version": "8.0.1",
		"fluentbit_version": "4.0.3", "sensor_zeek_running": "yes", "sensor_suricata_running": "yes",
		"rules_updated": "2026-10-15T03:41:00Z", "rules_count": int64(48211), "rules_update": "ok",
		"sensor_interface": "ens192", "sensor_link": "up", "packets_received": int64(1234567), "packets_dropped": int64(12),
		"drop_percent": 0.1, "disk_free_percent": 63.0, "disk_free_bytes": int64(53687091200),
		"sensor_disk_encrypted": "no", "sensor_time_synced": "yes",
		"message": "nsm-01: Zeek 8.0.4 running, Suricata 8.0.1 running, rules 8 hours old, ens192 up, 0.1% dropped, 63% disk free",
	})
	if w, _ := doc["sensor_warnings"].([]string); len(w) != 1 || w[0] != "capture_ip" {
		t.Errorf("warnings: %v", doc["sensor_warnings"])
	}
	if ev.ID == "" || ev.ID != Normalize(SensorStatusTag, map[string]any{"log": line, "hostname": "nsm-01"}, now).ID {
		t.Errorf("ID %q is not the same for the same line", ev.ID)
	}
	s := ev.Sensor
	if s == nil || !s.At.Equal(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)) || s.Zeek == nil || !s.Zeek.Running || s.Suricata.Version != "8.0.1" ||
		s.RulesCount != 48211 || s.Interface != "ens192" || s.DropPercent != 0.1 || s.DiskFreePercent != 63 || s.DiskEncrypted || !s.TimeSynced {
		t.Errorf("sensor: %+v", s)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
}

// Missing, odd and hostile values are dropped, never stored as given.
func TestSensorStatusOddValues(t *testing.T) {
	for name, c := range map[string]struct {
		line string
		want map[string]any
	}{
		"Suricata only, no rules yet": {`{"kind":"signalith-sensor-status","v":1,"time":"2026-10-15T12:00:00Z","host":"nsm-02","suricata":{"version":"8.0.1","running":false},"rules":{"update":"never","count":0},"interface":{"name":"eth1","link":"down","drop_percent":250},"disk":{"free_percent":-3}}`,
			map[string]any{"host": "nsm-02", "zeek_version": nil, "sensor_zeek_running": nil, "sensor_suricata_running": "no", "rules_count": int64(0),
				"drop_percent": 100.0, "disk_free_percent": 0.0, "message": "nsm-02: Suricata 8.0.1 stopped, no rules yet, eth1 down, 100% dropped, 0% disk free"}},
		"failed update": {`{"kind":"signalith-sensor-status","v":1,"suricata":{"version":"8.0.1","running":true},"rules":{"updated":"2026-10-01T00:00:00Z","update":"failed"}}`,
			map[string]any{"rules_update": "failed", "message": "Suricata 8.0.1 running, rules update failed, 0% dropped, 0% disk free"}},
		"control characters and long words": {`{"kind":"signalith-sensor-status","v":1,"sensor_version":"1.6\u0000","layout":"` + strings.Repeat("x", 80) + `","interface":{"name":["eth1"],"rx_packets":"many"},"warnings":["drops",7,"a\nb"]}`,
			map[string]any{"sensor_version": nil, "sensor_interface": nil, "packets_received": nil}},
	} {
		ev := Normalize(SensorStatusTag, map[string]any{"log": c.line}, now)
		checkSensorEvent(t, ev)
		doc := ev.Document()
		for k, v := range c.want {
			if v == nil {
				if _, ok := doc[k]; ok {
					t.Errorf("%s: %s = %#v, want none", name, k, doc[k])
				}
				continue
			}
			if doc[k] != v {
				t.Errorf("%s: %s = %#v, want %#v", name, k, doc[k], v)
			}
		}
		if ev.Sensor == nil {
			t.Errorf("%s: no sensor", name)
		}
	}
	// Not a status line: a generic event, and nothing for the inventory.
	for _, line := range []string{`{"kind":"other","v":1}`, `not json`, `{"kind":"signalith-sensor-status"`} {
		ev := Normalize(SensorStatusTag, map[string]any{"log": line}, now)
		checkSensorEvent(t, ev)
		if ev.Sensor != nil || ev.Fields["sourcetype"] != "sensor:status" {
			t.Errorf("%q: %+v", line, ev)
		}
	}
	// Only the exact tag: a Zeek or other line is never read as one.
	if ev := Normalize("sensor.statusx", map[string]any{"log": sensorLines(t, "sensor", "status.json")[0]}, now); ev.Sensor != nil {
		t.Error("sensor.statusx read as a status line")
	}
}

// A batch hands the last status line in it that was stored to the agent
// inventory: the last one sent, whatever time it gives itself, which is
// never kept later than when it arrived.
func TestSensorStatusResult(t *testing.T) {
	ahead := `{"kind":"signalith-sensor-status","v":1,"time":"2099-01-01T00:00:00Z","host":"nsm-01","interface":{"name":"eth1"}}`
	last := `{"kind":"signalith-sensor-status","v":1,"time":"2026-10-11T11:55:00Z","host":"nsm-01","interface":{"name":"eth2"}}`
	refused := `{"kind":"signalith-sensor-status","v":1,"time":"2026-10-11T11:59:00Z","host":"nsm-01","interface":{"name":"eth3"}}`
	body, _ := json.Marshal([]map[string]any{{"log": ahead}, {"log": last}})
	bulk := &countingBulk{keep: true, reject: func(d store.IndexedDoc) *store.BulkItemError {
		if strings.Contains(fmt.Sprint(d.Doc), "eth3") {
			return &store.BulkItemError{Index: d.Index, Status: http.StatusBadRequest, Reason: "refused"}
		}
		return nil
	}}
	p := &Pipeline{Store: bulk, Now: func() time.Time { return now }}
	res, err := p.IngestBody(context.Background(), SensorStatusTag, body)
	if err != nil || res.Sensor == nil || res.Sensor.Interface != "eth2" || !res.Sensor.At.Equal(now.Add(-5*time.Minute)) {
		t.Fatalf("IngestBody: %+v %v", res, err)
	}
	res, err = p.Ingest(context.Background(), SensorStatusTag, []map[string]any{{"log": last}, {"log": ahead}, {"log": refused}})
	if err != nil || res.Sensor == nil || res.Sensor.Interface != "eth1" || !res.Sensor.At.Equal(now) {
		t.Fatalf("Ingest: %+v %v", res, err)
	}
	res, err = p.IngestBody(context.Background(), "zeek.conn", []byte(`{"log":"{}"}`))
	if err != nil || res.Sensor != nil {
		t.Errorf("a Zeek batch: %+v %v", res, err)
	}
}
