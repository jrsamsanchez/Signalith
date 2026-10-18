package splcheck

import "testing"

func TestChannelRules(t *testing.T) {
	macros := map[string]*Macro{
		"wineventlog_system":               {Name: "wineventlog_system", Definition: `source="XmlWinEventLog:System"`},
		"wineventlog_appxdeploymentserver": {Name: "wineventlog_appxdeploymentserver", Definition: `source="XmlWinEventLog:Microsoft-Windows-AppXDeploymentServer/Operational"`},
		"wineventlog_application":          {Name: "wineventlog_application", Definition: `source="XmlWinEventLog:Application"`},
		"normalized_service_binary_field": {Name: "normalized_service_binary_field", Definition: `EventCode=7036 | spath input=EventData_Xml path="Binary" output=binary_data` +
			` | eval normalized_service_name = mvjoin(split(trim(binary_data, "0"), "00"), "")`},
	}
	for _, tc := range []struct{ search, node, field string }{
		{"`wineventlog_appxdeploymentserver` EventCode=603 Flags=\"8388608\"\n| stats count by dvc EventCode Flags",
			"AppxDeploymentStarted", "appx_flags"},
		{"`wineventlog_system` `normalized_service_binary_field`\n| rename param1 as display_name\n" +
			"| where param2=\"stopped\" AND match(display_name, \"(?i)backup\")\n| stats count by display_name normalized_service_name",
			"ServiceStateChanged", "system_param2"},
		{"`wineventlog_application` EventCode=15457\n" +
			"| rex field=EventData_Xml \"<Data>(?<config_name>[^<]+)</Data><Data>(?<old_value>[^<]+)</Data><Data>(?<new_value>[^<]+)</Data>\"\n" +
			"| where config_name=\"xp_cmdshell\"\n| stats count by host config_name",
			"SqlConfigChanged", "event_data"},
	} {
		r, err := Parse(rule(tc.search), macros)
		if err != nil {
			t.Fatalf("%s: %v", tc.node, err)
		}
		if r.Node != tc.node {
			t.Fatalf("node %s, want %s", r.Node, tc.node)
		}
		if ev := map[string]string{"sourcetype": "WinEventLog:Security", tc.field: "8388608"}; Eval(r.Where, ev) {
			t.Errorf("%s: another log's event matches", tc.node)
		}
		pos := 0
		for _, c := range Cases(r) {
			if c.Expect {
				pos++
				if !inChannel(r.Node, c) {
					t.Errorf("%s: case of %s %s", tc.node, c.Channel, c.EventID)
				}
			}
		}
		if pos == 0 {
			t.Errorf("%s: no positive cases", tc.node)
		}
	}
	if got := utf16Hex("wu"); got != "770075000000" {
		t.Errorf("utf16Hex: %s", got)
	}
}
