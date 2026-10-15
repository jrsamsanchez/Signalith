package sensortune

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestValidateLines(t *testing.T) {
	ok := []Tuning{
		{Disable: "2014520\n1:2014520\n# a comment\n\n1:2014520, 1:2014521\n2014520,2014521\nre:heartbleed\nre: ET POLICY .* curl\ngroup:emerging-icmp.rules\ngroup: emerging-*.rules\nmetadata: deployment perimeter"},
		{Threshold: "suppress gen_id 1, sig_id 2014520\nsuppress gen_id 1, sig_id 2014520, track by_src, ip 10.0.0.5\n" +
			"suppress gen_id 1,sig_id 2,track by_dst,ip 10.0.0.0/8\nsuppress gen_id 1, sig_id 3, track by_either, ip [10.0.0.1, 192.168.0.0/16, $HOME_NET]\n" +
			"suppress gen_id 1, sig_id 4, track by_src, ip $EXTERNAL_NET\nsuppress gen_id 1, sig_id 4, track by_src, ip fe80::1\n" +
			"threshold gen_id 1, sig_id 5, type limit, track by_src, count 1, seconds 60\n" +
			"event_filter gen_id 1, sig_id 6, type both, track by_rule, count 10, seconds 600\n" +
			"rate_filter gen_id 1, sig_id 7, track by_rule, count 10, seconds 60, new_action alert, timeout 300"},
		{Local: "alert tcp any any -> $HOME_NET 23 (msg:\"Telnet\"; sid:1000001; rev:1;)\n" +
			"# disabled: alert ip any any -> any any (sid:1000002;)\n" +
			"drop udp any any -> any 53 (msg:\"x\"; content:\"evil\"; sid: 1000003 ; rev:2;)\n" +
			"alert http any any -> any any (msg:\"lua in content is fine\"; content:\"lua\"; sid:1000004;)"},
	}
	for i, tu := range ok {
		if err := tu.Normalize().Validate(); err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	bad := []struct {
		tu    Tuning
		field string
		line  int
		says  string
	}{
		{Tuning{Disable: "2014520\nfoo"}, FieldDisable, 2, "SID"},
		{Tuning{Disable: "0"}, FieldDisable, 1, "not a rule number"},
		{Tuning{Disable: "99999999999"}, FieldDisable, 1, ""},
		{Tuning{Disable: "group:../../etc/passwd"}, FieldDisable, 1, "group:"},
		{Tuning{Disable: "group:a;rm -rf /"}, FieldDisable, 1, "group:"},
		{Tuning{Disable: "re:"}, FieldDisable, 1, "pattern"},
		{Tuning{Disable: "$(reboot)"}, FieldDisable, 1, "SID"},
		{Tuning{Disable: "[local]"}, FieldDisable, 1, "start with ["},
		{Tuning{Disable: "  [end]"}, FieldDisable, 1, "start with ["},
		{Tuning{Disable: "123\x00"}, FieldDisable, 1, "control"},
		{Tuning{Disable: "123\r456"}, FieldDisable, 1, "control"},
		{Tuning{Disable: "\xff"}, FieldDisable, 1, "UTF-8"},
		{Tuning{Disable: strings.Repeat("1", MaxLineBytes+1)}, FieldDisable, 1, "longer"},
		{Tuning{Threshold: "suppress gen_id 1"}, FieldThreshold, 1, "write it as: suppress"},
		{Tuning{Threshold: "suppress gen_id 1, sig_id 2, track by_src, ip 10.0.0.300"}, FieldThreshold, 1, "not an address"},
		{Tuning{Threshold: "suppress gen_id 1, sig_id 2, track by_src, ip `id`"}, FieldThreshold, 1, "not an address"},
		{Tuning{Threshold: "threshold gen_id 1, sig_id 5, type sometimes, track by_src, count 1, seconds 60"}, FieldThreshold, 1, "write it as: threshold"},
		{Tuning{Threshold: "rate_filter gen_id 1, sig_id 7, track by_rule, count 10, seconds 60, new_action explode, timeout 300"}, FieldThreshold, 1, "rate_filter"},
		{Tuning{Threshold: "include /etc/shadow"}, FieldThreshold, 1, "each line starts"},
		{Tuning{Local: "alert tcp any any -> any any (msg:\"no sid\";)"}, FieldLocal, 1, "exactly one sid"},
		{Tuning{Local: "alert tcp any any -> any any (sid:1; sid:2;)"}, FieldLocal, 1, "exactly one sid"},
		{Tuning{Local: "alert tcp any any -> any any (sid:1000001;)\n\nalert tcp any any -> any any (sid:1000001;)"}, FieldLocal, 3, "line 1 too"},
		{Tuning{Local: "hello world"}, FieldLocal, 1, "one whole rule"},
		{Tuning{Local: "alert tcp any any -> any any (msg:\"x\"; lua:evil.lua; sid:1000001;)"}, FieldLocal, 1, "cannot use lua"},
		{Tuning{Local: "alert tcp any any -> any any (msg:\"x\"; luajit:evil.lua; sid:1000001;)"}, FieldLocal, 1, "cannot use luajit"},
		{Tuning{Local: "alert http any any -> any any (http.uri; dataset:set,bad,type string,save /etc/cron.d/x; sid:1000001;)"}, FieldLocal, 1, "cannot use dataset"},
		{Tuning{Local: "alert http any any -> any any (DATAREP:x; sid:1000001;)"}, FieldLocal, 1, "cannot use datarep"},
		{Tuning{Local: "alert http any any -> any any (filestore; sid:1000001;)"}, FieldLocal, 1, "cannot use filestore"},
		{Tuning{Local: "alert ip any any -> any any (iprep:src,cat,>,10; sid:1000001;)"}, FieldLocal, 1, "cannot use iprep"},
		{Tuning{Local: "alert tcp any any -> any any (sid:1000001;) \\"}, FieldLocal, 1, "one whole rule"},
	}
	for _, c := range bad {
		err := c.tu.Normalize().Validate()
		var le *LineError
		if !errors.As(err, &le) || le.Field != c.field || le.Line != c.line || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%+v: %v", c.tu, err)
		}
	}
	// Too many entries, too many bytes.
	many := strings.Repeat("1\n", MaxDisable+1)
	if err := (Tuning{Disable: many}).Normalize().Validate(); err == nil || !strings.Contains(err.Error(), "at most 5000") {
		t.Errorf("too many: %v", err)
	}
	big := strings.Repeat("# "+strings.Repeat("x", 1000)+"\n", 300)
	if err := (Tuning{Threshold: big}).Normalize().Validate(); err == nil || !strings.Contains(err.Error(), "at most 256 KB") {
		t.Errorf("too big: %v", err)
	}
	if got := (&LineError{Field: FieldLocal, Line: 4, Msg: "x"}).Error(); got != "Your own rules, line 4: x" {
		t.Errorf("message: %q", got)
	}
}

func TestNormalizeAndCounts(t *testing.T) {
	tu := Tuning{Disable: "\ufeff\r\n2014520  \r\n# off\r\n\r\n1:2\t\r\n\r\n", Local: "\n\nalert ip any any -> any any (sid:5;)\n"}.Normalize()
	if tu.Disable != "2014520\n# off\n\n1:2" || tu.Local != "alert ip any any -> any any (sid:5;)" {
		t.Errorf("normalized: %q %q", tu.Disable, tu.Local)
	}
	if c := tu.Counts(); c[FieldDisable] != 2 || c[FieldThreshold] != 0 || c[FieldLocal] != 1 {
		t.Errorf("counts: %v", c)
	}
	if w := tu.Warnings(); len(w) != 1 || !strings.Contains(w[0], "sid 5 is outside") {
		t.Errorf("warnings: %v", w)
	}
}

// split reads a bundle as the sensor's awk does: lines under each
// [section] go to that section; anything after [end] is ignored, and no
// [end] means the body was cut short.
func split(b []byte) (map[string]string, bool) {
	out := map[string]string{}
	cur, ended := "", false
	sc := bufio.NewScanner(bytes.NewReader(b))
	first := true
	for sc.Scan() {
		l := sc.Text()
		if first {
			first = false
			if l != BundleHeader {
				return nil, false
			}
			continue
		}
		switch l {
		case "[disable]", "[threshold]", "[local]":
			cur = l[1 : len(l)-1]
			continue
		case BundleEnd:
			ended = true
		}
		if ended {
			break
		}
		if strings.HasPrefix(l, "[") || cur == "" {
			return nil, false
		}
		out[cur] += l + "\n"
	}
	return out, ended
}

func TestBundleRoundTrip(t *testing.T) {
	tu := Tuning{Disable: "2014520\n# why", Threshold: "suppress gen_id 1, sig_id 2", Local: "alert ip any any -> any any (sid:1000001;)", UpdatedBy: "admin"}
	b := tu.Bundle()
	want := BundleHeader + "\n[disable]\n2014520\n# why\n[threshold]\nsuppress gen_id 1, sig_id 2\n[local]\nalert ip any any -> any any (sid:1000001;)\n[end]\n"
	if string(b) != want {
		t.Fatalf("bundle:\n%s", b)
	}
	got, ok := split(b)
	if !ok || got[FieldDisable] != tu.Disable+"\n" || got[FieldThreshold] != tu.Threshold+"\n" || got[FieldLocal] != tu.Local+"\n" {
		t.Errorf("split: %v %v", ok, got)
	}
	if _, ok := split(b[:len(b)-6]); ok {
		t.Error("a cut bundle was read")
	}
	empty := Tuning{}.Bundle()
	if string(empty) != BundleHeader+"\n[disable]\n[threshold]\n[local]\n[end]\n" {
		t.Errorf("empty: %q", empty)
	}
	// Who saved it is not part of what sensors run.
	h := tu.Hash()
	tu.UpdatedBy = "someone else"
	if tu.Hash() != h || len(h) != 64 || ShortHash(h) != h[:12] {
		t.Errorf("hash: %s %s", h, tu.Hash())
	}
}

// Whatever passes the checks splits back into the same three texts.
func FuzzValidate(f *testing.F) {
	f.Add("2014520", "suppress gen_id 1, sig_id 2", "alert ip any any -> any any (sid:1000001;)")
	f.Add("[end]", "[local]\n1", "x\n[disable]")
	f.Add("\r\n1\r", "\x00", "\ufeff")
	f.Fuzz(func(t *testing.T, d, th, l string) {
		tu := Tuning{Disable: d, Threshold: th, Local: l}.Normalize()
		if tu.Validate() != nil {
			return
		}
		got, ok := split(tu.Bundle())
		if !ok {
			t.Fatalf("accepted but not read back: %q", tu.Bundle())
		}
		for _, f := range Fields {
			want := tu.Field(f)
			if want != "" {
				want += "\n"
			}
			if got[f] != want {
				t.Fatalf("%s: %q != %q", f, got[f], want)
			}
		}
	})
}
