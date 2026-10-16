package splcheck

import (
	"fmt"
	"math/rand"
	"regexp"
	"testing"
)

// Every number's hex text, as Windows writes it and with leading zeros,
// matches bitsPattern exactly when its bits do.
func TestBitsPattern(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	masks := []uint64{1, 0x10, 0x40, 0x400, 0x1000, 0x1010, 0x1f3fff, 0x1fffff, 0x2, 0x6, 0x80000000}
	for i := 0; i < 40; i++ {
		masks = append(masks, uint64(r.Uint32())&uint64(r.Uint32()))
	}
	for _, set := range masks {
		for _, clear := range []uint64{0, set ^ 0xffffffff, 0x400, 0x8} {
			clear &^= set
			re := regexp.MustCompile(bitsPattern(set, clear))
			for j := 0; j < 400; j++ {
				v := uint64(r.Uint32())
				switch j % 4 {
				case 1:
					v |= set
				case 2:
					v = (v | set) &^ clear
				case 3:
					v &= 0xffff
				}
				want := v&set == set && v&clear == 0
				for _, text := range []string{fmt.Sprintf("0x%x", v), fmt.Sprintf("0x%X", v), fmt.Sprintf("0x%08x", v), fmt.Sprintf("%x", v)} {
					if re.MatchString(text) != want {
						t.Fatalf("set %#x clear %#x: %s matched %v, want %v", set, clear, text, !want, want)
					}
				}
			}
		}
	}
	if regexp.MustCompile(bitsPattern(0x10, 0)).MatchString("0x10z") {
		t.Error("matches text that is not a number")
	}
}

func TestParseBitTests(t *testing.T) {
	src := rule("`sysmon` EventCode=10 TargetImage=\"*\\\\lsass.exe\"\n" +
		"| eval g = tonumber(replace(GrantedAccess,\"0x\",\"\"),16) | eval VM_READ = 16 | eval QUERY_LIMITED = 4096 | eval QUERY = 1024\n" +
		"| eval r = bit_and(g, VM_READ) | eval l = bit_and(g, QUERY_LIMITED) | eval q = bit_and(g, QUERY)\n" +
		"| where r == VM_READ AND l == QUERY_LIMITED AND (q == 0 OR q == QUERY)\n" +
		"| stats count by dest GrantedAccess | eval CallTrace=split(CallTrace, \"|\")")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	for access, want := range map[string]bool{"0x1010": true, "0x1410": true, "0x1FFFFF": true, "0x1000": false, "0x10": false, "0x1400": false} {
		ev := map[string]string{"signature_id": "10", "target_process_path": `C:\Windows\System32\lsass.exe`, "granted_access": access}
		if Eval(r.Where, ev) != want {
			t.Errorf("%s: want %v", access, want)
		}
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event matches")
	}
	// Any of two bits set.
	src = rule("`wineventlog_security` EventCode=5145 ShareName=\"\\\\\\\\*\\\\C$\" | eval m = tonumber(AccessMask, 16) | where (bit_and(m, 2) != 0) OR (bit_and(m, 4) != 0)")
	if r, err = Parse(src, nil); err != nil {
		t.Fatal(err)
	}
	for mask, want := range map[string]bool{"0x2": true, "0x4": true, "0x6": true, "0x1": false, "0x100180": false, "0x100182": true} {
		if Eval(r.Where, map[string]string{"signature_id": "5145", "share_name": `\\*\C$`, "access_mask": mask}) != want {
			t.Errorf("%s: want %v", mask, want)
		}
	}
	// A comparison with another value is not a bit test.
	if _, err := Parse(rule("`sysmon` EventCode=10 TargetImage=\"*x*\" | eval g = tonumber(GrantedAccess, 16) | eval r = bit_and(g, 16) | where r == 3"), nil); err == nil {
		t.Error("r == 3 parsed")
	}
}
