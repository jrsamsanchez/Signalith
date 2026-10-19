// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"testing"
	"time"
)

func TestParseBitLocker(t *testing.T) {
	one := []byte("\xef\xbb\xbf{\"DriveLetter\":\"c:\",\"ProtectionStatus\":1,\"ConversionStatus\":1,\"EncryptionMethod\":7}\r\n")
	vols, err := ParseBitLocker(one)
	if err != nil || len(vols) != 1 || vols[0] != (BitLockerVolume{Drive: "C:", Protection: 1, Conversion: 1, Method: 7}) {
		t.Errorf("one: %+v %v", vols, err)
	}
	many := []byte(`[{"DriveLetter":"C:","ProtectionStatus":1,"ConversionStatus":1,"EncryptionMethod":6},
		{"DriveLetter":null,"ProtectionStatus":0,"ConversionStatus":0,"EncryptionMethod":0},
		{"DriveLetter":"D:","ProtectionStatus":0,"ConversionStatus":0,"EncryptionMethod":0}]`)
	vols, err = ParseBitLocker(many)
	if err != nil || len(vols) != 2 || vols[1].Drive != "D:" {
		t.Errorf("many: %+v %v", vols, err)
	}
	if _, err := ParseBitLocker([]byte("  ")); err == nil {
		t.Error("no answer accepted")
	}
	if _, err := ParseBitLocker([]byte("Get-CimInstance : Access denied")); err == nil {
		t.Error("an error message accepted")
	}
}

func TestBitLockerDisk(t *testing.T) {
	at := now.Add(-48 * time.Hour)
	saved := &SavedDisks{CheckedAt: at, Volumes: []BitLockerVolume{
		{Drive: "C:", Protection: 1, Conversion: 1},
		{Drive: "D:", Protection: 0, Conversion: 1},
		{Drive: "E:", Protection: 0, Conversion: 0},
	}}
	for _, tc := range []struct {
		path  string
		saved *SavedDisks
		vm    vmInfo
		want  Disk
	}{
		{`C:\ProgramData\Signalith`, saved, vmInfo{}, Disk{Kind: DiskEncrypted, Method: "BitLocker", CheckedAt: at}},
		{`c:\ProgramData\Signalith`, saved, vmInfo{}, Disk{Kind: DiskEncrypted, Method: "BitLocker", CheckedAt: at}},
		{`D:\data`, saved, vmInfo{}, Disk{Kind: DiskEncrypted, Method: "BitLocker", Suspended: true, CheckedAt: at}},
		{`E:\data`, saved, vmInfo{}, Disk{Kind: DiskPlain, CheckedAt: at}},
		{`E:\data`, saved, vmInfo{Virtual: true, Provider: "Hyper-V"}, Disk{Kind: DiskVirtual, Provider: "Hyper-V", CheckedAt: at}},
		// No answer for the drive, no answer at all, or an old one.
		{`F:\data`, saved, vmInfo{}, Disk{Kind: DiskWindows}},
		{`C:\data`, nil, vmInfo{}, Disk{Kind: DiskWindows}},
		{`C:\data`, &SavedDisks{CheckedAt: now.Add(-31 * 24 * time.Hour), Volumes: saved.Volumes}, vmInfo{}, Disk{Kind: DiskWindows}},
	} {
		got := bitLockerDisk(tc.path, tc.saved, now, tc.vm)
		if got.Kind != tc.want.Kind || got.Method != tc.want.Method || got.Suspended != tc.want.Suspended ||
			got.Provider != tc.want.Provider || !got.CheckedAt.Equal(tc.want.CheckedAt) || got.Path != tc.path {
			t.Errorf("%s: %+v, want %+v", tc.path, got, tc.want)
		}
	}
	if d := bitLockerDisk(`\\nas\share\signalith`, saved, now, vmInfo{}); d.Kind != DiskNetwork || d.Source != `\\nas\share` {
		t.Errorf("share: %+v", d)
	}
}

func TestSavedDisks(t *testing.T) {
	dir := t.TempDir()
	if LoadDisks(dir) != nil {
		t.Error("an answer before one was saved")
	}
	s := SavedDisks{CheckedAt: now.UTC(), Volumes: []BitLockerVolume{{Drive: "C:", Protection: 1, Conversion: 1}}}
	if err := SaveDisks(dir, s); err != nil {
		t.Fatal(err)
	}
	got := LoadDisks(dir)
	if got == nil || !got.CheckedAt.Equal(s.CheckedAt) || len(got.Volumes) != 1 || got.Volumes[0] != s.Volumes[0] {
		t.Errorf("%+v", got)
	}
}
