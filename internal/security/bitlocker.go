// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// On Windows the service's account can't ask BitLocker about a drive.
// "signalith security", run as Administrator, asks and saves the answer
// in the state folder (security\disk.json); the server shows an answer
// that is less than 30 days old, with its date.

// BitLockerVolume is one volume, as Win32_EncryptableVolume says.
type BitLockerVolume struct {
	Drive string `json:"drive"`
	// Protection: 0 off, 1 on, 2 unknown.
	Protection int `json:"protection"`
	// Conversion: 0 fully decrypted, 1 fully encrypted, 2 encrypting,
	// 3 decrypting, 4 encryption paused, 5 decryption paused.
	Conversion int `json:"conversion"`
	Method     int `json:"method"`
}

// SavedDisks is the saved answer.
type SavedDisks struct {
	CheckedAt time.Time         `json:"checked_at"`
	Volumes   []BitLockerVolume `json:"volumes"`
}

// SavedDisksMaxAge is how long a saved answer is shown.
const SavedDisksMaxAge = 30 * 24 * time.Hour

// BitLockerQuery is the PowerShell that asks BitLocker about every
// volume.
const BitLockerQuery = "Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | " +
	"Select-Object DriveLetter,ProtectionStatus,ConversionStatus,EncryptionMethod | ConvertTo-Json"

// SavedDisksFile is where the answer is kept, in the state folder.
func SavedDisksFile(stateDir string) string { return filepath.Join(stateDir, "security", "disk.json") }

// ParseBitLocker reads what BitLockerQuery prints: one object, or a list
// of them.
func ParseBitLocker(out []byte) ([]BitLockerVolume, error) {
	out = bytes.TrimSpace(out)
	out = bytes.TrimPrefix(out, []byte("\xef\xbb\xbf"))
	if len(out) == 0 {
		return nil, errors.New("BitLocker gave no answer")
	}
	type row struct {
		DriveLetter      *string
		ProtectionStatus int
		ConversionStatus int
		EncryptionMethod int
	}
	var rows []row
	if out[0] == '{' {
		var r row
		if err := json.Unmarshal(out, &r); err != nil {
			return nil, err
		}
		rows = []row{r}
	} else if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	var vols []BitLockerVolume
	for _, r := range rows {
		if r.DriveLetter == nil || *r.DriveLetter == "" {
			continue
		}
		vols = append(vols, BitLockerVolume{Drive: strings.ToUpper(*r.DriveLetter), Protection: r.ProtectionStatus,
			Conversion: r.ConversionStatus, Method: r.EncryptionMethod})
	}
	return vols, nil
}

// SaveDisks keeps an answer for the server, readable only by Signalith
// and administrators.
func SaveDisks(stateDir string, s SavedDisks) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := securefile.MkdirPrivate(filepath.Dir(SavedDisksFile(stateDir))); err != nil {
		return err
	}
	return securefile.WriteFile(SavedDisksFile(stateDir), data)
}

// LoadDisks reads a saved answer, or nil when there is none.
func LoadDisks(stateDir string) *SavedDisks {
	data, err := os.ReadFile(SavedDisksFile(stateDir))
	if err != nil {
		return nil
	}
	var s SavedDisks
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	return &s
}

// bitLockerDisk describes the drive of path from a saved answer.
func bitLockerDisk(p string, saved *SavedDisks, now time.Time, vm vmInfo) Disk {
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		return Disk{Path: p, Kind: DiskNetwork, Source: windowsShare(p)}
	}
	drive := ""
	if len(p) >= 2 && p[1] == ':' && ('a' <= p[0] && p[0] <= 'z' || 'A' <= p[0] && p[0] <= 'Z') {
		drive = strings.ToUpper(p[:2])
	}
	d := Disk{Path: p, Drive: drive, Kind: DiskWindows}
	if saved == nil || now.Sub(saved.CheckedAt) > SavedDisksMaxAge {
		return d
	}
	for _, v := range saved.Volumes {
		if !strings.EqualFold(v.Drive, drive) {
			continue
		}
		d.CheckedAt = saved.CheckedAt
		switch {
		case v.Protection == 1:
			d.Kind, d.Method = DiskEncrypted, "BitLocker"
		case v.Conversion == 1 || v.Conversion == 4:
			// Encrypted, with its protection suspended.
			d.Kind, d.Method, d.Suspended = DiskEncrypted, "BitLocker", true
		case vm.Virtual:
			d.Kind, d.Provider = DiskVirtual, vm.Provider
		default:
			d.Kind = DiskPlain
		}
		return d
	}
	return d
}

// windowsShare is the \\server\share part of a network path. It is read
// by hand, not with filepath, so that it is the same on every system.
func windowsShare(p string) string {
	parts := strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' })
	if len(parts) < 2 {
		return p
	}
	return `\\` + parts[0] + `\` + parts[1]
}
