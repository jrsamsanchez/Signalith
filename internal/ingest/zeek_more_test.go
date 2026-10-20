// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"testing"
)

func TestZeekSSH(t *testing.T) {
	d := zeekDocs(t, "ssh")
	expect(t, d[0], map[string]any{
		"datamodel": "Authentication", "app": "ssh", "action": "failure", "signature": "SSH sign-in",
		"src": "203.0.113.50", "src_port": int64(51012), "dest": "192.168.10.5", "dest_port": int64(22),
		"direction": "inbound", "session_id": "CsshFail1aBcDeFgH", "user": nil,
		// Zeek's own keys stay, for Sigma's Zeek rules and searches.
		"zeek_auth_attempts": int64(3), "zeek_client": "SSH-2.0-libssh2_1.10.0", "zeek_direction": "INBOUND",
	})
	expect(t, d[1], map[string]any{"action": "success", "direction": "internal"})
	// No auth_success: Zeek could not tell.
	expect(t, d[2], map[string]any{"action": "unknown"})
}

func TestZeekRDP(t *testing.T) {
	d := zeekDocs(t, "rdp")
	expect(t, d[0], map[string]any{
		"datamodel": "Authentication", "app": "rdp", "action": "unknown", "user": "jsmith", "src_host": "WS-0042",
		"authentication_method": "HYBRID", "reason": "encrypted", "dest": "192.168.10.30", "dest_port": int64(3389),
		"zeek_cookie": "jsmith",
	})
	// A negotiation the server refused: the client chose the cookie and
	// never signed in, so it is no failed sign-in for that user.
	expect(t, d[1], map[string]any{"action": "unknown", "user": "administr", "reason": "HYBRID_REQUIRED_BY_SERVER", "direction": "inbound"})
}

func TestZeekKerberos(t *testing.T) {
	d := zeekDocs(t, "kerberos")
	expect(t, d[0], map[string]any{
		"datamodel": "Authentication", "app": "kerberos", "action": "failure", "user": "jsmith", "user_domain": "CORP.EXAMPLE",
		"kerberos_service": "krbtgt/CORP.EXAMPLE", "reason": "KDC_ERR_PREAUTH_FAILED", "signature": "Kerberos AS",
		"ticket_encryption_type": "aes256-cts-hmac-sha1-96", "authentication_method": "kerberos", "dest": "192.168.10.2",
	})
	// Asked to pre-authenticate: the usual first step, not a failure.
	expect(t, d[1], map[string]any{"action": "unknown", "reason": "KDC_ERR_PREAUTH_REQUIRED"})
	expect(t, d[2], map[string]any{"action": "success", "signature": "Kerberos TGS", "kerberos_service": "cifs/file-01.corp.example",
		"zeek_cipher": "rc4-hmac", "zeek_request_type": "TGS"})
	// A service with no SPN is not about the client's credentials.
	expect(t, d[3], map[string]any{"action": "unknown", "reason": "KDC_ERR_S_PRINCIPAL_UNKNOWN", "kerberos_service": "http/old-app.corp.example"})
}

func TestZeekNTLM(t *testing.T) {
	d := zeekDocs(t, "ntlm")
	expect(t, d[0], map[string]any{
		"datamodel": "Authentication", "app": "ntlm", "action": "success", "user": "jsmith", "user_domain": "CORP",
		"src_host": "WS-0042", "dest_host": "file-01.corp.example", "zeek_hostname": "WS-0042",
		// The client's name is never the sensor's.
		"host": "nsm-01",
	})
	expect(t, d[1], map[string]any{"action": "failure", "user": "administrator", "src_host": "kali", "dest_host": "FILE-01"})
	expect(t, d[2], map[string]any{"action": "failure", "user": nil, "user_domain": nil, "src_host": nil, "reason": "STATUS_LOGON_FAILURE"})
}

func TestZeekSMBFiles(t *testing.T) {
	d := zeekDocs(t, "smb_files")
	expect(t, d[0], map[string]any{
		"datamodel": "Filesystem", "action": "modified", "app": "smb", "file_name": "budget.xlsx",
		"file_path": `\\FILE-01\Finance\Q3\budget.xlsx`, "share_name": `\\FILE-01\Finance`, "share_target": `Q3\budget.xlsx`,
		"file_size": int64(48211), "src": "192.168.10.21", "dest": "192.168.10.5", "zeek_fuid": "FsmbWr1aBcDeFgHiJ",
		"zeek_name": `Q3\budget.xlsx`, "zeek_path": `\\FILE-01\Finance`,
	})
	expect(t, d[1], map[string]any{"action": "opened", "pipe_name": "atsvc", "file_path": nil, "share_name": `\\FILE-01\IPC$`})
	expect(t, d[2], map[string]any{"action": "deleted", "file_path": `\\FILE-01\Finance\old.txt`})
	// Long values are cut to what a keyword indexes.
	long := strings.Repeat("a", 9000)
	f := ParseZeek("smb_files", map[string]any{"ts": 1791720600.0, "action": "SMB::FILE_OPEN", "path": `\\X\` + long, "name": long}, "").Fields
	for _, k := range []string{"share_name", "share_target", "file_path", "file_name"} {
		if v, _ := f[k].(string); len(v) > MaxValueLen {
			t.Errorf("%s is %d bytes", k, len(v))
		}
	}

	m := zeekDocs(t, "smb_mapping")[0]
	expect(t, m, map[string]any{"datamodel": "Other", "share_name": `\\FILE-01\Finance`, "signature": "SMB share connected"})
}

func TestZeekInventoryLogs(t *testing.T) {
	expect(t, zeekDocs(t, "known_hosts")[0], map[string]any{"datamodel": "Other", "signature": "Host seen", "dest": "192.168.10.21", "zeek_host": "192.168.10.21"})
	expect(t, zeekDocs(t, "known_services")[0], map[string]any{"signature": "Service seen", "dest": "192.168.10.5", "dest_port": int64(445),
		"transport": "tcp", "app": "smb"})
	expect(t, zeekDocs(t, "software")[0], map[string]any{"signature": "Software seen", "dest": "192.168.10.5", "dest_port": int64(22),
		"zeek_name": "OpenSSH", "zeek_software_type": "SSH::SERVER"})
	expect(t, zeekDocs(t, "dhcp")[0], map[string]any{"signature": "DHCP lease", "src": "192.168.10.21", "dest": "192.168.10.1",
		"src_mac": "00:50:56:aa:bb:01", "src_host": "ws-0042.corp.example", "session_id": "CdhcpAbCdEfGhIjKl"})
	// No address assigned (a DHCPINFORM): the client's own address is
	// whatever it says, so the name is tied to no address.
	expect(t, zeekDocs(t, "dhcp")[1], map[string]any{"src": nil, "src_host": "file-01"})
	// A host that is not an address is not taken as one.
	f := ParseZeek("known_hosts", map[string]any{"ts": 1791720600.0, "host": "$(rm -rf /)"}, "").Fields
	if f["dest"] != nil {
		t.Errorf("dest = %v", f["dest"])
	}
}

func TestZeekGenericFieldOfMappedLogs(t *testing.T) {
	// Sigma's Zeek rules for these logs name Zeek's keys, kept as zeek_*.
	for _, c := range [][3]string{
		{"kerberos", "cipher", "zeek_cipher"}, {"smb_files", "name", "zeek_name"}, {"rdp", "cookie", "zeek_cookie"},
		{"ntlm", "hostname", "zeek_hostname"}, {"ssh", "id.resp_h", "dest"}, {"conn", "proto", ""},
	} {
		if got := ZeekGenericField(c[0], c[1]); got != c[2] {
			t.Errorf("ZeekGenericField(%s, %s) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}
