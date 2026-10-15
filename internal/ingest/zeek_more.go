package ingest

import (
	"cmp"
	"net/netip"
	"strings"
)

// Zeek logs mapped onto a data model besides the zeek_<key> fields every
// unmapped log keeps (zeekGeneric): sign-ins seen on the wire (ssh, rdp,
// kerberos, ntlm) in Authentication, file activity on SMB shares in
// Filesystem, and the hosts, services and software Zeek learns about
// (known_hosts, known_services, software, dhcp), which feed the asset
// list's discovered hosts (see assets.ParseDiscovery).

// zeekAuthApps are the app of each sign-in log: the protocol, so a
// search tells them from a host's own sshd or Windows logons.
var zeekAuthApps = map[string]string{"ssh": "ssh", "rdp": "rdp", "kerberos": "kerberos", "ntlm": "ntlm"}

// zeekAuth maps ssh, rdp, kerberos and ntlm onto Authentication: src
// signed in to dest. action is success or failure where Zeek can tell,
// and unknown where it cannot (an encrypted RDP sign-in, an SSH
// connection whose outcome Zeek could not guess, a Kerberos request
// that is only asked to pre-authenticate), so the brute force
// detections count real failures only.
func zeekAuth(lt string, r, f map[string]any) {
	f["app"] = zeekAuthApps[lt]
	f["action"] = "unknown"
	switch lt {
	case "ssh":
		f["signature"] = "SSH sign-in"
		if ok, known := zeekBool(wstr(r["auth_success"])); known {
			f["action"] = outcome(ok)
		}
	case "rdp":
		// The cookie is the user name the client offered (mstshash),
		// which Windows clients cut to 9 characters. With network level
		// authentication (HYBRID) the sign-in itself is encrypted: result
		// says only whether the connection was set up.
		f["signature"] = "RDP sign-in"
		setUser(f, wstr(r["cookie"]))
		setStr(f, "authentication_method", r["security_protocol"])
		setHostName(f, "src_host", wstr(r["client_name"]))
		setStr(f, "reason", r["result"])
		if res := strings.ToLower(wstr(r["result"])); res != "" && res != "success" && res != "unknown" {
			f["action"] = "failure"
		}
	case "kerberos":
		req := strings.ToUpper(wstr(r["request_type"]))
		f["signature"] = "Kerberos " + cmp.Or(req, "request")
		f["authentication_method"] = "kerberos"
		user, realm, _ := strings.Cut(wstr(r["client"]), "/")
		setUser(f, user)
		if realm != "" && len(realm) <= 255 {
			f["user_domain"] = realm
		}
		setStr(f, "kerberos_service", r["service"])
		setStr(f, "ticket_encryption_type", r["cipher"])
		msg := wstr(r["error_msg"])
		setStr(f, "reason", msg)
		if ok, known := zeekBool(wstr(r["success"])); known {
			switch {
			case ok:
				f["action"] = "success"
			case msg == "KDC_ERR_PREAUTH_REQUIRED":
				// The first step of every AS exchange: the KDC asks the
				// client to pre-authenticate. Not a failed sign-in.
			default:
				f["action"] = "failure"
			}
		}
	case "ntlm":
		f["signature"] = "NTLM sign-in"
		f["authentication_method"] = "ntlm"
		setUser(f, wstr(r["username"]))
		if d := strings.TrimSpace(wstr(r["domainname"])); d != "" && len(d) <= 255 {
			f["user_domain"] = d
		}
		// The workstation name the client sent, and the server's own name.
		setHostName(f, "src_host", wstr(r["hostname"]))
		setHostName(f, "dest_host", cmp.Or(wstr(r["server_dns_computer_name"]), wstr(r["server_nb_computer_name"])))
		if ok, known := zeekBool(wstr(r["success"])); known {
			f["action"] = outcome(ok)
		} else if st := strings.ToUpper(wstr(r["status"])); st != "" {
			// Before Zeek 3, ntlm.log had a status instead.
			f["action"] = outcome(st == "SUCCESS")
			f["reason"] = st
		}
	}
}

func outcome(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}

// setUser sets user when the name is one: not empty, "-" or longer than
// a user name can be.
func setUser(f map[string]any, u string) {
	u = strings.TrimSpace(u)
	if u == "" || u == "-" || len(u) > 256 {
		return
	}
	f["user"] = u
}

// setHostName sets a host name field when the value looks like one: a
// name the client chose, so nothing with spaces or control characters.
func setHostName(f map[string]any, k, h string) {
	h = strings.TrimSpace(h)
	if h == "" || h == "-" || len(h) > 255 || strings.ContainsFunc(h, func(c rune) bool { return c <= ' ' || c == 0x7f }) {
		return
	}
	f[k] = h
}

// zeekSMBActions maps smb_files.log's actions onto Filesystem's.
var zeekSMBActions = map[string]string{
	"FILE_READ": "read", "FILE_WRITE": "modified", "FILE_OPEN": "opened", "FILE_CLOSE": "closed",
	"FILE_DELETE": "deleted", "FILE_RENAME": "renamed", "FILE_SET_ATTRIBUTE": "modified",
	"PIPE_READ": "read", "PIPE_WRITE": "modified", "PIPE_OPEN": "opened", "PIPE_CLOSE": "closed",
	"PRINT_READ": "read", "PRINT_WRITE": "modified", "PRINT_OPEN": "opened", "PRINT_CLOSE": "closed",
}

// zeekSMBFiles maps smb_files.log (a file or named pipe used on an SMB
// share) onto Filesystem: src is the client, dest the file server.
// share_name is the share (\\FILE-01\Finance) and share_target the path
// inside it, as on a Windows share access (Security 5145).
func zeekSMBFiles(r, f map[string]any) {
	f["signature"] = "SMB file access"
	f["app"] = "smb"
	act := strings.TrimPrefix(wstr(r["action"]), "SMB::")
	if a, ok := zeekSMBActions[act]; ok {
		f["action"] = a
	} else if act != "" {
		f["action"] = strings.ToLower(act)
	}
	share := wstr(r["path"])
	name := wstr(r["name"])
	setStr(f, "share_name", share)
	setStr(f, "share_target", name)
	if name != "" {
		base := name
		if i := strings.LastIndexAny(base, `\/`); i >= 0 {
			base = base[i+1:]
		}
		if base != "" {
			f["file_name"] = base
		}
		switch {
		case strings.HasPrefix(act, "PIPE_"):
			f["pipe_name"] = name
		case share != "":
			f["file_path"] = strings.TrimRight(share, `\`) + `\` + strings.TrimLeft(name, `\`)
		default:
			f["file_path"] = name
		}
	}
	setInt(f, "file_size", r["size"])
	setStr(f, "zeek_fuid", r["fuid"])
}

// zeekSMBMapping keeps smb_mapping.log (a share connected to) in Other,
// with the share as share_name.
func zeekSMBMapping(r, f map[string]any) {
	f["signature"] = "SMB share connected"
	f["app"] = "smb"
	setStr(f, "share_name", r["path"])
}

// zeekInventory keeps what Zeek learned about the hosts of your network
// in Other, with the host as dest (or, for a DHCP lease, as src, the
// client), so the asset list can find them.
func zeekInventory(lt string, r, f map[string]any) {
	switch lt {
	case "known_hosts":
		f["signature"] = "Host seen"
		setAddr(f, "dest", r["host"])
	case "known_services":
		f["signature"] = "Service seen"
		setAddr(f, "dest", r["host"])
		setInt(f, "dest_port", r["port_num"])
		setStr(f, "transport", r["port_proto"])
		if svc := strings.ToLower(wstr(listFirst(r["service"]))); svc != "" && len(svc) <= 64 {
			f["app"] = svc
		}
	case "software":
		f["signature"] = "Software seen"
		setAddr(f, "dest", r["host"])
		setInt(f, "dest_port", r["host_p"])
	case "dhcp":
		f["signature"] = "DHCP lease"
		if !setAddr(f, "src", r["assigned_addr"]) {
			setAddr(f, "src", r["client_addr"])
		}
		setAddr(f, "dest", r["server_addr"])
		setStr(f, "src_mac", r["mac"])
		setHostName(f, "src_host", cmp.Or(wstr(r["client_fqdn"]), wstr(r["host_name"])))
		if uids := sensorList(r["uids"]); len(uids) > 0 && f["session_id"] == nil {
			f["session_id"] = uids[0]
		}
	}
}

// setAddr sets an address field, in its short form, when v is an
// address; it reports whether it was.
func setAddr(f map[string]any, k string, v any) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(wstr(v)))
	if err != nil {
		return false
	}
	f[k] = a.Unmap().WithZone("").String()
	return true
}
