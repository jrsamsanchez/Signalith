package ingest

import (
	"testing"
	"time"
)

func TestAuditd(t *testing.T) {
	audit := func(line string) map[string]any {
		return Normalize("linux.audit", map[string]any{"log": line, "hostname": "web1"}, now).Document()
	}
	// A raw EXECVE record: quoted arguments as they are, an argument with
	// a space in hex.
	doc := audit(`type=EXECVE msg=audit(1760443200.123:4711): argc=3 a0="chmod" a1="u+s" a2=2F746D702F6D7920736800`)
	expect(t, doc, map[string]any{
		"datamodel": "Other", "sourcetype": "linux:audit", "host": "web1", "auditd_type": "EXECVE", "signature": "EXECVE",
		"auditd_id": "4711", "auditd_a0": "chmod", "auditd_a1": "u+s", "auditd_a2": "/tmp/my sh",
		"auditd_execve_command": "chmod u+s /tmp/my sh", "process": "chmod u+s /tmp/my sh",
	})
	if got := doc["@timestamp"]; got != time.Unix(1760443200, 123e6).UTC().Format(time.RFC3339Nano) {
		t.Errorf("@timestamp = %v", got)
	}
	// An ENRICHED SYSCALL record: numbers, then their names after 0x1d.
	expect(t, audit("type=SYSCALL msg=audit(1760443200.123:4711): arch=c000003e syscall=59 success=yes exit=0 a0=55d5 ppid=900 pid=901 auid=1000 uid=0 euid=0 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"exec\"\x1dARCH=x86_64 SYSCALL=execve AUID=\"bob\" UID=\"root\" EUID=\"root\""), map[string]any{
		"auditd_syscall": "59", "auditd_syscall_name": "execve", "auditd_uid": "0", "auditd_uid_name": "root",
		"auditd_auid_name": "bob", "user": "bob", "auditd_a0": "55d5", "auditd_key": "exec", "auditd_comm": "chmod",
		"process_path": "/usr/bin/chmod", "process_name": "chmod", "process_id": int64(901), "parent_process_id": int64(900),
	})
	// A command line in hex, its arguments split by zero bytes.
	expect(t, audit(`type=PROCTITLE msg=audit(1760443200.123:4711): proctitle=7375646F0063686F776E00726F6F74`), map[string]any{
		"auditd_proctitle": "sudo chown root", "process": "sudo chown root",
	})
	// A user-space record's own fields, one with spaces.
	expect(t, audit(`type=SERVICE_STOP msg=audit(1760443200.500:4712): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=auditd comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'`), map[string]any{
		"auditd_type": "SERVICE_STOP", "auditd_unit": "auditd", "auditd_comm": "systemd", "auditd_res": "success",
	})
	expect(t, audit(`type=ADD_USER msg=audit(1760443200.600:4713): pid=2 uid=0 auid=1000 ses=3 msg='op=adding user id=1001 exe="/usr/sbin/useradd" acct="eve" res=success'`), map[string]any{
		"auditd_op": "adding user", "auditd_acct": "eve", "auditd_exe": "/usr/sbin/useradd",
	})
	// A long argument comes in pieces.
	expect(t, audit(`type=EXECVE msg=audit(1760443200.700:4714): argc=2 a0="bash" a1_len=6 a1[0]="-c " a1[1]="id"`), map[string]any{
		"auditd_a1": "-c id", "auditd_execve_command": "bash -c id",
	})
	// ausearch -i output: already readable, with names for numbers.
	expect(t, audit(`type=SYSCALL msg=audit(04/16/2025 08:20:23.552:47372) : arch=x86_64 syscall=execve success=yes exit=0 ppid=5153 pid=6324 auid=ubuntu uid=ubuntu comm=whoami exe=/usr/bin/whoami key=recon`), map[string]any{
		"auditd_syscall": "execve", "auditd_uid": "ubuntu", "auditd_comm": "whoami", "auditd_key": "recon", "user": "ubuntu",
		"auditd_id": "47372",
	})
	expect(t, audit(`type=PATH msg=audit(04/16/2025 08:20:23.552:47372) : item=0 name=cafe nametype=CREATE`), map[string]any{
		"auditd_name": "cafe", "auditd_nametype": "CREATE",
	})
	expect(t, audit(`type=PROCTITLE msg=audit(02/20/2025 10:00:25.563:44654) : proctitle=dd if=/dev/zero of=/dev/sda bs=1M`), map[string]any{
		"auditd_proctitle": "dd if=/dev/zero of=/dev/sda bs=1M",
	})
	// Lines built for test events read back as written.
	for _, fields := range []map[string]string{
		{"argc": "3", "a0": "sh", "a1": "-c", "a2": `echo "hi there"`},
		{"syscall": "59", "exe": "/usr/bin/id", "comm": "id", "key": "exec", "SYSCALL": "execve", "UID": "root"},
		{"proctitle": "sudo chown root x"},
	} {
		typ := "SYSCALL"
		if fields["argc"] != "" {
			typ = "EXECVE"
		} else if fields["proctitle"] != "" {
			typ = "PROCTITLE"
		}
		line := AuditdLine(typ, now, fields)
		rec, ok := ReadAuditd(line)
		if !ok || rec.Type != typ {
			t.Fatalf("%q: %v %+v", line, ok, rec)
		}
		for k, v := range fields {
			if rec.Fields[k] != v {
				t.Errorf("%q: %s = %q, want %q", line, k, rec.Fields[k], v)
			}
		}
	}
	// Audit records forwarded to syslog by auditd's syslog plugin.
	expect(t, Normalize("syslog", map[string]any{"log": `Oct 14 10:00:00 db2 audisp-syslog: node=db2 type=EXECVE msg=audit(1760443200.123:9): argc=1 a0="id"`}, now).Document(), map[string]any{
		"sourcetype": "linux:audit", "host": "db2", "auditd_execve_command": "id",
	})
	// Not an audit record.
	expect(t, audit("hello"), map[string]any{"datamodel": "Other", "sourcetype": "linux:audit", "message": "hello"})
}
