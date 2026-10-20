// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"fmt"
	"strconv"
	"time"
)

// These are the typed event builders the background and attack generators
// use. Each fills the StringInserts positions (Windows) or Key: Value lines
// (Sysmon) exactly where the ingest parsers read them, so the normalised
// fields match what a real agent would produce.

// winInserts returns a StringInserts slice large enough for every Security
// event the sample emits, with positions set from the given pairs.
func winInserts(set map[int]string) []string {
	max := 0
	for i := range set {
		if i > max {
			max = i
		}
	}
	out := make([]string, max+1)
	for i, v := range set {
		out[i] = v
	}
	return out
}

// logonWin writes a 4624 successful interactive logon.
func (g *gen) logonWin(h Host, u User, t time.Time, src, srcHost string, logonType int) {
	in := winInserts(map[int]string{
		5:  u.Login,
		6:  NetBIOS,
		8:  strconv.Itoa(logonType),
		10: "Negotiate",
		11: srcHost,
		18: src,
		19: strconv.Itoa(40000 + g.rng.intn(20000)),
	})
	g.b.win(h, "4624", t, "An account was successfully logged on.", in...)
}

// logonFailWin writes a 4625 failed logon with a reason (sub-status) code.
func (g *gen) logonFailWin(h Host, login string, t time.Time, src, srcHost, subStatus string, logonType int) {
	in := winInserts(map[int]string{
		5:  login,
		6:  NetBIOS,
		7:  "0xc000006d",
		9:  subStatus,
		10: strconv.Itoa(logonType),
		12: "Negotiate",
		13: srcHost,
		19: src,
		20: strconv.Itoa(40000 + g.rng.intn(20000)),
	})
	g.b.win(h, "4625", t, "An account failed to log on.", in...)
}

// procWin writes a 4688 process-creation event (plain user name).
func (g *gen) procWin(h Host, login, image, cmdline, parentImage string, t time.Time) {
	in := winInserts(map[int]string{
		1:  login,
		2:  NetBIOS,
		4:  fmt.Sprintf("0x%x", 1000+g.rng.intn(60000)),
		5:  image,
		8:  cmdline,
		13: parentImage,
	})
	g.b.win(h, "4688", t, "A new process has been created.", in...)
}

// sysmonProc writes a Sysmon event 1 (process create). winuser is kept in
// DOMAIN\user form so a person's risk adds up across Sysmon and Security.
func (g *gen) sysmonProc(h Host, winuser, image, cmdline, parentImage, parentCmd, hashes string, t time.Time) {
	kv := [][2]string{
		{"Image", image},
		{"CommandLine", cmdline},
		{"User", winuser},
		{"ProcessId", strconv.Itoa(1000 + g.rng.intn(60000))},
	}
	if hashes != "" {
		kv = append(kv, [2]string{"Hashes", hashes})
	}
	kv = append(kv,
		[2]string{"ParentImage", parentImage},
		[2]string{"ParentCommandLine", parentCmd},
	)
	g.b.sysmon(h, "1", t, kv)
}

// sysmonNet writes a Sysmon event 3 (network connection).
func (g *gen) sysmonNet(h Host, winuser, src string, srcPort int, dest, destHost string, destPort int, proto, image string, t time.Time) {
	kv := [][2]string{
		{"User", winuser},
		{"Protocol", proto},
		{"SourceIp", src},
		{"SourcePort", strconv.Itoa(srcPort)},
		{"DestinationIp", dest},
		{"DestinationHostname", destHost},
		{"DestinationPort", strconv.Itoa(destPort)},
		{"Image", image},
	}
	g.b.sysmon(h, "3", t, kv)
}

// sshLogin writes an SSH logon line (Accepted or Failed).
func (g *gen) sshLogin(h Host, user, src string, srcPort int, t time.Time, ok, invalid bool) {
	verb := "Accepted"
	if !ok {
		verb = "Failed"
	}
	who := user
	if invalid {
		who = "invalid user " + user
	}
	msg := fmt.Sprintf("%s password for %s from %s port %d ssh2", verb, who, src, srcPort)
	g.b.syslogLine(h, "sshd", strconv.Itoa(1000+g.rng.intn(60000)), msg, t)
}

// sudoRun writes a successful sudo command line.
func (g *gen) sudoRun(h Host, srcUser, target, command string, t time.Time) {
	msg := fmt.Sprintf("  %s : TTY=pts/0 ; PWD=/home/%s ; USER=%s ; COMMAND=%s", srcUser, srcUser, target, command)
	g.b.syslogLine(h, "sudo", strconv.Itoa(1000+g.rng.intn(60000)), msg, t)
}

// sudoFail writes a sudo authentication failure (one incorrect attempt).
func (g *gen) sudoFail(h Host, srcUser string, t time.Time) {
	msg := fmt.Sprintf("pam_unix(sudo:auth): authentication failure; logname=%s uid=1000 euid=0 tty=/dev/pts/0 ruser=%s rhost= user=%s", srcUser, srcUser, srcUser)
	g.b.syslogLine(h, "sudo", strconv.Itoa(1000+g.rng.intn(60000)), msg, t)
}

// accountCreatedWin writes a 4720 user-account creation (creator = by).
func (g *gen) accountCreatedWin(h Host, account, by string, t time.Time) {
	in := winInserts(map[int]string{0: account, 4: by})
	g.b.win(h, "4720", t, "A user account was created.", in...)
}

// accountDeletedWin writes a 4726 user-account deletion.
func (g *gen) accountDeletedWin(h Host, account, by string, t time.Time) {
	in := winInserts(map[int]string{0: account, 4: by})
	g.b.win(h, "4726", t, "A user account was deleted.", in...)
}

// groupAddWin writes a 4732 add-member-to-group (member, group, by).
func (g *gen) groupAddWin(h Host, member, group, by string, t time.Time) {
	in := winInserts(map[int]string{0: member, 2: group, 6: by})
	g.b.win(h, "4732", t, "A member was added to a security-enabled local group.", in...)
}
