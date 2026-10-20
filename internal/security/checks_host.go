// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"path/filepath"
	"strings"
)

// checkAccount: host.account.
func checkAccount(f *Facts) *Check {
	p := f.Process
	if !p.Known {
		return &Check{State: Unknown, Line: processWhy(p), Fix: processFix(p)}
	}
	if f.Server.OS == "windows" {
		fix := &Fix{Steps: []string{"Run install.ps1 from this version again, in an elevated PowerShell. It moves the service to its own account."}, Docs: doc(docReadmeWindows)}
		switch {
		case p.SID == "S-1-5-18":
			return &Check{State: Attention, Line: "Signalith runs as Local System, the most powerful account on Windows.", Fix: fix}
		case strings.HasPrefix(p.SID, "S-1-5-80-"):
			return &Check{State: Good, Line: "Signalith runs as its own service account (NT SERVICE\\Signalith)."}
		case p.Elevated:
			return &Check{State: Attention, Line: "Signalith runs as " + p.UserName + ", an administrator.", Fix: fix}
		case p.AdminUnknown:
			return &Check{State: Unknown, Line: "Signalith runs as " + p.UserName + ". Signalith couldn't tell whether that account is an administrator.",
				Fix: &Fix{Steps: []string{"Check whether " + p.UserName + " is in the Administrators group. If it is, run install.ps1 from this version again, in an elevated PowerShell. It moves the service to its own account."},
					Commands: cmds("", "net localgroup Administrators", ""), Docs: doc(docReadmeWindows)}}
		}
		return &Check{State: Good, Line: "Signalith runs as " + p.UserName + ", without administrator rights."}
	}
	switch {
	case p.Root && f.InContainer:
		return &Check{State: Attention, Line: "Signalith runs as root inside its container.",
			Fix: &Fix{Steps: []string{"Remove the user: line that overrides the image's account in your compose file; the image runs as uid 65532."}, Docs: doc(docReadmeDocker)}}
	case p.Root:
		return &Check{State: Attention, Line: "Signalith runs as root, so a flaw in it could reach the whole computer.", Fix: &Fix{
			Steps: []string{"Run Signalith as its own account, with the systemd unit from this version."},
			Commands: cmds("sudo useradd --system --no-create-home signalith\n"+
				"sudo chown -R signalith /etc/signalith /var/lib/signalith\n"+
				"sudo cp deploy/systemd/signalith.service /etc/systemd/system/\n"+
				"sudo systemctl daemon-reload && sudo systemctl restart signalith", "", ""),
			Docs: doc(docReadmeLinux)}}
	case f.InContainer:
		return &Check{State: Good, Line: "Signalith runs as an unprivileged account (uid " + itoa(p.UID) + ") in its container."}
	}
	name := p.UserName
	if name == "" {
		name = "uid " + itoa(p.UID)
	}
	return &Check{State: Good, Line: "Signalith runs as its own account (" + name + "), not as root."}
}

// processFix says how to check the process when it couldn't be read.
func processFix(p ProcessFacts) *Fix {
	if p.Why == NoServiceLine {
		return noServiceFix()
	}
	return nil
}

func processWhy(p ProcessFacts) string {
	if p.Why != "" {
		return p.Why
	}
	return "Signalith couldn't read how its process runs."
}

// checkService: host.service, on Linux.
func checkService(f *Facts) *Check {
	if f.Server.OS != "linux" {
		return nil
	}
	p := f.Process
	if !p.Known {
		return &Check{State: Unknown, Line: processWhy(p), Fix: processFix(p)}
	}
	unitFix := &Fix{Steps: []string{"Install the current unit and restart. If you changed the unit on purpose, compare it with systemctl cat signalith."},
		Commands: cmds("sudo cp deploy/systemd/signalith.service /etc/systemd/system/\n"+
			"sudo systemctl daemon-reload && sudo systemctl restart signalith\n"+
			"systemd-analyze security signalith", "", ""),
		Docs: doc(docReadmeLinux)}
	var missing []string
	add := func(ok bool, name string) {
		if !ok {
			missing = append(missing, name)
		}
	}
	switch {
	case f.InContainer:
		add(p.NoNewPrivs, "no new privileges")
		add(p.NoCapsAtAll, "no capabilities")
		add(p.ReadOnlyRoot, "a read-only system")
		add(f.Memory.CoreOff || !f.Memory.Known, "no crash dumps")
		if len(missing) > 0 {
			return &Check{State: Attention, Line: "Signalith's container is missing protections from the quick start: " + joinAnd(missing) + ".",
				Fix: &Fix{Steps: []string{"Keep read_only: true, cap_drop: [ALL], security_opt: [no-new-privileges:true] and ulimits core: 0 for the signalith service in docker-compose.yml."},
					Docs: doc(docReadmeDocker)}}
		}
		return &Check{State: Good, Line: "Signalith's container runs read-only, without extra privileges or capabilities."}
	case !p.Systemd:
		return &Check{State: Attention, Line: "Signalith isn't running as a systemd service, so it lacks the protections the service adds.", Fix: unitFix}
	}
	add(p.NoNewPrivs, "no new privileges")
	add(p.Seccomp, "a system-call filter")
	add(p.NoCaps, "no extra capabilities")
	add(p.ReadOnlyRoot, "a read-only system")
	// systemd hides other processes (ProtectProc=invisible) only on Linux
	// 5.8 or newer; on older ones the unit can't, so it isn't missing.
	var details []string
	if p.NoHiddenProc && !p.HiddenProc {
		details = append(details, "Hidden processes: not available on this Linux version.")
	} else {
		add(p.HiddenProc, "hidden processes")
	}
	add(p.PrivateDev, "private /dev")
	add(p.Umask077, "private new files")
	if len(missing) > 0 {
		return &Check{State: Attention, Line: "Signalith's service is missing protections its current systemd unit sets up: " + joinAnd(missing) + ".", Details: details, Fix: unitFix}
	}
	return &Check{State: Good, Line: "Signalith's service runs with all the protections its systemd unit sets up.", Details: details}
}

// filePermCommands make files and folders Signalith's own: one command
// per problem, or one for the whole state folder. They name this
// server's paths, so only its own system's are kept.
func filePermCommands(f *Facts, probs []FileProblem, stateDir string) map[string]string {
	var linux, windows, docker []string
	for _, p := range probs {
		dir := p.Kind == "folder"
		switch {
		case p.Read:
			linux = append(linux, "sudo chmod go-rwx "+sh(p.Path))
		default:
			linux = append(linux, "sudo chmod go-w "+sh(p.Path))
		}
		svc := "F"
		if p.Kind == "config" {
			svc = "R"
		}
		if dir {
			windows = append(windows, icaclsDir(p.Path, "M"))
		} else {
			windows = append(windows, icaclsFile(p.Path, svc))
		}
		if inVolume(p.Path) != "" && f.Docker && len(docker) == 0 {
			docker = append(docker, busybox("chmod -R go-rwx /data"))
		}
	}
	if len(linux) > 3 && stateDir != "" {
		linux = []string{"sudo chmod -R go-rwx " + sh(stateDir)}
	}
	return ownOnly(f, cmds(strings.Join(linux, "\n"), strings.Join(windows, "\n"), strings.Join(docker, "\n")))
}

// checkFiles: host.files.
func checkFiles(f *Facts) *Check {
	fs := f.Files
	if !fs.Known {
		return &Check{State: Unknown, Line: "Signalith couldn't read who may use its files.",
			Fix: &Fix{Steps: []string{"Check that only Signalith's account can read its state folder."}, Docs: doc(docSecFiles)}}
	}
	stateDir := ""
	if f.Config != nil {
		stateDir = f.Config.StateDir()
	}
	var risk, attention []FileProblem
	for _, p := range fs.Problems {
		switch {
		case p.Kind == "key" && p.Read && p.Everyone,
			(p.Kind == "config" || p.Kind == "folder") && p.Write && p.Everyone:
			risk = append(risk, p)
		default:
			attention = append(attention, p)
		}
	}
	fixFor := func(list []FileProblem) *Fix {
		steps := []string{"Make them readable and writable only by Signalith's account."}
		if f.Server.OS == "windows" {
			steps = append(steps, "For everything in C:\\ProgramData\\Signalith, run install.ps1 from this version again; it resets access there.")
		} else if f.Docker {
			steps = append(steps, "docker volume ls shows the volume's name.")
		}
		return &Fix{Steps: steps, Commands: filePermCommands(f, list, stateDir), Docs: doc(docSecFiles)}
	}
	var details []string
	if len(risk) > 0 {
		p := risk[0]
		verb := "read"
		if !p.Read {
			verb = "change"
		}
		for _, o := range append(risk[1:], attention...) {
			details = append(details, describeFile(o))
		}
		return &Check{State: Risk, Line: "Any account on this computer can " + verb + " " + p.Path + ".", Details: details, Fix: fixFor(append(risk, attention...))}
	}
	if len(attention) > 0 {
		var read, write []string
		for _, p := range attention {
			if p.Read {
				read = append(read, filepath.Base(p.Path))
			} else {
				write = append(write, p.Path)
			}
			details = append(details, describeFile(p))
		}
		line := ""
		switch {
		case len(read) > 0:
			n := len(read)
			line = "Other accounts can read " + itoa(n) + " of Signalith's private files: " + shorten(read, 5) + "."
			if n == 1 {
				line = "Other accounts can read one of Signalith's private files: " + read[0] + "."
			}
		default:
			line = "Other accounts can change " + write[0] + "."
		}
		return &Check{State: Attention, Line: line, Details: details, Fix: fixFor(attention)}
	}
	if fs.NetworkState != "" {
		return &Check{State: Attention, Line: "Signalith's state folder is on a network share (" + fs.NetworkState + "), so its keys cross the network each time they're read.",
			Fix: &Fix{Steps: []string{"Keep the state folder on a local disk (SIGNALITH_STATE_DIR)."}, Docs: doc(docServersIdentity)}}
	}
	who := "its own account"
	if fs.Admins {
		who += " and administrators"
	}
	return &Check{State: Good, Line: "Signalith's keys and private files can only be read by " + who + "."}
}

// describeFile says who may use a file, for details.
func describeFile(p FileProblem) string {
	who := "Other accounts"
	switch {
	case p.Everyone:
		who = "Any account"
	case p.Group != "":
		who = "The " + p.Group + " group"
	}
	verb := "read"
	if !p.Read {
		verb = "change"
	} else if p.Write {
		verb = "read and change"
	}
	return who + " can " + verb + " " + p.Path + "."
}
