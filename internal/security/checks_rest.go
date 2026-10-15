package security

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// keyPermCommands make a key file Signalith's own, on this server's
// system only.
func keyPermCommands(f *Facts, p string) map[string]string {
	docker := ""
	if v := inVolume(p); v != "" && f.Docker {
		docker = busybox("chmod 600 " + sh(v))
	}
	return ownOnly(f, cmds("sudo chown signalith "+sh(p)+" && sudo chmod 600 "+sh(p), icaclsFile(p, "R"), docker))
}

// checkMasterKey: rest.master_key.
func checkMasterKey(f *Facts) *Check {
	k := f.Key
	src := k.Source
	if k.SourceErr != nil {
		if errors.Is(k.SourceErr, secrets.ErrNoKey) {
			if len(f.Secrets.Stored) > 0 {
				// Stored passwords and keys covers the plain values.
				return &Check{State: Good, Line: "There's no master key yet. Signalith makes one the first time it encrypts a password or key."}
			}
			return &Check{State: Good, Line: "No passwords or keys are stored yet, so there's no master key."}
		}
		return &Check{State: Unknown, Line: "Signalith couldn't read the master key (" + short(k.SourceErr.Error()) + ").",
			Fix: &Fix{Steps: []string{"signalith secrets status says where the master key is and why it can't be read."}, Docs: doc(docEncKey)}}
	}
	permFix := &Fix{Steps: []string{"Make the key file readable only by Signalith's account."}, Commands: keyPermCommands(f, src.Path), Docs: doc(docEncKey)}
	if f.Server.OS == "windows" {
		permFix.Steps = append(permFix.Steps, "Running install.ps1 from this version again also resets access to everything in C:\\ProgramData\\Signalith.")
	} else if inVolume(src.Path) != "" && f.Docker {
		permFix.Steps = append(permFix.Steps, "docker volume ls shows the volume's name.")
	}
	var probs []problem
	if p := k.Perm; p != nil {
		switch {
		case p.OtherRead:
			probs = append(probs, problem{Risk, "Any account on this computer can read the master key (" + src.Path + ").", permFix})
		case p.SomeRead:
			probs = append(probs, problem{Risk, "Other accounts on this computer can read the master key (" + src.Path + ").", permFix})
		}
	}
	if src.Kind == secrets.FromEnv {
		probs = append(probs, problem{Attention, "The master key is in the SIGNALITH_MASTER_KEY environment variable, which is easier to leak than a file.", &Fix{
			Steps: []string{"Put the key in a file only Signalith can read, and point SIGNALITH_MASTER_KEY_FILE at it."}, Docs: doc(docEncElsewhere)}})
	}
	if p := k.Perm; p != nil {
		if p.GroupRead {
			probs = append(probs, problem{Attention, "The " + p.Group + " group can read the master key (" + src.Path + ").", permFix})
		}
		if p.WrongOwner {
			probs = append(probs, problem{Attention, "The master key (" + src.Path + ") belongs to " + p.Owner + ", not to the account Signalith runs as.", permFix})
		}
	}
	if src.OldPath != "" {
		probs = append(probs, problem{Attention, "The previous master key is still kept, in " + src.OldPath + ".", &Fix{
			Steps:    []string{"Back up the current key, then remove the previous one."},
			Commands: signalithCommands(f, "secrets rotate-master -prune"),
			Docs:     doc(docEncChange)}})
	}
	for _, u := range k.Unused {
		probs = append(probs, problem{Attention, "There's an unused copy of a master key in " + u + ".", &Fix{
			Steps: []string{"Keep a backup of it if you might need it, then delete it."}, Docs: doc(docEncBackup)}})
	}
	if c := worst(probs); c != nil {
		return c
	}
	owner := "Signalith's account"
	if k.Perm != nil && k.Perm.Owner != "" {
		owner = k.Perm.Owner
	}
	switch {
	case src.Kind == secrets.FromCredential:
		return &Check{State: Good, Line: "The master key comes from a systemd credential, so only the Signalith service can read it."}
	case src.Kind == secrets.FromDefault && f.Server.OS == "windows":
		return &Check{State: Good, Line: "The master key is protected by Windows and works only on this computer."}
	case src.Kind == secrets.FromDefault && f.Docker:
		return &Check{State: Good, Line: "The master key is in the signalith-data volume, readable only by Signalith's account.",
			Tip: &Fix{Steps: []string{"Keep the key out of the volume as a Docker secret, so a backup of the volume doesn't hold the key next to what it protects."},
				Docs: doc(docEncDocker)}}
	case src.Kind == secrets.FromKeyFile && f.InContainer:
		return &Check{State: Good, Line: "The master key comes from a file given to the container (" + src.Path + ")."}
	}
	c := &Check{State: Good, Line: "The master key is in " + src.Path + ", and only " + owner + " can read it."}
	if f.Server.OS == "linux" && src.Kind == secrets.FromDefault && !f.InContainer {
		c.Tip = &Fix{Steps: []string{"Give the key to the service as a systemd credential, so it can live outside Signalith's folders."}, Docs: doc(docEncElsewhere)}
	}
	return c
}

// encryptCommands encrypt the plain values in Signalith's files.
func encryptCommands(f *Facts) map[string]string {
	c := signalithCommands(f, "secrets encrypt")
	c["docker"] += "\n" + "docker compose restart signalith"
	return c
}

// checkStoredSecrets: rest.stored_secrets.
func checkStoredSecrets(f *Facts) *Check {
	s := f.Secrets
	var plain, unreadable []string
	byFile := map[string]int{}
	previous, total := 0, len(s.Stored)
	for _, v := range s.Stored {
		name := v.Setting
		if v.Label != "" {
			name = v.Label
		}
		switch v.State {
		case secrets.Plain:
			plain = append(plain, name)
			byFile[v.File]++
		case secrets.Previous:
			previous++
		case secrets.Unreadable:
			unreadable = append(unreadable, name)
		}
	}
	encrypt := &Fix{Steps: []string{"Encrypt them with the master key."}, Commands: encryptCommands(f), Docs: doc(docEncWhat)}
	var probs []problem
	for _, file := range s.Exposed {
		n := byFile[file]
		if n == 0 {
			continue
		}
		fix := *encrypt
		fix.Steps = []string{"Encrypt them with the master key, and make the file readable only by Signalith's account."}
		fix.Commands = encryptCommands(f)
		for k, v := range filePermCommands(f, []FileProblem{{Path: file, Kind: "private", Read: true}}, "") {
			fix.Commands[k] += "\n" + v
		}
		probs = append(probs, problem{Risk, filepath.Base(file) + " holds " + itoa(n) + plural(n, " password or key", " passwords or keys") +
			" as plain text, and other accounts on this computer can read it.", &fix})
	}
	if n := len(plain); n > 0 {
		probs = append(probs, problem{Attention, itoa(n) + plural(n, " password or key is", " passwords or keys are") +
			" stored as plain text: " + shorten(plain, 5) + ".", encrypt})
	}
	for _, a := range s.Address {
		fix := &Fix{Steps: []string{"Move the password out of the address into its own setting, where it can be encrypted."}, Docs: doc(docEncNot)}
		if _, ok := config.Lookup(a); ok {
			fix.Setting = a
		}
		probs = append(probs, problem{Attention, a + " has a password written into its address, where it can't be encrypted.", fix})
	}
	if previous > 0 {
		probs = append(probs, problem{Attention, itoa(previous) + plural(previous, " value is", " values are") +
			" still encrypted with the previous master key.", encrypt})
	}
	if n := len(unreadable); n > 0 {
		probs = append(probs, problem{Attention, itoa(n) + plural(n, " value", " values") + " can't be decrypted with the master key in use: " +
			shorten(unreadable, 5) + ".", &Fix{Steps: []string{"Restore the master key they were encrypted with, or enter them again."}, Docs: doc(docEncLosing)}})
	}
	c := worst(probs)
	switch {
	case c != nil:
	case len(s.Errors) > 0:
		var files []string
		for p := range s.Errors {
			files = append(files, filepath.Base(p))
		}
		slices.Sort(files)
		c = &Check{State: Unknown, Line: "Signalith couldn't read " + joinAnd(files) + ", so it can't tell how the passwords and keys in " +
			plural(len(files), "it", "them") + " are kept.", Fix: &Fix{Steps: []string{"signalith secrets status lists what each file holds."}, Docs: doc(docEncWhat)}}
	case total == 0:
		c = &Check{State: Good, Line: "No passwords or keys are stored in Signalith's files."}
	default:
		c = &Check{State: Good, Line: "All " + itoa(total) + " stored " + plural(total, "password or key is", "passwords and keys are") + " encrypted with the master key."}
		if total == 1 {
			c.Line = "The one stored password or key is encrypted with the master key."
		}
	}
	c.Details = append(c.Details, "Signalith's HTTPS keys and the Docker setup's generated secrets are protected by file permissions, not by the master key (see File permissions).")
	return c
}

// diskFix says how to encrypt the disk under Signalith's files.
func diskFix(d Disk) *Fix {
	fix := &Fix{Steps: []string{"Encrypt the disk (LUKS on Linux, BitLocker on Windows), or move Signalith's folders to an encrypted one."}, Docs: doc(docEncDisk)}
	if d.Suspended {
		drive := d.Drive
		if drive == "" {
			drive = "C:"
		}
		fix.Steps = []string{"Turn BitLocker protection back on, in a PowerShell opened as Administrator."}
		fix.Commands = cmds("", "manage-bde -resume "+drive, "")
	}
	return fix
}

// diskCheckFix says how to check by hand what Signalith can't see.
func diskCheckFix(d Disk, docs DocLink) *Fix {
	fix := &Fix{Docs: doc(docs)}
	switch d.Kind {
	case DiskVirtual:
		where := "where the virtual machine is managed"
		if d.Provider != "" {
			where = "in " + d.Provider + "'s console"
		}
		fix.Steps = []string{"Check the disk's settings " + where + ", or ask whoever runs the host."}
	case DiskUnreadable:
		if strings.EqualFold(d.FSType, "zfs") {
			fix.Commands = cmds("zfs get encryption "+sh(d.Source), "", "")
		}
		fix.Steps = []string{"Check the encryption of " + d.FSType + " with its own tools."}
	case DiskWindows:
		fix.Steps = []string{"Run signalith security in a PowerShell opened as Administrator; it also saves the answer for this page. Or ask Windows directly."}
		fix.Commands = cmds("", winExe+" security\nmanage-bde -status C:", "")
	case DiskContainer:
		fix.Steps = []string{"Check the disk of the computer that runs the container."}
		fix.Commands = cmds("lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS", "manage-bde -status C:", "lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS")
	case DiskNetwork:
		fix.Steps = []string{"Ask whoever runs " + d.Source + " whether its disks are encrypted."}
	default:
		fix.Steps = []string{"Check the disk with the computer's own tools. A crypt line above the disk means it's encrypted."}
		fix.Commands = cmds("lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS", "manage-bde -status C:", "")
	}
	return fix
}

// diskLine describes a disk Signalith can't see into; what is "Signalith's
// files" or "OpenSearch's data files".
func diskLine(d Disk, what string) string {
	switch d.Kind {
	case DiskVirtual:
		host := "Its host"
		if d.Provider != "" {
			host += " (" + d.Provider + ")"
		}
		return what + " are on a virtual disk. " + host + " may encrypt it, but Signalith can't see that from inside."
	case DiskContainer:
		if what == "Signalith's files" {
			return "Signalith runs in a container, so it can't see the disk under its files."
		}
		return "Signalith runs in a container, so it can't see the disk under " + what + "."
	case DiskNetwork:
		return what + " are on a network share (" + d.Source + "), whose disks Signalith can't see."
	case DiskUnreadable:
		return what + " are on " + d.FSType + ", whose encryption Signalith can't read."
	case DiskWindows:
		return "Windows tells only administrators whether BitLocker is on."
	case DiskDenied:
		where := d.Hidden
		if where == "" {
			where = d.Path
		}
		return "Signalith's account isn't allowed to look inside " + where + ", so it can't tell which disk holds " + what + "."
	}
	return "Signalith can't tell whether the disk under " + what + " is encrypted."
}

// diskState is how a disk counts: worst first.
func diskState(d Disk) State {
	switch d.Kind {
	case DiskEncrypted, DiskMemory:
		if d.Suspended {
			return Attention
		}
		return Good
	case DiskPlain:
		return Attention
	}
	return Unknown
}

// checkDisk: rest.disk.
func checkDisk(f *Facts) *Check {
	if len(f.Disks) == 0 {
		return &Check{State: Unknown, Line: "Signalith couldn't find the disk that holds its files.", Fix: diskCheckFix(Disk{}, docSecDisk)}
	}
	disks := slices.Clone(f.Disks)
	slices.SortStableFunc(disks, func(a, b Disk) int { return diskState(a).order() - diskState(b).order() })
	d := disks[0]
	switch diskState(d) {
	case Attention:
		c := &Check{State: Attention, Fix: diskFix(d)}
		switch {
		case d.Suspended:
			c.Line = "BitLocker is suspended on drive " + d.Drive + " (checked " + day(d.CheckedAt) + ")."
		case d.Drive != "":
			c.Line = "Drive " + d.Drive + ", which holds Signalith's files, isn't protected by BitLocker (checked " + day(d.CheckedAt) + ")."
		default:
			c.Line = "The disk that holds Signalith's files (" + d.Device + ") isn't encrypted, as far as Linux can tell."
			c.Details = []string{"Someone who takes the disk could read the master key and what it protects.", "Self-encrypting drives don't show here."}
		}
		return c
	case Unknown:
		return &Check{State: Unknown, Line: diskLine(d, "Signalith's files"), Fix: diskCheckFix(d, docSecDisk)}
	}
	encrypted := 0
	for _, x := range disks {
		if x.Kind == DiskEncrypted {
			encrypted++
		}
	}
	switch {
	case encrypted == 0:
		return &Check{State: Good, Line: "Signalith's files are kept in memory only."}
	case d.Drive != "" && d.Method == "BitLocker" && len(disks) == 1:
		return &Check{State: Good, Line: "BitLocker protects drive " + d.Drive + ", which holds Signalith's files (checked " + day(d.CheckedAt) + ")."}
	case len(disks) == 2:
		return &Check{State: Good, Line: "Both disks that hold Signalith's files are encrypted."}
	case len(disks) > 2:
		return &Check{State: Good, Line: "All " + itoa(len(disks)) + " disks that hold Signalith's files are encrypted."}
	}
	method := ""
	if d.Method != "" {
		method = " (" + d.Method + ")"
	}
	return &Check{State: Good, Line: "The disk that holds Signalith's files is encrypted" + method + "."}
}

// checkArchives: rest.archives.
func checkArchives(f *Facts) *Check {
	a := f.Archive
	if a == nil || a.Count == 0 && !a.Policies {
		return nil
	}
	if a.Count == 0 {
		return &Check{State: Good, Line: "Archiving is on; no days are archived yet."}
	}
	count := itoa(a.Count)
	if a.More {
		count = "100,000+"
	} else if a.Count >= 1000 {
		count = thousands(a.Count)
	}
	what := count + plural(a.Count, " archived day", " archived days") + " (" + sizeOf(a.Bytes) + ")"
	details := []string{"Copies of archives you move elsewhere are only as safe as where you put them."}
	if p := a.Perm; p != nil && (p.OtherRead || p.GroupRead || p.SomeRead) {
		docker := ""
		if v := inVolume(a.Dir); v != "" && f.Docker {
			docker = busybox("chmod -R go-rwx " + sh(v))
		}
		return &Check{State: Attention, Line: "Other accounts on this computer can read the archived days in " + a.Dir + ".", Details: details,
			Fix: &Fix{Steps: []string{"Make the archive folder readable only by Signalith's account."},
				Commands: ownOnly(f, cmds("sudo chmod -R go-rwx "+sh(a.Dir), icaclsDir(a.Dir, "M"), docker)), Docs: doc(docRetArchives)}}
	}
	if a.Plain == 0 && !a.More {
		// Every file is encrypted with Signalith's keys, so the disk under
		// them doesn't matter.
		return &Check{State: Good, Line: what + " in " + a.Dir + " are encrypted, readable only by Signalith.", Details: details}
	}
	plain := what + " are kept as plain files"
	switch {
	case a.Plain < a.Count && !a.More:
		plain = itoa(a.Plain) + " of the " + what + " are kept as plain files"
	}
	why := " Archive encryption is turned off (retention.encrypt_archives: false)."
	if a.Encrypting {
		why = " They were written before Signalith encrypted archives; new archives are encrypted."
		if a.More {
			why = " Archives written before Signalith encrypted archives are plain; new archives are encrypted."
		}
	}
	moveFix := &Fix{Steps: []string{"Keep the archive folder on an encrypted disk: point retention.archive_dir at one."},
		Page: &PageLink{ID: "retention", Label: "Open Data retention"}, Docs: doc(docRetArchives)}
	if !a.Encrypting {
		moveFix.Steps = append(moveFix.Steps, "Or remove retention.encrypt_archives: false from signalith.yaml, so new archives are encrypted.")
	}
	switch diskState(a.Disk) {
	case Attention:
		return &Check{State: Attention, Line: plain + " in " + a.Dir + ", on a disk that isn't encrypted." + why,
			Details: details, Fix: moveFix}
	case Unknown:
		under := "disk"
		if a.Disk.Kind == DiskNetwork {
			under = "share"
		}
		fix := diskCheckFix(a.Disk, docEncDisk)
		return &Check{State: Unknown, Line: plain + " in " + a.Dir + ". Signalith can't see whether the " + under + " under them is encrypted." + why,
			Details: details, Fix: fix}
	}
	if a.Disk.Kind == DiskMemory {
		return &Check{State: Good, Line: what + " are kept in " + a.Dir + ", in memory only, readable only by Signalith.", Details: details}
	}
	return &Check{State: Good, Line: what + " are kept in " + a.Dir + ", on an encrypted disk, readable only by Signalith.", Details: details}
}

// thousands writes n with commas, such as 12,345.
func thousands(n int) string {
	s := itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// checkOpenSearchDisk: rest.opensearch_disk.
func checkOpenSearchDisk(f *Facts) *Check {
	_, host, _ := urlParts(f.Config.OpenSearch.URL)
	o := f.OpenSearch
	howTo := &Fix{Steps: []string{"On the computer OpenSearch runs on, check the disk that holds its data folder (path.data in opensearch.yml)."},
		Commands: cmds("lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS", "manage-bde -status C:", ""), Docs: doc(docSecOSDisk)}
	switch {
	case f.Docker && host == "opensearch":
		return &Check{State: Unknown, Line: "OpenSearch runs in its own container. Its events are in the opensearch-data volume on this computer's disk, which Signalith can't see from its container.", Fix: howTo}
	case f.InContainer:
		return &Check{State: Unknown, Line: "Signalith runs in a container, so it can't see the disk where OpenSearch (" + host + ") keeps events.", Fix: howTo}
	case !isLoopback(host):
		return &Check{State: Unknown, Line: "OpenSearch runs on another computer (" + host + "), so Signalith can't see its disk.", Fix: howTo}
	case o.DataErr != "" && o.SecurityNotLoaded:
		return &Check{State: Unknown, Line: "Signalith couldn't ask OpenSearch where it keeps events: OpenSearch's security settings aren't loaded, so it turns everyone away for now.",
			Fix: notLoadedFix(f)}
	case o.DataErr != "":
		return &Check{State: Unknown, Line: "Signalith couldn't ask OpenSearch where it keeps events (" + short(o.DataErr) + ").", Fix: howTo}
	case len(o.DataPaths) == 0 && len(o.DataMissing) > 0:
		return &Check{State: Unknown, Line: "OpenSearch says it keeps events in " + shorten(o.DataMissing, 3) +
			", which isn't on this computer's disks as Signalith sees them. It may run in a container.", Fix: howTo}
	case len(o.DataPaths) == 0:
		return &Check{State: Unknown, Line: "Signalith couldn't ask OpenSearch where it keeps events.", Fix: howTo}
	}
	disks := slices.Clone(o.DataPaths)
	slices.SortStableFunc(disks, func(a, b Disk) int { return diskState(a).order() - diskState(b).order() })
	d := disks[0]
	switch diskState(d) {
	case Attention:
		line := "OpenSearch keeps events in " + d.Path + ", on a disk that isn't encrypted, as far as Linux can tell."
		switch {
		case d.Suspended:
			line = "OpenSearch keeps events in " + d.Path + ", on drive " + d.Drive + ", where BitLocker is suspended (checked " + day(d.CheckedAt) + ")."
		case d.Drive != "":
			line = "OpenSearch keeps events in " + d.Path + ", on drive " + d.Drive + ", which BitLocker doesn't protect (checked " + day(d.CheckedAt) + ")."
		}
		fix := &Fix{Steps: []string{"Encrypt the disk that holds OpenSearch's data folder, or move the folder (path.data in opensearch.yml) to an encrypted one."}, Docs: doc(docEncDisk)}
		if d.Suspended {
			fix = diskFix(d)
		}
		return &Check{State: Attention, Line: line, Fix: fix}
	case Unknown:
		fix := diskCheckFix(d, docSecOSDisk)
		return &Check{State: Unknown, Line: diskLine(d, "OpenSearch's data files"), Fix: fix}
	}
	c := &Check{State: Good, Line: "OpenSearch keeps events in " + d.Path + ", in memory only."}
	for _, x := range disks {
		if x.Kind != DiskMemory {
			c.Line = "OpenSearch keeps events in " + x.Path + ", on an encrypted disk."
			break
		}
	}
	for _, x := range disks {
		if x.Hidden != "" {
			c.Details = append(c.Details, "Signalith's account can't look inside "+x.Hidden+", so this is the disk that holds that folder.")
			break
		}
	}
	return c
}

// checkOpenSearchAccess: rest.opensearch_access.
func checkOpenSearchAccess(f *Facts) *Check {
	_, host, hostport := urlParts(f.Config.OpenSearch.URL)
	o := f.OpenSearch
	docs := docOSLinux
	if f.InContainer {
		docs = docOSDocker
	}
	fix := &Fix{Steps: []string{"Turn on OpenSearch's security plugin with your own certificates, and have Signalith sign in with a certificate of its own. signalith opensearch-certs makes the files."},
		Docs: doc(docs)}
	switch o.Anonymous {
	case "open":
		if !isLoopback(host) || o.Listening {
			return &Check{State: Risk, Line: "Anyone who can reach OpenSearch at " + hostport + " can read events without signing in.", Fix: fix}
		}
		return &Check{State: Attention, Line: "OpenSearch lets anyone on this computer read events without signing in. It isn't listening on the network.", Fix: fix}
	case "closed":
		return &Check{State: Good, Line: "OpenSearch turns away anyone who doesn't sign in."}
	}
	if o.SecurityNotLoaded {
		return &Check{State: Unknown, Line: "OpenSearch's security settings aren't loaded, so it turns everyone away for now, Signalith too. " +
			"Who can read events once they are loaded depends on them.", Fix: notLoadedFix(f)}
	}
	c := &Check{State: Unknown, Line: "Signalith couldn't reach OpenSearch just now, so it can't tell who else can.", Fix: reachFix()}
	if o.AnonymousErr != "" {
		c.Details = []string{osWhy(o.AnonymousErr)}
		if osAnswered(o.AnonymousErr) {
			c.Line = "Signalith couldn't tell whether OpenSearch lets anyone read events without signing in."
			c.Fix = &Fix{Steps: []string{"Re-check in a few minutes. If OpenSearch keeps answering this way, its log may say why. " + store.OpenSearchLog}, Docs: doc(docs)}
		}
	}
	return c
}

// osAnswered reports whether a probe's why is OpenSearch's own answer
// ("status N"), rather than a reason it couldn't be reached.
func osAnswered(why string) bool { return strings.HasPrefix(why, "status ") }

// osWhy says why a probe of OpenSearch failed, in a sentence.
func osWhy(why string) string {
	if osAnswered(why) {
		return "OpenSearch answered: " + short(why) + "."
	}
	return "Signalith couldn't reach OpenSearch: " + short(why) + "."
}

// notLoadedFix is the step when OpenSearch's security settings aren't
// loaded: with the Docker quick start, run its step that loads them again;
// else securityadmin.sh, as the docs show.
func notLoadedFix(f *Facts) *Fix {
	const wait = "If OpenSearch started only a few minutes ago, re-check in a few minutes: it loads them as it starts. "
	if f.Docker {
		return &Fix{Steps: []string{wait + "Otherwise, run the command below from the Signalith folder: it re-runs the step that loads " +
			"OpenSearch's security settings. If that doesn't load them, the docs say what to do. Then re-check."},
			Commands: cmds("", "", dockerCompose+" up -d"), Docs: doc(docOSNotLoaded)}
	}
	return &Fix{Steps: []string{wait + "Otherwise, load them with securityadmin.sh, as the docs show. Then re-check."}, Docs: doc(docOSRoles)}
}

// reachFix is the step when OpenSearch couldn't be reached.
func reachFix() *Fix {
	return &Fix{Steps: []string{"Re-check once OpenSearch is reachable; the Health page shows why it can't be reached."}}
}

// short keeps an error message to one short line.
func short(s string) string {
	for i, r := range s {
		if r == '\n' {
			s = s[:i]
			break
		}
	}
	const most = 160
	if len(s) > most {
		cut := most
		for cut > 0 && s[cut]&0xC0 == 0x80 {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}
