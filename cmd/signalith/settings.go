package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// serviceSettingsFile is where the Linux service keeps the Settings page's
// file with the unit Signalith ships, which points the lookups folder at
// /var/lib/signalith: what a shell assumes when it cannot read the unit.
var serviceSettingsFile = "/var/lib/signalith/lookups/settings.yaml"

// serviceSettingsPath returns where the signalith service keeps the
// Settings page's file, from its unit as the other folders it is given
// are read (see readServiceSettings): SIGNALITH_SETTINGS_FILE, or
// settings.yaml in SIGNALITH_LOOKUPS_DIR. When the unit cannot be read, it
// is the shipped unit's file; "" when the unit moves neither, so the
// service keeps the file where this command looks too.
func serviceSettingsPath() string {
	s := readServiceSettings()
	if s == nil {
		return serviceSettingsFile
	}
	if f := s.env["SIGNALITH_SETTINGS_FILE"]; filepath.IsAbs(f) {
		return f
	}
	if d := s.env["SIGNALITH_LOOKUPS_DIR"]; filepath.IsAbs(d) {
		return filepath.Join(d, "settings.yaml")
	}
	return ""
}

// settingsFileFlag adds -file, the Settings page's file, for a service
// that names another one than signalith.yaml does.
func settingsFileFlag(fs *flag.FlagSet) *string {
	return fs.String("file", "", "the Settings page's file, as the service has it (same as SIGNALITH_SETTINGS_FILE); by default settings.yaml in the lookups folder")
}

// useSettingsFile makes -file the Settings page's file for this command.
func useSettingsFile(file string) error {
	if file == "" {
		return nil
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	return os.Setenv("SIGNALITH_SETTINGS_FILE", abs)
}

// serviceNote points to the file the Linux service uses, when it is not
// file and exists, with the command to use on it; otherwise it says
// where else a service may keep it. cmd is the command to show, such as
// "settings reset". When the service runs with configPath and its unit
// can be read, its folders are used already (see useServiceEnv), so file
// is the service's own.
func serviceNote(file, configPath, cmd string, keys []string) string {
	svc := ""
	if runtime.GOOS == "linux" {
		svc = serviceSettingsPath()
	}
	if svc != "" && svc != file {
		if _, err := os.Stat(svc); err == nil {
			line := "sudo signalith " + cmd + " -c " + configPath + " -file " + svc
			if len(keys) > 0 {
				line += " " + strings.Join(keys, " ")
			}
			return "The Signalith service keeps its settings in " + svc + ". To use that file:\n  " + line
		}
	}
	return "If Signalith runs as a service, it may keep the file elsewhere: give it with -file, or set SIGNALITH_LOOKUPS_DIR or SIGNALITH_SETTINGS_FILE as the service does."
}

// printable is s as the terminal shows it: quoted, with line breaks and
// other control characters escaped, when it has any, so a value cannot
// pass for more than one line or hide others.
func printable(s string) string {
	if s == "" || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return strconv.Quote(s)
	}
	return s
}

// cmdSettings shows or removes the changes made on the Settings page. It
// is the way back when a change there locks people out: reset the
// setting here, then restart Signalith.
func cmdSettings(args []string) error {
	const use = "usage: signalith settings list [-c file] [-file settings.yaml]\n" +
		"       signalith settings reset [-c file] [-file settings.yaml] [key...]   (no key: every change made on the page)\n" +
		"       signalith settings reset -local [-c file] key...   (a member of a cluster: set settings aside on this server while OpenSearch cannot be reached)"
	if len(args) == 0 || (args[0] != "list" && args[0] != "reset") {
		return errors.New(use)
	}
	fs := flag.NewFlagSet("settings "+args[0], flag.ExitOnError)
	path := configFlag(fs)
	fileFlag := settingsFileFlag(fs)
	local := fs.Bool("local", false, "on a member of a cluster that shares its settings: set the settings named aside on this server only, "+
		"for its next start, without OpenSearch")
	fs.Parse(args[1:])
	if err := useSettingsFile(*fileFlag); err != nil {
		return err
	}
	// The folders the service is given, so this finds the file it uses;
	// -file, set above, still wins.
	useServiceEnv(*path, os.Stdout)
	file, err := config.SettingsFileFor(*path)
	if err != nil {
		return err
	}
	keys := fs.Args()
	if args[0] == "reset" {
		// On a member whose settings are shared, they are reset in the
		// shared settings; settings.yaml keeps only those needed to reach
		// OpenSearch.
		if *local {
			if keys, err = settingsResetLocal(*path, keys); err != nil || len(keys) == 0 {
				return err
			}
		} else if done, err := settingsResetShared(*path, keys); done || err != nil {
			return err
		}
	}
	_, statErr := os.Stat(file)
	missing := errors.Is(statErr, os.ErrNotExist)
	note := ""
	if *fileFlag == "" {
		note = serviceNote(file, *path, "settings "+args[0], keys)
	}
	page, readErr := config.ReadPageSettings(file)
	if args[0] == "list" {
		switch {
		case missing:
			fmt.Printf("There is no settings file at %s, so nothing was changed on the Settings page there.\n", file)
			if note != "" {
				fmt.Println(note)
			}
			return nil
		case readErr != nil:
			return fmt.Errorf("%v; start a new one with: signalith settings reset -c %s -file %s", readErr, *path, file)
		case page.Empty():
			fmt.Printf("Nothing was changed on the Settings page (%s).\n", file)
			return nil
		}
		fmt.Printf("Changed on the Settings page (%s):\n", file)
		for _, key := range page.Keys() {
			e := page.Settings[key]
			value := "(hidden)"
			if e.Secret == nil {
				var v any
				if e.Value.Decode(&v) == nil {
					value = printable(fmt.Sprint(v))
				}
			}
			fmt.Printf("  %-34s %-28s by %s on %s\n", key, value, printable(e.ChangedBy), e.ChangedAt.Local().Format("2006-01-02 15:04"))
			if e.Refused != "" {
				fmt.Printf("  %-34s set aside, not used: %s\n", "", printable(e.Refused))
			}
		}
		if strings.HasPrefix(note, "The Signalith service") {
			fmt.Println(note)
		}
		return nil
	}
	if missing {
		msg := fmt.Sprintf("there is no settings file at %s, so nothing was reset", file)
		if note != "" {
			msg += ".\n" + note
		}
		return errors.New(msg)
	}
	if len(keys) == 0 {
		backup := ""
		if readErr != nil {
			// What a file that cannot be read held is kept next to it.
			if backup, err = config.BackUpPageFile(file); err != nil {
				return err
			}
		}
		if err := config.WritePageSettings(file, &config.PageSettings{}); err != nil {
			return err
		}
		fmt.Printf("Removed every change made on the Settings page (%s).\n", file)
		if backup != "" {
			fmt.Printf("The file could not be read; it is kept as %s.\n", backup)
		}
		fmt.Println("Restart Signalith to use signalith.yaml alone.")
		return nil
	}
	if readErr != nil {
		return fmt.Errorf("%v; remove every change with: signalith settings reset -c %s -file %s", readErr, *path, file)
	}
	for _, key := range keys {
		if _, ok := config.Lookup(key); !ok {
			return fmt.Errorf("%s is not a setting on the Settings page; see signalith settings list", key)
		}
	}
	var removed []string
	for _, key := range keys {
		if page.Remove(key) {
			removed = append(removed, key)
		}
	}
	if len(removed) == 0 {
		msg := fmt.Sprintf("none of these were changed on the Settings page (%s), so nothing was reset", file)
		if note != "" {
			msg += ".\n" + note
		}
		return errors.New(msg)
	}
	if err := config.WritePageSettings(file, page); err != nil {
		return err
	}
	fmt.Printf("Reset %s in %s; signalith.yaml or the default applies again.\n", strings.Join(removed, ", "), file)
	fmt.Println("Restart Signalith to apply it.")
	return nil
}
