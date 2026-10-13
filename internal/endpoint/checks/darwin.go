package checks

import "fmt"

// macPref returns an expression for a system preference's effective value,
// lowercased: a configuration-profile (managed) value wins over the local
// plist in /Library/Preferences. It is NULL when neither sets the key.
func macPref(domain, key string) string {
	return fmt.Sprintf(`coalesce(
      (SELECT lower(value) FROM managed_policies WHERE domain = %[1]s AND name = %[2]s LIMIT 1),
      (SELECT lower(value) FROM plist WHERE path = %[3]s AND key = %[2]s LIMIT 1))`,
		sqlQuote(domain), sqlQuote(key), sqlQuote("/Library/Preferences/"+domain+".plist"))
}

// macPrefSQL checks a boolean system preference whose default, when unset,
// is def. It passes when the effective value equals want.
func macPrefSQL(domain, key string, def, want bool, failDetail string) string {
	b := func(x bool) string {
		if x {
			return "'1'"
		}
		return "'0'"
	}
	inner := fmt.Sprintf(`SELECT CASE
      WHEN raw IN ('1', 'true', 'yes') THEN '1'
      WHEN raw IN ('0', 'false', 'no') THEN '0'
      ELSE %s END AS v FROM (SELECT %s AS raw)`, b(def), macPref(domain, key))
	return verdict(inner, "", "", "v = "+b(want), sqlQuote(failDetail))
}

// sharingSQL checks that one sharing service is off.
func sharingSQL(column, name string) string {
	inner := fmt.Sprintf("SELECT count(*) AS n, max(%s) AS v FROM sharing_preferences", column)
	return verdict(inner, "n = 0", "'sharing preferences could not be read'", "v = 0", sqlQuote(name+" is turned on"))
}

var darwinChecks = []Check{
	{
		ID:          "darwin-filevault-enabled",
		Title:       "FileVault disk encryption is on",
		Platform:    "darwin",
		Severity:    "high",
		References:  refs("SC-28,SC-28(1)"),
		Description: "Without FileVault, anyone who gets hold of the Mac or its disk can read its data, including saved credentials.",
		Remediation: "Turn on FileVault in System Settings > Privacy & Security > FileVault, or run \"sudo fdesetup enable\", and escrow the recovery key (for example in your MDM).",
		SQL: verdict(`SELECT count(*) AS n, sum(filevault_status = 'on') AS fv_on FROM disk_encryption`,
			"n = 0", "'no disk encryption information'", "fv_on > 0", "'FileVault is off'"),
	},
	{
		ID:          "darwin-gatekeeper-enabled",
		Title:       "Gatekeeper is on",
		Platform:    "darwin",
		Severity:    "high",
		References:  refs("CM-5,SI-3"),
		Description: "Gatekeeper refuses to open apps that are not signed by an identified developer and notarized by Apple, which stops a lot of commodity malware.",
		Remediation: "Run \"sudo spctl --global-enable\" (\"sudo spctl --master-enable\" on older macOS), or set Allow applications from App Store and identified developers in System Settings > Privacy & Security.",
		SQL: verdict(`SELECT count(*) AS n, max(assessments_enabled) AS v FROM gatekeeper`,
			"n = 0", "'Gatekeeper status could not be read'", "v = 1", "'Gatekeeper assessments are disabled'"),
	},
	{
		ID:          "darwin-sip-enabled",
		Title:       "System Integrity Protection is on",
		Platform:    "darwin",
		Severity:    "high",
		References:  refs("AC-3,AU-9,CM-5,SI-7"),
		Description: "SIP stops even root from changing protected system files and processes, so malware with admin rights cannot easily tamper with the OS or hide itself.",
		Remediation: "Start the Mac in Recovery, open Terminal and run \"csrutil enable\", then restart.",
		SQL: verdict(`SELECT count(*) AS n, max(enabled) AS v FROM sip_config WHERE config_flag = 'sip'`,
			"n = 0", "'SIP status could not be read'", "v = 1", "'System Integrity Protection is disabled'"),
	},
	{
		ID:          "darwin-firewall-enabled",
		Title:       "The application firewall is on",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-4,SC-7"),
		Description: "The macOS firewall blocks unsolicited incoming connections to apps and services that have not been allowed, which limits exposure on untrusted networks.",
		Remediation: "Turn on the firewall in System Settings > Network > Firewall, or run \"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on\".",
		SQL: verdict(`SELECT count(*) AS n, max(global_state) AS v FROM alf`,
			"n = 0", "'firewall status could not be read'", "v >= 1", "'the application firewall is off'"),
	},
	{
		ID:          "darwin-firewall-stealth-mode",
		Title:       "Firewall stealth mode is on",
		Platform:    "darwin",
		Severity:    "low",
		References:  refs("SC-7"),
		Description: "Stealth mode stops the Mac from answering pings and connection probes to closed ports, making it harder to find on a network.",
		Remediation: "Run \"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on\", or enable Stealth Mode in the firewall options.",
		SQL: verdict(`SELECT count(*) AS n, max(stealth_enabled) AS v FROM alf`,
			"n = 0", "'firewall status could not be read'", "v = 1", "'firewall stealth mode is off'"),
	},
	{
		ID:          "darwin-firewall-logging",
		Title:       "Firewall logging is on",
		Platform:    "darwin",
		Severity:    "low",
		References:  refs("AU-2,AU-12"),
		Description: "Firewall logs show blocked and allowed connection attempts, which helps when investigating scanning or unexpected listeners.",
		Remediation: "Run \"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on\".",
		SQL: verdict(`SELECT count(*) AS n, max(logging_enabled) AS v FROM alf`,
			"n = 0", "'firewall status could not be read'", "v = 1", "'firewall logging is off'"),
	},
	{
		ID:          "darwin-update-auto-check",
		Title:       "macOS checks for software updates automatically",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("SI-2"),
		Description: "Automatic checks make sure the Mac learns about security updates promptly instead of only when someone remembers to look.",
		Remediation: "Run \"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true\", or enforce it with a configuration profile (com.apple.SoftwareUpdate).",
		SQL:         macPrefSQL("com.apple.SoftwareUpdate", "AutomaticCheckEnabled", true, true, "automatic update checks are turned off"),
	},
	{
		ID:          "darwin-update-auto-download",
		Title:       "macOS downloads new updates in the background",
		Platform:    "darwin",
		Severity:    "low",
		References:  refs("SI-2"),
		Description: "Downloading updates ahead of time shortens the gap between a fix being released and being installed.",
		Remediation: "Run \"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true\", or enforce it with a configuration profile.",
		SQL:         macPrefSQL("com.apple.SoftwareUpdate", "AutomaticDownload", true, true, "automatic update downloads are turned off"),
	},
	{
		ID:          "darwin-update-security-responses",
		Title:       "Security responses and system data files install automatically",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("SI-2,SI-3"),
		Description: "Rapid security responses and XProtect malware definitions arrive through this setting; with it off, the Mac misses urgent fixes and new malware signatures.",
		Remediation: "Run \"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true\" and \"... ConfigDataInstall -bool true\", or enforce both with a configuration profile.",
		SQL: verdict(`SELECT
    `+macPref("com.apple.SoftwareUpdate", "CriticalUpdateInstall")+` AS critical,
    `+macPref("com.apple.SoftwareUpdate", "ConfigDataInstall")+` AS config`,
			"", "",
			"coalesce(critical, '1') NOT IN ('0', 'false', 'no') AND coalesce(config, '1') NOT IN ('0', 'false', 'no')",
			"'automatic installation of security responses or system data files is turned off'"),
	},
	{
		ID:          "darwin-screen-lock",
		Title:       "The screen locks with a password within 5 seconds of the screen saver",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-11"),
		Description: "Requiring the password as soon as the screen saver starts stops someone at an unattended Mac from using the signed-in session.",
		Remediation: "In System Settings > Lock Screen set \"Require password after screen saver begins or display is turned off\" to Immediately (or up to 5 seconds), or enforce askForPassword and askForPasswordDelay with a configuration profile.",
		SQL: verdict(`SELECT count(*) AS n, max(enabled) AS enabled, max(grace_period) AS grace FROM screenlock`,
			"n = 0", "'no user is signed in at the console'",
			"enabled = 1 AND grace <= 5",
			"CASE WHEN enabled = 1 THEN 'the password is required only after ' || grace || ' seconds' ELSE 'no password is required to unlock the screen saver' END"),
	},
	{
		ID:          "darwin-remote-login-disabled",
		Title:       "Remote Login (SSH) is off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-17,CM-7"),
		Description: "Remote Login exposes an SSH server to the network; most Macs do not need it, and it is a common target for password guessing.",
		Remediation: "Run \"sudo systemsetup -setremotelogin off\", or turn off Remote Login in System Settings > General > Sharing.",
		SQL:         sharingSQL("remote_login", "Remote Login (SSH)"),
	},
	{
		ID:          "darwin-screen-sharing-disabled",
		Title:       "Screen Sharing is off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-17,CM-7"),
		Description: "Screen Sharing lets other computers view and control this Mac over VNC; when not needed it is unnecessary remote access.",
		Remediation: "Turn off Screen Sharing in System Settings > General > Sharing, or run \"sudo launchctl disable system/com.apple.screensharing\".",
		SQL:         sharingSQL("screen_sharing", "Screen Sharing"),
	},
	{
		ID:          "darwin-remote-management-disabled",
		Title:       "Remote Management (Apple Remote Desktop) is off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-17,CM-7"),
		Description: "Remote Management gives full remote control of the Mac; if it is not part of how the Mac is managed it should not be listening.",
		Remediation: "Run \"sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop\", or turn off Remote Management in Sharing settings.",
		SQL:         sharingSQL("remote_management", "Remote Management"),
	},
	{
		ID:          "darwin-remote-apple-events-disabled",
		Title:       "Remote Apple Events are off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("CM-7"),
		Description: "Remote Apple Events let other computers send AppleScript commands to this Mac, which can be abused to run actions remotely.",
		Remediation: "Run \"sudo systemsetup -setremoteappleevents off\", or turn off Remote Application Scripting in Sharing settings.",
		SQL:         sharingSQL("remote_apple_events", "Remote Apple Events"),
	},
	{
		ID:          "darwin-file-sharing-disabled",
		Title:       "File Sharing is off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("CM-7"),
		Description: "File Sharing runs an SMB server on the Mac; outside of dedicated file servers it exposes data and a network service needlessly.",
		Remediation: "Turn off File Sharing in System Settings > General > Sharing, or run \"sudo launchctl disable system/com.apple.smbd\".",
		SQL:         sharingSQL("file_sharing", "File Sharing"),
	},
	{
		ID:          "darwin-internet-sharing-disabled",
		Title:       "Internet Sharing is off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-4,CM-7"),
		Description: "Internet Sharing turns the Mac into a router that can bridge an untrusted network into a trusted one, bypassing network controls.",
		Remediation: "Turn off Internet Sharing in System Settings > General > Sharing, or block it with a configuration profile.",
		SQL:         sharingSQL("internet_sharing", "Internet Sharing"),
	},
	{
		ID:          "darwin-printer-sharing-disabled",
		Title:       "Printer Sharing is off",
		Platform:    "darwin",
		Severity:    "low",
		References:  refs("CM-7"),
		Description: "Printer Sharing opens the CUPS print service to the network, which most Macs never need to offer.",
		Remediation: "Run \"sudo cupsctl --no-share-printers\", or turn off Printer Sharing in Sharing settings.",
		SQL:         sharingSQL("printer_sharing", "Printer Sharing"),
	},
	{
		ID:          "darwin-bluetooth-sharing-disabled",
		Title:       "Bluetooth Sharing is off",
		Platform:    "darwin",
		Severity:    "low",
		References:  refs("CM-7"),
		Description: "Bluetooth Sharing lets nearby devices browse or send files to this Mac, an unneeded way for data to move in or out.",
		Remediation: "Turn off Bluetooth Sharing in System Settings > General > Sharing.",
		SQL:         sharingSQL("bluetooth_sharing", "Bluetooth Sharing"),
	},
	{
		ID:          "darwin-guest-account-disabled",
		Title:       "The guest user account is off",
		Platform:    "darwin",
		Severity:    "medium",
		References:  refs("AC-2,AC-14"),
		Description: "The guest account lets anyone use the Mac without a password, and their actions cannot be traced to a person.",
		Remediation: "Turn off \"Allow guests to log in to this computer\" in System Settings > Users & Groups, or run \"sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false\".",
		SQL: verdict(`SELECT
    `+macPref("com.apple.loginwindow", "GuestEnabled")+` AS guest,
    (SELECT lower(value) FROM managed_policies WHERE domain = 'com.apple.MCX' AND name = 'DisableGuestAccount' LIMIT 1) AS mcx_disable`,
			"", "",
			"mcx_disable IN ('1', 'true') OR coalesce(guest, '0') IN ('0', 'false', 'no')",
			"'the guest account is enabled'"),
	},
	{
		ID:          "darwin-auto-login-disabled",
		Title:       "Automatic login is off",
		Platform:    "darwin",
		Severity:    "high",
		References:  refs("IA-2"),
		Description: "With automatic login, anyone who turns the Mac on gets a signed-in session, and the user's password is kept in an easily decoded file.",
		Remediation: "Set Automatic login to Off in System Settings > Users & Groups, or run \"sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser\".",
		SQL: verdict(`SELECT (SELECT value FROM plist WHERE path = '/Library/Preferences/com.apple.loginwindow.plist' AND key = 'autoLoginUser' LIMIT 1) AS v`,
			"", "", "coalesce(v, '') = ''", "'automatic login is enabled for ' || v"),
	},
}
