package checks

import "fmt"

const (
	hklm        = `HKEY_LOCAL_MACHINE\`
	lsaKey      = hklm + `SYSTEM\CurrentControlSet\Control\Lsa\`
	polSystem   = hklm + `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\`
	lanmanSrv   = hklm + `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\`
	termSrvPol  = hklm + `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\`
	termSrv     = hklm + `SYSTEM\CurrentControlSet\Control\Terminal Server\`
	defenderKey = hklm + `SOFTWARE\Microsoft\Windows Defender\`
	defenderPol = hklm + `SOFTWARE\Policies\Microsoft\Windows Defender\`
)

// reg returns a scalar subquery for the data of one registry value; it is
// NULL when the value does not exist.
func reg(path string) string {
	return fmt.Sprintf("(SELECT data FROM registry WHERE path = %s)", sqlQuote(path))
}

// regSQL checks one registry value. In pass and failDetail, v is the value's
// data, or NULL when it is not set.
func regSQL(path, pass, failDetail string) string {
	return verdict("SELECT "+reg(path)+" AS v", "", "", pass, failDetail)
}

// secPolicySQL checks a column of security_profile_info (the local security
// policy). It is n/a when the table returns no row.
func secPolicySQL(column, pass, failDetail string) string {
	inner := fmt.Sprintf("SELECT count(*) AS n, max(%s) AS v FROM security_profile_info", column)
	return verdict(inner, "n = 0", "'local security policy could not be read'", pass, failDetail)
}

// firewallProfile returns an expression that is the profile's name followed
// by a space when the Windows Firewall is off for it. Group Policy settings
// override the local ones; the firewall is on when neither is set.
func firewallProfile(policyName, localName, label string) string {
	return fmt.Sprintf("CASE WHEN coalesce(%s, %s, '1') = '0' THEN '%s ' ELSE '' END",
		reg(hklm+`SOFTWARE\Policies\Microsoft\WindowsFirewall\`+policyName+`\EnableFirewall`),
		reg(hklm+`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+localName+`\EnableFirewall`),
		label)
}

var windowsChecks = []Check{
	{
		ID:          "windows-smb1-server-disabled",
		Title:       "The SMBv1 server protocol is turned off",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("CM-7"),
		Description: "SMBv1 is obsolete, lacks modern integrity protection and was the entry point for worms such as WannaCry and NotPetya.",
		Remediation: "Run \"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\" (or \"Set-SmbServerConfiguration -EnableSMB1Protocol $false\" on Windows Server) and restart.",
		SQL: verdict(`SELECT
    (SELECT count(*) FROM windows_optional_features WHERE name IN ('SMB1Protocol', 'SMB1Protocol-Server') AND state = 1) AS feature_on,
    `+reg(lanmanSrv+`SMB1`)+` AS v`,
			"", "", "feature_on = 0 AND coalesce(v, '') != '1'",
			"CASE WHEN feature_on > 0 THEN 'the SMB1Protocol optional feature is enabled' ELSE 'LanmanServer SMB1 is set to 1' END"),
	},
	{
		ID:          "windows-smb1-client-disabled",
		Title:       "The SMBv1 client driver is disabled",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("CM-7"),
		Description: "A host that can still speak SMBv1 as a client can be tricked into downgrading connections and exposes the same old protocol flaws.",
		Remediation: "Run \"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client\", or set the Start value of HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10 to 4, and restart.",
		SQL:         regSQL(hklm+`SYSTEM\CurrentControlSet\Services\mrxsmb10\Start`, "v IS NULL OR v = '4'", "'mrxsmb10 driver start type is ' || v || ', expected 4 (disabled)'"),
	},
	{
		ID:          "windows-firewall-all-profiles",
		Title:       "Windows Firewall is on for the domain, private and public profiles",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("SC-7,AC-4"),
		Description: "With a profile turned off, every listening service is reachable from the network whenever the host is on that kind of network.",
		Remediation: "Run \"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True\", or enable all three profiles under Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall in Group Policy.",
		SQL: verdict(`SELECT trim(`+
			firewallProfile("DomainProfile", "DomainProfile", "domain")+` || `+
			firewallProfile("PrivateProfile", "StandardProfile", "private")+` || `+
			firewallProfile("PublicProfile", "PublicProfile", "public")+`) AS off`,
			"", "", "off = ''", "'Windows Firewall is off for: ' || off"),
	},
	{
		ID:          "windows-uac-enabled",
		Title:       "User Account Control is on",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("AC-6"),
		Description: "With UAC off, every administrator process runs with full rights, so any program an administrator opens can change the whole system.",
		Remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1 (Group Policy: \"User Account Control: Run all administrators in Admin Approval Mode\" = Enabled) and restart.",
		SQL:         regSQL(polSystem+`EnableLUA`, "v IS NULL OR v = '1'", "'EnableLUA is ' || v"),
	},
	{
		ID:          "windows-uac-admin-prompt",
		Title:       "UAC asks administrators for consent or credentials on the secure desktop",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AC-6"),
		Description: "Prompting on the secure desktop for every elevation stops malware from silently elevating or clicking through the prompt.",
		Remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin to 2 (prompt for consent on the secure desktop) or 1 (prompt for credentials).",
		SQL:         regSQL(polSystem+`ConsentPromptBehaviorAdmin`, "v IN ('1', '2')", "'ConsentPromptBehaviorAdmin is ' || coalesce(v, 'not set (default 5, no secure-desktop prompt for Windows binaries)')"),
	},
	{
		ID:          "windows-antivirus-realtime",
		Title:       "Antivirus real-time protection is on",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("SI-3"),
		Description: "Real-time scanning blocks known malware as files are written or run; without it, malware is only found, if at all, by a later scan.",
		Remediation: "Turn on real-time protection in Windows Security, or run \"Set-MpPreference -DisableRealtimeMonitoring $false\" and remove any DisableRealtimeMonitoring policy under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender. If another antivirus product is used, make sure its real-time protection is on.",
		SQL: verdict(`SELECT
    (SELECT count(*) FROM windows_security_products WHERE type = 'Antivirus' AND state = 'On') AS av_on,
    (SELECT count(*) FROM services WHERE name = 'WinDefend' AND status = 'RUNNING') AS defender_running,
    coalesce(`+reg(defenderPol+`Real-Time Protection\DisableRealtimeMonitoring`)+`, '0') AS pol_off,
    coalesce(`+reg(defenderKey+`Real-Time Protection\DisableRealtimeMonitoring`)+`, '0') AS local_off`,
			"", "",
			"av_on > 0 OR (defender_running > 0 AND pol_off != '1' AND local_off != '1')",
			"CASE WHEN defender_running = 0 THEN 'no antivirus product reports real-time protection on and the Defender service is not running' ELSE 'Defender real-time monitoring is disabled' END"),
	},
	{
		ID:          "windows-bitlocker-system-drive",
		Title:       "BitLocker protects the system drive",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("SC-28,SC-28(1)"),
		Description: "Without disk encryption anyone with physical access to the disk, for example a stolen laptop, can read all its data and offline credentials.",
		Remediation: "Turn on BitLocker for the system drive with \"Enable-BitLocker -MountPoint C: -TpmProtector -EncryptionMethod XtsAes256\" or from Control Panel > BitLocker Drive Encryption, and store the recovery key safely.",
		SQL: verdict(`SELECT count(*) AS n, max(protection_status) AS protection, max(conversion_status) AS conversion
  FROM bitlocker_info
  WHERE drive_letter = coalesce(substr(`+reg(hklm+`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot`)+`, 1, 2), 'C:')`,
			"", "", "n > 0 AND protection = 1",
			"CASE WHEN n = 0 THEN 'no BitLocker information for the system drive' ELSE 'BitLocker protection is off for the system drive (conversion status ' || coalesce(conversion, '?') || ')' END"),
	},
	{
		ID:          "windows-guest-account-disabled",
		Title:       "The built-in Guest account is disabled",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AC-2,AC-14"),
		Description: "The Guest account allows sign-in without a personal identity, so actions taken through it cannot be traced to anyone.",
		Remediation: "Run \"net user Guest /active:no\", or set \"Accounts: Guest account status\" to Disabled in Local Security Policy.",
		SQL:         secPolicySQL("enable_guest_account", "v = 0", "'the Guest account is enabled'"),
	},
	{
		ID:          "windows-no-lm-hash",
		Title:       "Windows does not store LAN Manager password hashes",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("IA-5(1)"),
		Description: "LM hashes are trivially cracked, so storing them turns any theft of the account database into immediate password disclosure.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash to 1 (\"Network security: Do not store LAN Manager hash value on next password change\" = Enabled), then have users change their passwords.",
		SQL:         regSQL(lsaKey+`NoLMHash`, "v IS NULL OR v = '1'", "'NoLMHash is ' || v"),
	},
	{
		ID:          "windows-lm-compatibility-level",
		Title:       "Only NTLMv2 is used; LM and NTLMv1 are refused",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("IA-5(1),SC-8"),
		Description: "LM and NTLMv1 responses can be captured on the network and cracked or relayed easily; level 5 sends and accepts only NTLMv2.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel to 5 (\"Network security: LAN Manager authentication level\" = Send NTLMv2 response only. Refuse LM & NTLM).",
		SQL:         regSQL(lsaKey+`LmCompatibilityLevel`, "v IS NOT NULL AND CAST(v AS INTEGER) >= 5", "'LmCompatibilityLevel is ' || coalesce(v, 'not set (default 3)')"),
	},
	{
		ID:          "windows-ntlm-session-security",
		Title:       "NTLM client sessions require NTLMv2 session security and 128-bit encryption",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("SC-8,SC-13"),
		Description: "Requiring NTLMv2 session security and 128-bit keys prevents a client from being downgraded to the weak NTLMv1 session protection.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec to 537395200 (\"Network security: Minimum session security for NTLM SSP based clients\" = Require NTLMv2 session security, Require 128-bit encryption).",
		SQL:         regSQL(lsaKey+`MSV1_0\NTLMMinClientSec`, "v IS NOT NULL AND (CAST(v AS INTEGER) & 537395200) = 537395200", "'NTLMMinClientSec is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-rdp-nla-required",
		Title:       "Remote Desktop requires Network Level Authentication",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("AC-17,IA-2"),
		Description: "Network Level Authentication makes users authenticate before a Remote Desktop session is created, which shields the logon screen and the RDP service from unauthenticated attacks.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication to 1, or enable \"Require user authentication for remote connections by using Network Level Authentication\" in Group Policy.",
		SQL: verdict(`SELECT
    coalesce(`+reg(termSrvPol+`fDenyTSConnections`)+`, `+reg(termSrv+`fDenyTSConnections`)+`, '1') AS deny,
    coalesce(`+reg(termSrvPol+`UserAuthentication`)+`, `+reg(termSrv+`WinStations\RDP-Tcp\UserAuthentication`)+`, '1') AS nla`,
			"deny = '1'", "'Remote Desktop is not enabled'",
			"nla = '1'", "'Remote Desktop is enabled without Network Level Authentication'"),
	},
	{
		ID:          "windows-wdigest-disabled",
		Title:       "WDigest does not keep clear-text passwords in memory",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("IA-5(1),SC-28"),
		Description: "When WDigest caches logon credentials, tools such as Mimikatz can read users' clear-text passwords straight out of LSASS memory.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0 (or delete it on Windows 8.1 / Server 2012 R2 and later).",
		SQL:         regSQL(hklm+`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`, "v IS NULL OR v = '0'", "'UseLogonCredential is ' || v"),
	},
	{
		ID:          "windows-lsa-protection",
		Title:       "LSA runs as a protected process",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AC-6,SC-3"),
		Description: "Running LSASS as a protected process stops unsigned code, including most credential-dumping tools, from reading its memory.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1 (DWORD) and restart; test drivers and plug-ins that load into LSA first.",
		SQL:         regSQL(lsaKey+`RunAsPPL`, "v IN ('1', '2')", "'RunAsPPL is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-autorun-disabled",
		Title:       "AutoRun is off for all drive types",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("CM-7,SI-3"),
		Description: "AutoRun can start programs from removable media or network drives as soon as they are attached, a classic way for malware to spread.",
		Remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 255 (Group Policy: \"Turn off Autoplay\" = Enabled, All drives).",
		SQL:         regSQL(hklm+`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun`, "v = '255'", "'NoDriveTypeAutoRun is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-powershell-script-block-logging",
		Title:       "PowerShell script block logging is on",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AU-2,AU-3,AU-12"),
		Description: "Script block logging records the code PowerShell actually runs, including de-obfuscated attacker scripts, in the event log for detection and investigation.",
		Remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging to 1 (Group Policy: \"Turn on PowerShell Script Block Logging\" = Enabled).",
		SQL:         regSQL(hklm+`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging`, "v = '1'", "'EnableScriptBlockLogging is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-powershell-v2-removed",
		Title:       "The PowerShell 2.0 engine is not installed",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("CM-7"),
		Description: "PowerShell 2.0 lacks script block logging and AMSI, so attackers invoke it to run scripts without being logged or scanned.",
		Remediation: "Run \"Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root\" (on Windows Server: \"Uninstall-WindowsFeature PowerShell-V2\").",
		SQL: verdict(`SELECT count(*) AS n, sum(state = 1) AS enabled FROM windows_optional_features
  WHERE name IN ('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')`,
			"n = 0", "'the PowerShell 2.0 feature is not offered on this Windows version'",
			"enabled = 0", "'the PowerShell 2.0 optional feature is enabled'"),
	},
	{
		ID:          "windows-remote-registry-disabled",
		Title:       "The Remote Registry service is disabled",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("CM-7"),
		Description: "Remote Registry lets other machines read and change this host's registry over the network, which attackers use for reconnaissance and lateral movement.",
		Remediation: "Run \"Set-Service RemoteRegistry -StartupType Disabled; Stop-Service RemoteRegistry\".",
		SQL: verdict(`SELECT count(*) AS n, max(start_type) AS start_type, max(status) AS status FROM services WHERE name = 'RemoteRegistry'`,
			"", "", "n = 0 OR start_type = 'DISABLED'",
			"'RemoteRegistry start type is ' || coalesce(start_type, '?') || ', status ' || coalesce(status, '?')"),
	},
	{
		ID:          "windows-inactivity-lock",
		Title:       "The machine locks after 15 minutes or less of inactivity",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AC-11"),
		Description: "An unattended unlocked session lets anyone nearby act as the signed-in user.",
		Remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs to 900 or less (\"Interactive logon: Machine inactivity limit\").",
		SQL:         regSQL(polSystem+`InactivityTimeoutSecs`, "v IS NOT NULL AND CAST(v AS INTEGER) BETWEEN 1 AND 900", "'InactivityTimeoutSecs is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-audit-process-command-line",
		Title:       "Process creation events include the command line",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AU-3,AU-12"),
		Description: "Including command lines in process creation events (4688) shows what attackers actually ran, not just which program.",
		Remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled to 1 and enable the \"Audit Process Creation\" subcategory with \"auditpol /set /subcategory:\"Process Creation\" /success:enable\".",
		SQL:         regSQL(polSystem+`Audit\ProcessCreationIncludeCmdLine_Enabled`, "v = '1'", "'ProcessCreationIncludeCmdLine_Enabled is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-smb-server-signing",
		Title:       "The SMB server requires packet signing",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("SC-8"),
		Description: "Required SMB signing stops attackers from tampering with file-sharing traffic or relaying captured NTLM authentications to this host.",
		Remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature to 1 (\"Microsoft network server: Digitally sign communications (always)\" = Enabled).",
		SQL:         regSQL(lanmanSrv+`RequireSecuritySignature`, "v = '1'", "'RequireSecuritySignature is ' || coalesce(v, 'not set')"),
	},
	{
		ID:          "windows-llmnr-disabled",
		Title:       "LLMNR name resolution is turned off",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("CM-7"),
		Description: "LLMNR broadcasts name lookups on the local network, and any machine can answer them to capture the client's NTLM credentials.",
		Remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast to 0 (Group Policy: \"Turn off multicast name resolution\" = Enabled).",
		SQL:         regSQL(hklm+`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast`, "v = '0'", "'EnableMulticast is ' || coalesce(v, 'not set (LLMNR on)')"),
	},
	{
		ID:          "windows-password-min-length",
		Title:       "Local passwords must be at least 14 characters",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("IA-5(1)"),
		Description: "Longer passwords take far longer to guess or crack, which matters most for local accounts that are not covered by domain policy.",
		Remediation: "Run \"net accounts /minpwlen:14\", or set \"Minimum password length\" to 14 in Local Security Policy or Group Policy.",
		SQL:         secPolicySQL("minimum_password_length", "v >= 14", "'minimum password length is ' || v"),
	},
	{
		ID:          "windows-password-complexity",
		Title:       "Local passwords must meet complexity requirements",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("IA-5(1)"),
		Description: "Complexity rules block the most common guessable passwords such as names and single dictionary words.",
		Remediation: "Set \"Password must meet complexity requirements\" to Enabled in Local Security Policy or Group Policy.",
		SQL:         secPolicySQL("password_complexity", "v = 1", "'password complexity is off'"),
	},
	{
		ID:          "windows-account-lockout",
		Title:       "Accounts lock after 10 or fewer failed sign-ins",
		Platform:    "windows",
		Severity:    "medium",
		References:  refs("AC-7"),
		Description: "A lockout threshold stops online password guessing against local accounts.",
		Remediation: "Run \"net accounts /lockoutthreshold:10\", or set \"Account lockout threshold\" to 10 or fewer in Local Security Policy or Group Policy.",
		SQL:         secPolicySQL("lockout_bad_count", "v BETWEEN 1 AND 10", "CASE WHEN v = 0 THEN 'accounts never lock out' ELSE 'lockout threshold is ' || v END"),
	},
	{
		ID:          "windows-no-reversible-passwords",
		Title:       "Passwords are not stored with reversible encryption",
		Platform:    "windows",
		Severity:    "high",
		References:  refs("IA-5(1)"),
		Description: "Reversible encryption is effectively clear text: anyone who obtains the account database can recover the passwords.",
		Remediation: "Set \"Store passwords using reversible encryption\" to Disabled in Local Security Policy or Group Policy, then have affected users change their passwords.",
		SQL:         secPolicySQL("clear_text_password", "v = 0", "'passwords are stored with reversible encryption'"),
	},
}
