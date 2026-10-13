package checks

import (
	"fmt"
	"strings"
)

// sshdSQL checks one global keyword in /etc/ssh/sshd_config. In pass and
// failDetail, v is the keyword's first value outside any Match block,
// lowercased, or NULL when the keyword is not set.
func sshdSQL(keyword, pass, failDetail string) string {
	inner := fmt.Sprintf(`SELECT
    (SELECT count(*) FROM file WHERE path = '/etc/ssh/sshd_config') AS present,
    (SELECT count(*) FROM augeas WHERE path = '/etc/ssh/sshd_config') AS parsed,
    (SELECT lower(value) FROM augeas WHERE path = '/etc/ssh/sshd_config'
       AND lower(label) = %s
       AND node GLOB '/files/etc/ssh/sshd_config/*'
       AND node NOT GLOB '/files/etc/ssh/sshd_config/*/*'
     ORDER BY node LIMIT 1) AS v`, sqlQuote(strings.ToLower(keyword)))
	return verdict(inner,
		"present = 0 OR parsed = 0",
		"CASE WHEN present = 0 THEN 'no /etc/ssh/sshd_config (OpenSSH server not installed)' ELSE '/etc/ssh/sshd_config could not be parsed' END",
		pass, failDetail)
}

// sshdListSQL checks the items of a comma-separated sshd_config keyword such
// as Ciphers or MACs. n is the number of items configured (0 when the keyword
// is unset) and bad lists the items matching badCond (NULL when none).
func sshdListSQL(keyword, badCond, pass, failDetail string) string {
	k := strings.ToLower(keyword)
	items := fmt.Sprintf(`FROM augeas WHERE path = '/etc/ssh/sshd_config'
       AND (lower(node) GLOB '/files/etc/ssh/sshd_config/%[1]s/*' OR lower(node) GLOB '/files/etc/ssh/sshd_config/%[1]s[[]1]/*')
       AND node NOT GLOB '/files/etc/ssh/sshd_config/*/*/*'`, k)
	inner := fmt.Sprintf(`SELECT
    (SELECT count(*) FROM file WHERE path = '/etc/ssh/sshd_config') AS present,
    (SELECT count(*) FROM augeas WHERE path = '/etc/ssh/sshd_config') AS parsed,
    (SELECT count(*) %[1]s) AS n,
    (SELECT group_concat(value, ', ') %[1]s AND (%[2]s)) AS bad`, items, badCond)
	return verdict(inner,
		"present = 0 OR parsed = 0",
		"CASE WHEN present = 0 THEN 'no /etc/ssh/sshd_config (OpenSSH server not installed)' ELSE '/etc/ssh/sshd_config could not be parsed' END",
		pass, failDetail)
}

// loginDefsSQL checks one key in /etc/login.defs. v is its value or NULL.
func loginDefsSQL(key, pass, failDetail string) string {
	inner := fmt.Sprintf(`SELECT
    (SELECT count(*) FROM file WHERE path = '/etc/login.defs') AS present,
    (SELECT count(*) FROM augeas WHERE path = '/etc/login.defs') AS parsed,
    (SELECT value FROM augeas WHERE path = '/etc/login.defs' AND label = %s ORDER BY node LIMIT 1) AS v`, sqlQuote(key))
	return verdict(inner,
		"present = 0 OR parsed = 0",
		"CASE WHEN present = 0 THEN 'no /etc/login.defs' ELSE '/etc/login.defs could not be parsed' END",
		pass, failDetail)
}

// sysctlSQL checks a kernel parameter's running value. v is the value as an
// integer; the check is n/a when the kernel does not expose the parameter.
func sysctlSQL(name, pass, want string) string {
	inner := fmt.Sprintf(`SELECT raw, CAST(raw AS INTEGER) AS v FROM (SELECT
    (SELECT trim(current_value) FROM system_controls WHERE name = %s) AS raw)`, sqlQuote(name))
	return verdict(inner,
		"raw IS NULL OR raw = ''",
		sqlQuote("kernel parameter "+name+" is not available on this kernel"),
		pass,
		fmt.Sprintf("%s || raw || %s", sqlQuote(name+" is "), sqlQuote(", expected "+want)))
}

// modeWithin returns an SQL condition that holds when the octal permission
// string in column col grants nothing beyond max (for example "0640") and has
// no setuid, setgid or sticky bit.
func modeWithin(col, max string) string {
	max = strings.TrimLeft(max, "0")
	for len(max) < 3 {
		max = "0" + max
	}
	conds := []string{
		fmt.Sprintf("length(%s) >= 3", col),
		fmt.Sprintf("CAST(substr(%[1]s, 1, length(%[1]s) - 3) AS INTEGER) = 0", col),
	}
	for i := 0; i < 3; i++ {
		conds = append(conds, fmt.Sprintf("(CAST(substr(%s, %d, 1) AS INTEGER) & ~%c) = 0", col, i-3, max[i]))
	}
	return strings.Join(conds, " AND ")
}

// fileSQL checks that path is owned by root, has a group in groups (by name;
// gid 0 is always accepted) and is no more permissive than maxMode. It is n/a
// when the path does not exist.
func fileSQL(path, maxMode string, groups ...string) string {
	gs := []string{"'root'"}
	for _, g := range groups {
		gs = append(gs, sqlQuote(g))
	}
	inner := fmt.Sprintf(`SELECT
    (SELECT count(*) FROM file WHERE path = %[1]s) AS present,
    (SELECT mode FROM file WHERE path = %[1]s) AS mode,
    (SELECT uid FROM file WHERE path = %[1]s) AS uid,
    (SELECT gid FROM file WHERE path = %[1]s) AS gid,
    (SELECT count(*) FROM file f JOIN groups g ON g.gid = f.gid WHERE f.path = %[1]s AND g.groupname IN (%[2]s)) AS group_ok`,
		sqlQuote(path), strings.Join(gs, ", "))
	want := "owner root, group " + strings.Join(append([]string{"root"}, groups...), " or ") + ", mode " + maxMode + " or stricter"
	return verdict(inner,
		"present = 0",
		sqlQuote(path+" does not exist"),
		fmt.Sprintf("uid = 0 AND (gid = 0 OR group_ok > 0) AND %s", modeWithin("mode", maxMode)),
		fmt.Sprintf("%s || mode || ' uid ' || uid || ' gid ' || gid || %s", sqlQuote(path+" has mode "), sqlQuote("; expected "+want)))
}

// absentSQL passes when none of the given files exist; it is used to show a
// network service binary is not installed, on both Debian and RHEL families.
func absentSQL(what string, paths ...string) string {
	qs := make([]string, len(paths))
	for i, p := range paths {
		qs[i] = sqlQuote(p)
	}
	inner := fmt.Sprintf(`SELECT count(*) AS n, group_concat(path, ', ') AS found FROM file WHERE path IN (%s)`, strings.Join(qs, ", "))
	return verdict(inner, "", "", "n = 0", fmt.Sprintf("%s || found", sqlQuote(what+" is installed: ")))
}

// mountOptSQL checks that every mount of path carries option. It is n/a when
// path is not a separate mount.
func mountOptSQL(path, option string) string {
	inner := fmt.Sprintf(`SELECT count(*) AS n,
    sum((',' || flags || ',') NOT LIKE %s) AS bad,
    group_concat(flags, ' | ') AS flags
  FROM mounts WHERE path = %s`, sqlQuote("%,"+option+",%"), sqlQuote(path))
	return verdict(inner,
		"n = 0",
		sqlQuote(path+" is not a separate mount"),
		"bad = 0",
		fmt.Sprintf("%s || flags", sqlQuote(path+" is mounted without "+option+": ")))
}

const (
	auditdPaths = `'/sbin/auditd', '/usr/sbin/auditd'`
)

var linuxChecks = []Check{
	// --- SSH server ---------------------------------------------------
	{
		ID:          "linux-sshd-disable-root-login",
		Title:       "SSH does not allow root to sign in",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_disable_root_login",
		References:  refs("AC-6(2),AC-17(a),IA-2,IA-2(5),CM-7(a),CM-7(b),CM-6(a)"),
		Description: "Direct root logins over SSH leave no record of which person used the account and give attackers a single, well-known target for password guessing.",
		Remediation: "Set \"PermitRootLogin no\" in /etc/ssh/sshd_config (before any Match block) and reload the SSH service with \"systemctl reload sshd\" (or \"ssh\" on Debian/Ubuntu). Administrators should sign in as themselves and use sudo.",
		SQL:         sshdSQL("PermitRootLogin", "v = 'no'", "'PermitRootLogin is ' || coalesce(v, 'not set (OpenSSH default prohibit-password)')"),
	},
	{
		ID:          "linux-sshd-disable-empty-passwords",
		Title:       "SSH refuses logins to accounts with empty passwords",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "sshd_disable_empty_passwords",
		References:  refs("AC-17(a),CM-7(a),CM-7(b),CM-6(a)"),
		Description: "If the SSH server accepts empty passwords, any account without a password can be entered remotely by anyone who knows its name.",
		Remediation: "Set \"PermitEmptyPasswords no\" in /etc/ssh/sshd_config, or remove the line to use the safe default, then reload the SSH service.",
		SQL:         sshdSQL("PermitEmptyPasswords", "v IS NULL OR v = 'no'", "'PermitEmptyPasswords is ' || v"),
	},
	{
		ID:          "linux-sshd-max-auth-tries",
		Title:       "SSH limits authentication attempts per connection to 4 or fewer",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_set_max_auth_tries",
		Description: "A low per-connection limit slows down password guessing and makes brute-force attempts show up sooner in the logs.",
		Remediation: "Set \"MaxAuthTries 4\" (or lower) in /etc/ssh/sshd_config and reload the SSH service.",
		SQL:         sshdSQL("MaxAuthTries", "v IS NOT NULL AND CAST(v AS INTEGER) BETWEEN 1 AND 4", "'MaxAuthTries is ' || coalesce(v, 'not set (OpenSSH default 6)')"),
	},
	{
		ID:          "linux-sshd-disable-x11-forwarding",
		Title:       "SSH does not forward X11 connections",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_disable_x11_forwarding",
		References:  refs("CM-6(b)"),
		Description: "X11 forwarding lets a compromised server reach back into the client's graphical session, for example to capture keystrokes; servers rarely need it.",
		Remediation: "Set \"X11Forwarding no\" in /etc/ssh/sshd_config and reload the SSH service.",
		SQL:         sshdSQL("X11Forwarding", "v IS NULL OR v = 'no'", "'X11Forwarding is ' || v"),
	},
	{
		ID:          "linux-sshd-protocol-2-only",
		Title:       "SSH accepts only protocol version 2",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "sshd_allow_only_protocol2",
		References:  refs("CM-6(a),AC-17(a),AC-17(2),IA-5(1)(c),SC-13,MA-4(6)"),
		Description: "SSH protocol 1 has known cryptographic weaknesses that allow session hijacking; modern OpenSSH only speaks protocol 2, but an explicit \"Protocol 1\" line signals an old or misconfigured server.",
		Remediation: "Remove any Protocol line from /etc/ssh/sshd_config or set \"Protocol 2\", and upgrade OpenSSH if it still supports protocol 1.",
		SQL:         sshdSQL("Protocol", "v IS NULL OR v = '2'", "'Protocol is ' || v"),
	},
	{
		ID:          "linux-sshd-strong-ciphers",
		Title:       "SSH does not offer weak ciphers",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_use_strong_ciphers",
		Description: "CBC-mode, RC4 (arcfour), 3DES, Blowfish and CAST ciphers are vulnerable to known attacks; offering them lets a client or attacker negotiate a weak session.",
		Remediation: "In /etc/ssh/sshd_config set a Ciphers line with only modern ciphers, for example \"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\", then reload the SSH service. Leaving Ciphers unset uses OpenSSH's modern defaults.",
		SQL: sshdListSQL("Ciphers",
			"lower(value) LIKE '%cbc%' OR lower(value) LIKE '%arcfour%' OR lower(value) LIKE '%3des%' OR lower(value) LIKE '%blowfish%' OR lower(value) LIKE '%cast128%' OR lower(value) LIKE '%rijndael%'",
			"bad IS NULL", "'weak ciphers configured: ' || bad"),
	},
	{
		ID:          "linux-sshd-strong-macs",
		Title:       "SSH uses only strong message authentication codes",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_use_strong_macs",
		References:  refs("AC-17(2)"),
		Description: "MD5, SHA-1 and 64-bit MACs give weaker integrity protection for the session; OpenSSH still enables some of them by default, so the list should be set explicitly.",
		Remediation: "Add \"MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\" to /etc/ssh/sshd_config and reload the SSH service.",
		SQL: sshdListSQL("MACs",
			"lower(value) LIKE '%md5%' OR lower(value) LIKE '%sha1%' OR lower(value) LIKE '%umac-64%' OR lower(value) LIKE '%ripemd%' OR lower(value) LIKE '%-96%' OR value LIKE '+%' OR value LIKE '^%'",
			"n > 0 AND bad IS NULL",
			"CASE WHEN n = 0 THEN 'MACs is not set; the OpenSSH default list includes SHA-1 and 64-bit MACs' ELSE 'weak MACs configured: ' || bad END"),
	},
	{
		ID:          "linux-sshd-ignore-rhosts",
		Title:       "SSH ignores .rhosts and .shosts files",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_disable_rhosts",
		References:  refs("AC-17(a),CM-7(a),CM-7(b),CM-6(a)"),
		Description: "Host-based trust files let users grant password-free access from other machines, bypassing normal authentication.",
		Remediation: "Set \"IgnoreRhosts yes\" in /etc/ssh/sshd_config, or remove the line to use the default, then reload the SSH service.",
		SQL:         sshdSQL("IgnoreRhosts", "v IS NULL OR v = 'yes'", "'IgnoreRhosts is ' || v"),
	},
	{
		ID:          "linux-sshd-no-user-environment",
		Title:       "SSH does not let users pass environment options to the server",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sshd_do_not_permit_user_env",
		References:  refs("AC-17(a),CM-7(a),CM-7(b),CM-6(a)"),
		Description: "Letting users set environment variables such as LD_PRELOAD through ~/.ssh/environment can be used to bypass restricted shells and command restrictions.",
		Remediation: "Set \"PermitUserEnvironment no\" in /etc/ssh/sshd_config, or remove the line to use the default, then reload the SSH service.",
		SQL:         sshdSQL("PermitUserEnvironment", "v IS NULL OR v = 'no'", "'PermitUserEnvironment is ' || v"),
	},
	{
		ID:          "linux-sshd-config-permissions",
		Title:       "The SSH server configuration is readable only by root",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_sshd_config",
		References:  refs("AC-17(a),CM-6(a),AC-6(1)"),
		Description: "If other users can change sshd_config they can weaken or open up remote access; keeping it private also hides details useful to an attacker.",
		Remediation: "Run \"chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config\".",
		SQL:         fileSQL("/etc/ssh/sshd_config", "0600"),
	},

	// --- Password and account policy ----------------------------------
	{
		ID:          "linux-password-max-age",
		Title:       "New passwords expire within 365 days",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "accounts_maximum_age_login_defs",
		References:  refs("IA-5(f),IA-5(1)(d),CM-6(a)"),
		Description: "A maximum password age bounds how long a stolen or guessed password stays useful.",
		Remediation: "Set \"PASS_MAX_DAYS 365\" (or your policy's lower value) in /etc/login.defs; for existing accounts run \"chage --maxdays 365 <user>\".",
		SQL:         loginDefsSQL("PASS_MAX_DAYS", "v IS NOT NULL AND CAST(v AS INTEGER) BETWEEN 1 AND 365", "'PASS_MAX_DAYS is ' || coalesce(v, 'not set (no expiry)')"),
	},
	{
		ID:          "linux-password-min-age",
		Title:       "Passwords cannot be changed again for at least one day",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "accounts_minimum_age_login_defs",
		References:  refs("IA-5(f),IA-5(1)(d),CM-6(a)"),
		Description: "A minimum age stops users from cycling through several changes at once to get back to an old password and defeat password history.",
		Remediation: "Set \"PASS_MIN_DAYS 1\" in /etc/login.defs; for existing accounts run \"chage --mindays 1 <user>\".",
		SQL:         loginDefsSQL("PASS_MIN_DAYS", "v IS NOT NULL AND CAST(v AS INTEGER) >= 1", "'PASS_MIN_DAYS is ' || coalesce(v, 'not set (0)')"),
	},
	{
		ID:          "linux-password-warn-age",
		Title:       "Users are warned at least 7 days before a password expires",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "accounts_password_warn_age_login_defs",
		References:  refs("IA-5(f),IA-5(1)(d),CM-6(a)"),
		Description: "Advance warning gives users time to choose a good new password instead of being locked out or rushed into a weak one.",
		Remediation: "Set \"PASS_WARN_AGE 7\" (or more) in /etc/login.defs.",
		SQL:         loginDefsSQL("PASS_WARN_AGE", "v IS NULL OR CAST(v AS INTEGER) >= 7", "'PASS_WARN_AGE is ' || v"),
	},
	{
		ID:          "linux-no-empty-passwords",
		Title:       "No account has an empty password",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "no_empty_passwords_etc_shadow",
		References:  refs("CM-6(b),CM-6.1(iv)"),
		Description: "An account with an empty password field can be entered by anyone who knows the user name, locally and often remotely.",
		Remediation: "Lock the account with \"passwd -l <user>\" or set a password with \"passwd <user>\".",
		SQL: verdict(`SELECT
    (SELECT count(*) FROM file WHERE path = '/etc/shadow') AS present,
    (SELECT count(*) FROM shadow WHERE password_status = 'empty') AS n,
    (SELECT group_concat(username, ', ') FROM shadow WHERE password_status = 'empty') AS names`,
			"present = 0", "'no /etc/shadow'",
			"n = 0", "'accounts with an empty password: ' || names"),
	},
	{
		ID:          "linux-only-root-has-uid-0",
		Title:       "Only root has user ID 0",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "accounts_no_uid_except_zero",
		References:  refs("IA-2,AC-6(5),IA-4(b)"),
		Description: "Any account with UID 0 has full root privileges; an extra one is a common backdoor and hides who performed administrative actions.",
		Remediation: "Give the extra account a unique non-zero UID with \"usermod -u <new-uid> <user>\" or remove it with \"userdel <user>\".",
		SQL: verdict(`SELECT count(*) AS n, group_concat(username, ', ') AS names FROM users WHERE uid = 0 AND username != 'root'`,
			"", "", "n = 0", "'accounts other than root with UID 0: ' || names"),
	},

	// --- Critical file permissions ------------------------------------
	{
		ID:          "linux-passwd-permissions",
		Title:       "/etc/passwd is owned by root and not writable by others",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_etc_passwd",
		References:  refs("CM-6(a),AC-6(1)"),
		Description: "Anyone who can write /etc/passwd can create accounts or give themselves root.",
		Remediation: "Run \"chown root:root /etc/passwd && chmod 0644 /etc/passwd\".",
		SQL:         fileSQL("/etc/passwd", "0644"),
	},
	{
		ID:          "linux-shadow-permissions",
		Title:       "/etc/shadow is readable only by root and the shadow group",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_etc_shadow",
		References:  refs("CM-6(a),AC-6(1)"),
		Description: "/etc/shadow holds password hashes; anyone who can read it can try to crack them offline.",
		Remediation: "Run \"chown root:root /etc/shadow && chmod 0000 /etc/shadow\" on RHEL-family hosts, or \"chown root:shadow /etc/shadow && chmod 0640 /etc/shadow\" on Debian/Ubuntu.",
		SQL:         fileSQL("/etc/shadow", "0640", "shadow"),
	},
	{
		ID:          "linux-group-permissions",
		Title:       "/etc/group is owned by root and not writable by others",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_etc_group",
		References:  refs("CM-6(a),AC-6(1)"),
		Description: "Anyone who can write /etc/group can add themselves to privileged groups such as sudo or wheel.",
		Remediation: "Run \"chown root:root /etc/group && chmod 0644 /etc/group\".",
		SQL:         fileSQL("/etc/group", "0644"),
	},
	{
		ID:          "linux-gshadow-permissions",
		Title:       "/etc/gshadow is readable only by root and the shadow group",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_etc_gshadow",
		References:  refs("CM-6(a),AC-6(1)"),
		Description: "/etc/gshadow holds group passwords and administrator lists; exposing it helps attackers join privileged groups.",
		Remediation: "Run \"chown root:root /etc/gshadow && chmod 0000 /etc/gshadow\" on RHEL-family hosts, or \"chown root:shadow /etc/gshadow && chmod 0640 /etc/gshadow\" on Debian/Ubuntu.",
		SQL:         fileSQL("/etc/gshadow", "0640", "shadow"),
	},
	{
		ID:          "linux-crontab-permissions",
		Title:       "/etc/crontab is readable and writable only by root",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_crontab",
		References:  refs("CM-6(a),AC-6(1)"),
		Description: "The system crontab runs commands as root; if others can change it they gain root, and if they can read it they learn what runs and when.",
		Remediation: "Run \"chown root:root /etc/crontab && chmod 0600 /etc/crontab\".",
		SQL:         fileSQL("/etc/crontab", "0600"),
	},
	{
		ID:          "linux-cron-d-permissions",
		Title:       "/etc/cron.d is accessible only by root",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "file_permissions_cron_d",
		References:  refs("CM-6(a),AC-6(1)"),
		Description: "Jobs dropped into /etc/cron.d run with the privileges they name, often root, so the directory must not be open to other users.",
		Remediation: "Run \"chown root:root /etc/cron.d && chmod 0700 /etc/cron.d\".",
		SQL:         fileSQL("/etc/cron.d", "0700"),
	},

	// --- Kernel parameters --------------------------------------------
	{
		ID:          "linux-sysctl-ip-forward",
		Title:       "The host does not route IPv4 packets",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_net_ipv4_ip_forward",
		References:  refs("CM-7(a),CM-7(b),SC-5,CM-6(a),SC-7(a)"),
		Description: "A host that forwards packets can be used to bypass network segmentation; only routers and container hosts that need it should enable forwarding.",
		Remediation: "Set \"net.ipv4.ip_forward = 0\" in a file under /etc/sysctl.d/ and run \"sysctl --system\" (skip on hosts that must route, such as container hosts).",
		SQL:         sysctlSQL("net.ipv4.ip_forward", "v = 0", "0"),
	},
	{
		ID:          "linux-sysctl-accept-redirects",
		Title:       "The host ignores ICMP redirects",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_net_ipv4_conf_all_accept_redirects",
		References:  refs("CM-7(a),CM-7(b),CM-6(a),SC-7(a)"),
		Description: "Accepting ICMP redirects lets anyone on the local network change the host's routing table and intercept its traffic.",
		Remediation: "Set \"net.ipv4.conf.all.accept_redirects = 0\" and \"net.ipv4.conf.default.accept_redirects = 0\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("net.ipv4.conf.all.accept_redirects", "v = 0", "0"),
	},
	{
		ID:          "linux-sysctl-send-redirects",
		Title:       "The host does not send ICMP redirects",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_net_ipv4_conf_all_send_redirects",
		References:  refs("CM-7(a),CM-7(b),SC-5,CM-6(a),SC-7(a)"),
		Description: "Only routers need to send redirects; a host that sends them can be abused to steer other machines' traffic.",
		Remediation: "Set \"net.ipv4.conf.all.send_redirects = 0\" and \"net.ipv4.conf.default.send_redirects = 0\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("net.ipv4.conf.all.send_redirects", "v = 0", "0"),
	},
	{
		ID:          "linux-sysctl-accept-source-route",
		Title:       "The host drops source-routed packets",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_net_ipv4_conf_all_accept_source_route",
		References:  refs("CM-7(a),CM-7(b),SC-5,CM-6(a),SC-7(a)"),
		Description: "Source routing lets the sender choose the path a packet takes, which can be used to reach hosts behind a firewall.",
		Remediation: "Set \"net.ipv4.conf.all.accept_source_route = 0\" and \"net.ipv4.conf.default.accept_source_route = 0\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("net.ipv4.conf.all.accept_source_route", "v = 0", "0"),
	},
	{
		ID:          "linux-sysctl-rp-filter",
		Title:       "Reverse-path filtering is on",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_net_ipv4_conf_all_rp_filter",
		References:  refs("CM-7(a),CM-7(b),CM-6(a),SC-7(a)"),
		Description: "Reverse-path filtering drops packets whose source address could not have arrived on that interface, which blocks many spoofing attacks.",
		Remediation: "Set \"net.ipv4.conf.all.rp_filter = 1\" (strict; 2 for loose on multi-homed hosts) in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("net.ipv4.conf.all.rp_filter", "v IN (1, 2)", "1 (strict) or 2 (loose)"),
	},
	{
		ID:          "linux-sysctl-tcp-syncookies",
		Title:       "TCP SYN cookies are on",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_net_ipv4_tcp_syncookies",
		References:  refs("CM-7(a),CM-7(b),SC-5(1),SC-5(2),SC-5(3)(a),CM-6(a)"),
		Description: "SYN cookies keep the host accepting legitimate connections during a SYN flood instead of exhausting its connection queue.",
		Remediation: "Set \"net.ipv4.tcp_syncookies = 1\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("net.ipv4.tcp_syncookies", "v = 1", "1"),
	},
	{
		ID:          "linux-sysctl-randomize-va-space",
		Title:       "Full address space layout randomization is on",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_kernel_randomize_va_space",
		References:  refs("SC-30,SC-30(2),CM-6(a)"),
		Description: "Randomizing where the stack, heap and libraries load makes memory-corruption exploits much harder to write reliably.",
		Remediation: "Set \"kernel.randomize_va_space = 2\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("kernel.randomize_va_space", "v = 2", "2"),
	},
	{
		ID:          "linux-sysctl-kptr-restrict",
		Title:       "Kernel pointers are hidden from unprivileged users",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_kernel_kptr_restrict",
		References:  refs("SC-30,SC-30(2),SC-30(5),CM-6(a)"),
		Description: "Kernel addresses in /proc and logs help attackers defeat kernel address randomization when exploiting a kernel bug.",
		Remediation: "Set \"kernel.kptr_restrict = 1\" (or 2) in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("kernel.kptr_restrict", "v >= 1", "1 or 2"),
	},
	{
		ID:          "linux-sysctl-dmesg-restrict",
		Title:       "Only privileged users can read the kernel log",
		Platform:    "linux",
		Severity:    "low",
		RuleID:      "sysctl_kernel_dmesg_restrict",
		References:  refs("SI-11(a),SI-11(b)"),
		Description: "The kernel ring buffer can reveal memory addresses and hardware details useful for local privilege escalation.",
		Remediation: "Set \"kernel.dmesg_restrict = 1\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("kernel.dmesg_restrict", "v = 1", "1"),
	},
	{
		ID:          "linux-sysctl-ptrace-scope",
		Title:       "Processes cannot attach a debugger to unrelated processes",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_kernel_yama_ptrace_scope",
		References:  refs("SC-7(10)"),
		Description: "Unrestricted ptrace lets any process read the memory of other processes of the same user, such as credentials held by an SSH agent or browser.",
		Remediation: "Set \"kernel.yama.ptrace_scope = 1\" (or higher) in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("kernel.yama.ptrace_scope", "v >= 1", "1 or higher"),
	},
	{
		ID:          "linux-sysctl-suid-dumpable",
		Title:       "Setuid programs do not write core dumps",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "sysctl_fs_suid_dumpable",
		References:  refs("SI-11(a),SI-11(b)"),
		Description: "Core dumps of privileged programs can contain password hashes, keys and other secrets that ordinary users could then read.",
		Remediation: "Set \"fs.suid_dumpable = 0\" in /etc/sysctl.d/ and run \"sysctl --system\".",
		SQL:         sysctlSQL("fs.suid_dumpable", "v = 0", "0"),
	},

	// --- Services and packages ----------------------------------------
	{
		ID:          "linux-telnet-server-absent",
		Title:       "No telnet server is installed",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "package_telnet-server_removed",
		References:  refs("CM-7(a),CM-7(b),CM-6(a)"),
		Description: "Telnet sends passwords and whole sessions in clear text; SSH should be used instead.",
		Remediation: "Remove the server package: \"dnf remove telnet-server\" on RHEL-family hosts or \"apt purge telnetd inetutils-telnetd\" on Debian/Ubuntu.",
		SQL:         absentSQL("a telnet server", "/usr/sbin/in.telnetd", "/usr/sbin/telnetd", "/usr/libexec/telnetd"),
	},
	{
		ID:          "linux-rsh-server-absent",
		Title:       "No rsh, rlogin or rexec server is installed",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "package_rsh-server_removed",
		References:  refs("CM-7(a),CM-7(b),CM-6(a),IA-5(1)(c)"),
		Description: "The r-services send credentials in clear text and trust host names, which makes them easy to abuse.",
		Remediation: "Remove the server package: \"dnf remove rsh-server\" on RHEL-family hosts or \"apt purge rsh-server rsh-redone-server\" on Debian/Ubuntu.",
		SQL:         absentSQL("an r-services server", "/usr/sbin/in.rshd", "/usr/sbin/in.rlogind", "/usr/sbin/in.rexecd"),
	},
	{
		ID:          "linux-tftp-server-absent",
		Title:       "No TFTP server is installed",
		Platform:    "linux",
		Severity:    "high",
		RuleID:      "package_tftp-server_removed",
		References:  refs("CM-7(a),CM-7(b),CM-6(a)"),
		Description: "TFTP has no authentication at all, so any file it serves can be read, and sometimes written, by anyone who can reach it.",
		Remediation: "Remove the server package: \"dnf remove tftp-server\" on RHEL-family hosts or \"apt purge tftpd-hpa tftpd atftpd\" on Debian/Ubuntu, unless the host is a dedicated network-boot server.",
		SQL:         absentSQL("a TFTP server", "/usr/sbin/in.tftpd", "/usr/sbin/atftpd"),
	},
	{
		ID:          "linux-xinetd-absent",
		Title:       "xinetd is not installed",
		Platform:    "linux",
		Severity:    "low",
		RuleID:      "package_xinetd_removed",
		References:  refs("CM-7(a),CM-7(b),CM-6(a)"),
		Description: "xinetd starts legacy network services on demand; modern hosts rarely need it and it widens what the host exposes.",
		Remediation: "Remove it with \"dnf remove xinetd\" or \"apt purge xinetd\".",
		SQL:         absentSQL("xinetd", "/usr/sbin/xinetd"),
	},
	{
		ID:          "linux-avahi-not-running",
		Title:       "The Avahi (mDNS) daemon is not running",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "service_avahi-daemon_disabled",
		References:  refs("CM-7(a),CM-7(b),CM-6(a)"),
		Description: "Avahi advertises the host and its services on the local network, which servers do not need and which helps attackers map the network.",
		Remediation: "Run \"systemctl disable --now avahi-daemon.socket avahi-daemon.service\", or remove the avahi-daemon (Debian/Ubuntu) or avahi (RHEL) package.",
		SQL: verdict(`SELECT count(*) AS n FROM processes WHERE name = 'avahi-daemon'`,
			"", "", "n = 0", "'avahi-daemon is running'"),
	},
	{
		ID:          "linux-auditd-installed",
		Title:       "The Linux audit daemon is installed",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "package_audit_installed",
		References:  refs("AC-7(a),AU-7(1),AU-7(2),AU-14,AU-12(2),AU-2(a),CM-6(a)"),
		Description: "auditd records security-relevant kernel events such as logins, privilege use and changes to key files, which investigations depend on.",
		Remediation: "Install it with \"dnf install audit\" on RHEL-family hosts or \"apt install auditd\" on Debian/Ubuntu.",
		SQL: verdict(`SELECT count(*) AS n FROM file WHERE path IN (`+auditdPaths+`)`,
			"", "", "n > 0", "'auditd is not installed'"),
	},
	{
		ID:          "linux-auditd-running",
		Title:       "The Linux audit daemon is running",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "service_auditd_enabled",
		References:  refs("AC-2(g),AU-3,AU-10,AU-2(d),AU-12(c),AU-14(1),AC-6(9),CM-6(a),SI-4(23)"),
		Description: "An installed but stopped audit daemon records nothing, so security events go unlogged.",
		Remediation: "Run \"systemctl enable --now auditd\".",
		SQL: verdict(`SELECT
    (SELECT count(*) FROM file WHERE path IN (`+auditdPaths+`)) AS installed,
    (SELECT count(*) FROM processes WHERE name = 'auditd') AS running`,
			"installed = 0", "'auditd is not installed'",
			"running > 0", "'auditd is installed but not running'"),
	},
	{
		ID:          "linux-time-sync-running",
		Title:       "A time synchronization service is running",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "service_chronyd_or_ntpd_enabled",
		References:  refs("CM-6(a),AU-8(1)(a),AU-12(1)"),
		Description: "Accurate clocks are needed to correlate logs across hosts and for time-based authentication such as Kerberos and TOTP.",
		Remediation: "Run \"systemctl enable --now chronyd\" (RHEL-family) or \"systemctl enable --now chrony\" or \"systemctl enable --now systemd-timesyncd\" (Debian/Ubuntu).",
		SQL: verdict(`SELECT count(*) AS n FROM processes WHERE name IN ('chronyd', 'ntpd', 'openntpd', 'systemd-timesyn', 'systemd-timesyncd')`,
			"", "", "n > 0", "'no chronyd, ntpd or systemd-timesyncd process is running'"),
	},
	{
		ID:          "linux-firewall-active",
		Title:       "A host firewall service is active",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "service_firewalld_enabled",
		References:  refs("AC-4,CM-7(b),CA-3(5),SC-7(21),CM-6(a)"),
		Description: "A host firewall limits which services can be reached even when network firewalls are misconfigured or the attacker is already inside the network.",
		Remediation: "Run \"systemctl enable --now firewalld\" on RHEL-family hosts, or \"ufw enable\" on Ubuntu, or enable nftables with \"systemctl enable --now nftables\" and a ruleset in /etc/nftables.conf.",
		SQL: verdict(`SELECT
    (SELECT count(*) FROM processes WHERE name = 'firewalld') +
    (SELECT count(*) FROM systemd_units WHERE id IN ('firewalld.service', 'ufw.service', 'nftables.service', 'iptables.service', 'netfilter-persistent.service') AND active_state = 'active') AS n`,
			"", "", "n > 0", "'none of firewalld, ufw, nftables or iptables services is active'"),
	},

	// --- Mount options ------------------------------------------------
	{
		ID:          "linux-tmp-nodev",
		Title:       "/tmp is mounted with nodev",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "mount_option_tmp_nodev",
		References:  refs("CM-7(a),CM-7(b),CM-6(a),AC-6,AC-6(1),MP-7"),
		Description: "Device files have no place in a world-writable directory; nodev stops users from creating device nodes there to reach hardware directly.",
		Remediation: "Add nodev to the /tmp options in /etc/fstab (or the tmp.mount unit) and run \"mount -o remount,nodev /tmp\".",
		SQL:         mountOptSQL("/tmp", "nodev"),
	},
	{
		ID:          "linux-tmp-nosuid",
		Title:       "/tmp is mounted with nosuid",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "mount_option_tmp_nosuid",
		References:  refs("CM-7(a),CM-7(b),CM-6(a),AC-6,AC-6(1),MP-7"),
		Description: "nosuid stops setuid programs placed in a world-writable directory from gaining elevated privileges.",
		Remediation: "Add nosuid to the /tmp options in /etc/fstab (or the tmp.mount unit) and run \"mount -o remount,nosuid /tmp\".",
		SQL:         mountOptSQL("/tmp", "nosuid"),
	},
	{
		ID:          "linux-dev-shm-noexec",
		Title:       "/dev/shm is mounted with noexec",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "mount_option_dev_shm_noexec",
		References:  refs("CM-7(a),CM-7(b),CM-6(a),AC-6,AC-6(1),MP-7"),
		Description: "/dev/shm is writable by every user and is a favourite place for attackers to drop and run payloads; noexec blocks running programs from it.",
		Remediation: "Add \"tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0\" to /etc/fstab and run \"mount -o remount,noexec /dev/shm\".",
		SQL:         mountOptSQL("/dev/shm", "noexec"),
	},

	// --- Core dumps ---------------------------------------------------
	{
		ID:          "linux-core-dumps-restricted",
		Title:       "User core dumps are disabled",
		Platform:    "linux",
		Severity:    "medium",
		RuleID:      "disable_users_coredumps",
		References:  refs("CM-6,SC-7(10)"),
		Description: "Core dumps copy a process's memory to disk, which can leak passwords and keys and fill the disk; a hard limit of zero stops them.",
		Remediation: "Add the line \"* hard core 0\" to /etc/security/limits.conf or a file in /etc/security/limits.d/.",
		SQL: verdict(`SELECT
    (SELECT count(*) FROM file WHERE path = '/etc/security/limits.conf') AS present,
    (SELECT count(*) FROM augeas WHERE path = '/etc/security/limits.conf') AS parsed,
    (SELECT count(*) FROM (
      SELECT substr(i.node, 1, length(i.node) - 5) AS parent FROM augeas i
      WHERE (i.node LIKE '/files/etc/security/limits.conf/%%' OR i.node LIKE '/files/etc/security/limits.d/%%')
        AND i.label = 'item' AND i.value = 'core') AS d
    WHERE (SELECT value FROM augeas WHERE node = d.parent) = '*'
      AND (SELECT value FROM augeas WHERE node = d.parent || '/type') IN ('hard', '-')
      AND (SELECT value FROM augeas WHERE node = d.parent || '/value') = '0') AS n`,
			"present = 0 OR parsed = 0",
			"CASE WHEN present = 0 THEN 'no /etc/security/limits.conf (pam_limits not installed)' ELSE '/etc/security/limits.conf could not be parsed' END",
			"n > 0", "'no \"* hard core 0\" limit in /etc/security/limits.conf or limits.d'"),
	},
}
