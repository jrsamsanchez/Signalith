#!/bin/sh
# Loads OpenSearch's security settings for Signalith's Docker quick start:
# who may sign in (only certificates from Signalith's own OpenSearch CA)
# and what each may do (the files in security/). docker-compose.yml runs
# it as the opensearch-security service on every "docker compose up",
# once OpenSearch has started, and starts Signalith only after it succeeds.
#
# OpenSearch loads these files by itself only as it starts with none
# stored yet, and tries just once, which can fail on a slow computer: it
# then answers every request with "OpenSearch Security not initialized".
# So this checks, and loads the files with securityadmin.sh when
# OpenSearch has no settings loaded, or when the files are not the ones
# this loaded last (the first time it runs, after an update of Signalith,
# or after an edit). When OpenSearch doesn't take a file in time, it tries
# that file again on its own, waiting longer each time, for about 10
# minutes in all. Then it says what to do and fails.
#
# A POSIX sh script. docker-compose.yml runs a copy without Windows line
# endings (CRLF), which a checkout on Windows can give it.

set -u
cd /usr/share/opensearch || exit 1

# How long to keep trying, in seconds.
limit=${SECURITY_LOAD_SECONDS:-600}
host=opensearch
certs=config/certs
dir=config/opensearch-security
tool=plugins/opensearch-security/tools/securityadmin.sh
# A fingerprint of the files this last loaded, in this service's volume.
state=data/loaded-files.sha256
# Each kind of setting securityadmin.sh loads, and its file. The four in
# deploy/docker/opensearch/security are Signalith's; the image has the
# others.
kinds="config:config.yml roles:roles.yml rolesmapping:roles_mapping.yml
internalusers:internal_users.yml actiongroups:action_groups.yml
tenants:tenants.yml nodesdn:nodes_dn.yml whitelist:whitelist.yml
audit:audit.yml allowlist:allowlist.yml"

say() { printf '%s\n' "$*"; }
now() { date +%s; }
start=$(now)
deadline=$((start + limit))
# Nothing new is started after the deadline. What runs then may finish
# within a minute more, and no longer.
hard=$((deadline + 60))
left() { echo $((deadline - $(now))); }
# minutes prints $1 seconds in whole minutes: "less than a minute",
# "1 minute", "3 minutes".
minutes() {
	m=$((($1 + 30) / 60))
	if [ "$1" -lt 60 ]; then
		echo "less than a minute"
	elif [ "$m" -le 1 ]; then
		echo "1 minute"
	else
		echo "$m minutes"
	fi
}

# status prints the HTTP status of OpenSearch's security health check,
# which needs no sign-in: 200 once its security settings are loaded, 503
# while they aren't, 000 when OpenSearch doesn't answer.
status() {
	curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
		--cacert "$certs/root-ca.pem" "https://$host:9200/_plugins/_security/health"
}

# stored prints how many kinds of settings OpenSearch keeps in its
# security index, asked with the admin certificate, which works before
# they are loaded: 0 when there is no such index, nothing when it can't
# tell.
stored() {
	out=$(curl -s --max-time 20 --cacert "$certs/root-ca.pem" --cert "$certs/admin.pem" --key "$certs/admin-key.pem" \
		"https://$host:9200/.opendistro_security/_count") || return 0
	case $out in
	*index_not_found_exception*) echo 0 ;;
	*'"count":'*) echo "$out" | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p' ;;
	esac
}

# admin runs securityadmin.sh with the admin certificate and the options
# given, with its output in /tmp/out.txt, and stops it once the time is
# up (giving it at least a minute, but never past the deadline's extra
# minute). Every request it makes waits up to 30 seconds for an answer.
admin() {
	t=$(left)
	[ "$t" -lt 60 ] && t=$((hard - $(now)))
	if [ "$t" -le 0 ]; then
		say "securityadmin.sh ran out of time and was stopped." > /tmp/out.txt
		return 124
	fi
	timeout "$t" "$tool" -h "$host" -p 9200 -icl -arc \
		-cacert "$certs/root-ca.pem" -cert "$certs/admin.pem" -key "$certs/admin-key.pem" \
		"$@" > /tmp/out.txt 2>&1
	rc=$?
	[ "$rc" = 124 ] && say "securityadmin.sh ran out of time and was stopped." >> /tmp/out.txt
	return "$rc"
}

# errors prints the first error line of securityadmin.sh's last run,
# indented, and what it means when OpenSearch didn't answer in time. It
# keeps the line for the summary if this gives up.
errors() {
	line=$(grep -E 'ERR:|FAIL:|Exception|ran out of time' /tmp/out.txt | grep -v 'see errors above' |
		sed 's/^[[:space:]]*//' | cut -c1-300 | head -n 1)
	[ -n "$line" ] || return 0
	say "$line" >> /tmp/errors.txt
	say "    $line"
	case $line in
	*flood-stage*) say "    (OpenSearch's disk is nearly full, so it refuses to store anything.)" ;;
	*imeout*) say "    (OpenSearch didn't answer within 30 seconds: it is busy, or the computer is slow.)" ;;
	esac
}

# check_file stops here when securityadmin.sh's last run found a file it
# can't read: trying again would not help.
check_file() {
	bad=$(grep 'ERR: Seems .* is not in OpenSearch Security' /tmp/out.txt | head -n 1)
	[ -n "$bad" ] || return 0
	file=$(echo "$bad" | sed 's/^ERR: Seems \(.*\) is not in .*/\1/')
	say ""
	say "$(basename "$file") has a mistake, so OpenSearch can't read it:"
	sed -n '/ERR: Seems/,/at \[Source/p' /tmp/out.txt | sed 's/^/    /' | head -n 12
	say "Correct it in deploy/docker/opensearch/security/ (or undo your change there), then run"
	say "docker compose -f deploy/docker/docker-compose.yml up -d again from the folder you cloned Signalith into."
	exit 1
}

# loaded reports whether securityadmin.sh's last run stored kind $1.
loaded() { grep -q "SUCC: Configuration for '$1' created or updated" /tmp/out.txt; }

# fingerprint prints a SHA-256 of every file this loads, without Windows
# line endings, so a checkout with other line endings is no change.
fingerprint() {
	for k in $kinds; do
		f=${k#*:}
		[ -f "$dir/$f" ] || continue
		printf '== %s\n' "$f"
		tr -d '\r' < "$dir/$f"
	done | sha256sum | cut -d' ' -f1
}

delay=5
# wait_a_bit sleeps before the next try, longer each time, up to 30 seconds.
wait_a_bit() {
	d=$delay
	l=$(left)
	[ "$d" -gt "$l" ] && d=$l
	[ "$d" -lt 1 ] && d=1
	say "Trying again in $d seconds (it keeps trying for $(minutes "$l") more)."
	sleep "$d"
	delay=$((delay * 2))
	[ "$delay" -gt 30 ] && delay=30
}

# answered is yes once OpenSearch has answered at all.
answered=no

give_up() {
	say ""
	say "Gave up after $(minutes $(($(now) - start))): $1"
	if [ -s /tmp/errors.txt ]; then
		say "The last errors were:"
		awk '!seen[$0]++' /tmp/errors.txt | tail -n 3 | sed 's/^/    /'
	fi
	say "Signalith does not start until OpenSearch has its security settings. What to do:"
	if [ "$answered" = no ]; then
		say "  - OpenSearch did not start, or stopped. From the folder you cloned Signalith into, see whether"
		say "    it runs (its STATUS says \"Up\"; \"Exited\" or \"Restarting\" when it stopped):"
		say "      docker compose -f deploy/docker/docker-compose.yml ps -a opensearch"
		say "    and look at the end of OpenSearch's own log for the reason:"
		say "      docker compose -f deploy/docker/docker-compose.yml logs opensearch"
		say "  - Once you have fixed what it says, run this again. It runs this step again:"
		say "      docker compose -f deploy/docker/docker-compose.yml up -d"
		say "  - If OpenSearch is up but was only slow to start, run that last command again, too."
		say "Help: the section \"If OpenSearch's security settings aren't loaded\" in docs/opensearch-security.md."
		exit 1
	fi
	if grep -q 'flood-stage' /tmp/errors.txt; then
		say "  - OpenSearch's disk is nearly full, so it refuses to store anything. Free some disk space on"
		say "    this computer (Docker Desktop on Windows keeps its data on drive C: unless you moved it)."
		say "    OpenSearch lifts its block by itself once there is room again."
		say "  - Then, from the folder you cloned Signalith into, run this again. It runs this step again:"
		say "      docker compose -f deploy/docker/docker-compose.yml up -d"
	else
		say "  - From the folder you cloned Signalith into, run this again. It runs this step again:"
		say "      docker compose -f deploy/docker/docker-compose.yml up -d"
		say "  - If it gives up again, OpenSearch is too slow on this computer right now: close other programs,"
		say "    or give Docker more memory and CPU (the help below says how), then run it again."
	fi
	say "  - OpenSearch's own log may say more: docker compose -f deploy/docker/docker-compose.yml logs opensearch"
	say "Help: the section \"If OpenSearch's security settings aren't loaded\" in docs/opensearch-security.md."
	exit 1
}

finish() {
	if ! { say "$want" > "$state.new" && mv "$state.new" "$state"; } 2> /dev/null; then
		say "(Could not note which files were loaded, in $state, so the next start loads them again.)"
	fi
	say "Done: OpenSearch's security settings are loaded."
	exit 0
}

: > /tmp/errors.txt
say "Checking that OpenSearch has loaded its security settings (who may sign in, and what each may do)."

# 1. Wait until OpenSearch answers, asking every 3 seconds.
code=$(status)
if [ "$code" = 000 ]; then
	say "Waiting for OpenSearch to answer (it takes a minute or more to start)..."
	i=0
	while code=$(status); [ "$code" = 000 ]; do
		[ "$(left)" -le 0 ] && give_up "OpenSearch did not answer at https://$host:9200."
		i=$((i + 1))
		[ $((i % 20)) = 0 ] && say "Still waiting for OpenSearch to answer (it keeps trying for $(minutes "$(left)") more)."
		sleep 3
	done
fi
answered=yes

all=""
for k in $kinds; do
	[ -f "$dir/${k#*:}" ] && all="$all ${k%%:*}"
done
count=$(echo $all | wc -w)

# 2. Right after it starts, OpenSearch answers before it has read the
# settings it already has: give it a minute to do that by itself, if it
# has them all.
if [ "$code" = 503 ]; then
	n=$(stored)
	if [ "${n:-$count}" -ge "$count" ]; then
		say "OpenSearch answers, but has not loaded its security settings yet. Giving it a minute to load them..."
		i=0
		while [ "$i" -lt 20 ] && [ "$(left)" -gt 0 ]; do
			sleep 3
			code=$(status)
			[ "$code" = 200 ] && break
			i=$((i + 1))
		done
	fi
fi

# 3. Nothing to do when its settings are loaded, from these same files.
want=$(fingerprint)
had=$(cat "$state" 2> /dev/null)
if [ "$code" = 200 ] && [ "$want" = "$had" ]; then
	say "Nothing to do: OpenSearch has its security settings loaded, from these same files."
	exit 0
fi
case $code in
200)
	if [ -n "$had" ]; then
		say "The security settings files changed since they were last loaded. Loading them again."
	else
		say "OpenSearch has security settings loaded, but this step has not loaded them before. Loading the ones in these files, to be sure OpenSearch has this version's."
	fi
	;;
503) say "OpenSearch's security settings aren't loaded (it answers \"Security not initialized\"). Loading them." ;;
000) say "OpenSearch stopped answering. Loading its security settings once it answers again." ;;
*) say "OpenSearch's security health check answered HTTP $code instead of 200. Loading its security settings." ;;
esac

# 4. Store each kind of setting, all at once first, then again one by
# one those OpenSearch didn't take; then have OpenSearch use them, and
# check that it does.
pending=$all
reloaded=no
while :; do
	if [ -n "$pending" ]; then
		if [ "$pending" = "$all" ]; then
			say "Storing all $count kinds of settings..."
			admin -cd "$dir"
			check_file
			# "Done with success": all stored, and OpenSearch uses them.
			if grep -q "Done with success" /tmp/out.txt; then reloaded=yes; else reloaded=no; fi
			rest=""
			for k in $pending; do
				loaded "$k" || rest="$rest $k"
			done
			pending=$rest
			if [ -n "$pending" ]; then
				say "Stored $((count - $(echo $pending | wc -w))) of $count. Not yet:$pending"
				errors
			fi
		else
			say "Storing again:$pending"
			rest=""
			for k in $pending; do
				if [ "$(left)" -le 0 ]; then
					rest="$rest $k"
					continue
				fi
				for kf in $kinds; do
					[ "${kf%%:*}" = "$k" ] && f=${kf#*:}
				done
				admin -f "$dir/$f" -t "$k"
				check_file
				if ! loaded "$k"; then
					rest="$rest $k"
					say "  Not yet: $k"
					errors
				fi
			done
			pending=$rest
			reloaded=no
		fi
		[ -z "$pending" ] && say "All $count kinds of settings are stored."
	fi
	if [ -z "$pending" ]; then
		if [ "$reloaded" = no ] && [ "$(left)" -gt 0 ]; then
			say "Asking OpenSearch to use them..."
			if admin -rl; then
				reloaded=yes
			else
				say "OpenSearch didn't take that."
				errors
			fi
		fi
		if [ "$reloaded" = yes ]; then
			# While OpenSearch is still trying to read the settings it had,
			# it does so again every 13 seconds or so, instead of reloading.
			# Checks for up to 30 seconds or so, but not past the deadline's
			# extra minute.
			i=0
			while [ "$i" -lt 15 ] && [ "$(now)" -lt "$hard" ]; do
				[ "$(status)" = 200 ] && finish
				sleep 2
				i=$((i + 1))
			done
			say "OpenSearch still says its security settings aren't loaded. Storing them all again."
			pending=$all
			reloaded=no
		fi
	fi
	[ "$(left)" -le 0 ] && give_up "OpenSearch's security settings aren't loaded."
	wait_a_bit
done
