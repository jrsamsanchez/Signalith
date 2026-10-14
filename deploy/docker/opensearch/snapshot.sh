#!/bin/sh
# Backs up and restores Signalith's events, findings and cases in the
# Docker quick start, with OpenSearch snapshots written to the
# opensearch-snapshots volume. From the Signalith folder:
#
#   docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh create
#   docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh list
#   docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh restore <name>
#   docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh delete <name>
#
# create can run while Signalith runs. restore replaces the indices the
# snapshot holds and keeps the others (days newer than the snapshot):
# stop Signalith first. docs/backup.md has the whole procedure.
#
# A POSIX sh script, run by OpenSearch's own user with its admin
# certificate, which only containers with the opensearch-certs volume can
# read. It sends nothing outside the container.

set -u
cd /usr/share/opensearch || exit 1

url=https://localhost:9200
repo=signalith
location=/usr/share/opensearch/snapshots
prefix=${SIGNALITH_INDEX_PREFIX:-signalith}

say() { printf '%s\n' "$*"; }
fail() { say "$*" >&2; exit 1; }

# api METHOD PATH [BODY] prints OpenSearch's answer, and fails on an HTTP
# error with the answer.
api() {
	out=$(curl -sS -w '\n%{http_code}' --cacert config/certs/root-ca.pem \
		--cert config/certs/admin.pem --key config/certs/admin-key.pem \
		-H 'Content-Type: application/json' -X "$1" "$url$2" ${3:+-d "$3"}) ||
		fail "OpenSearch does not answer. Is it running? docker compose -f deploy/docker/docker-compose.yml ps"
	code=$(printf '%s\n' "$out" | tail -n 1)
	body=$(printf '%s\n' "$out" | sed '$d')
	case $code in
	2??) printf '%s\n' "$body" ;;
	*) fail "OpenSearch refused $1 $2 ($code): $body" ;;
	esac
}

# repository registers the snapshots folder with OpenSearch, which it
# needs once (after a restore of a new install too).
repository() {
	[ -w "$location" ] || fail "OpenSearch cannot write to $location. Give it the folder: docker compose -f deploy/docker/docker-compose.yml exec -u 0 opensearch chown -R 1000:1000 $location"
	api PUT "/_snapshot/$repo" "{\"type\":\"fs\",\"settings\":{\"location\":\"$location\"}}" >/dev/null
}

case ${1:-} in
create)
	repository
	name=${2:-$prefix-$(date -u +%Y%m%d-%H%M%S)}
	say "Taking snapshot $name of the $prefix* indices..."
	# Not the cluster's global state: OpenSearch's own security settings
	# come from the files in deploy/docker/opensearch/security.
	res=$(api PUT "/_snapshot/$repo/$name?wait_for_completion=true" "{\"indices\":\"$prefix*\",\"include_global_state\":false}") || exit 1
	case $res in
	*'"state":"SUCCESS"'*) say "Done: $name. Copy the snapshots folder somewhere safe (see docs/backup.md)." ;;
	*) fail "The snapshot did not succeed: $res" ;;
	esac
	;;
list)
	repository
	api GET "/_cat/snapshots/$repo?v&h=id,status,start_time,end_time,indices&s=start_epoch"
	;;
restore)
	[ -n "${2:-}" ] || fail "Name the snapshot to restore: sh snapshot.sh restore <name> (sh snapshot.sh list shows them)"
	repository
	api GET "/_snapshot/$repo/$2" >/dev/null || exit 1
	# Indices that are open cannot be restored over: close Signalith's,
	# restore the snapshot's into them, and open the rest again.
	say "Closing the $prefix* indices..."
	api POST "/$prefix*/_close?expand_wildcards=open&ignore_unavailable=true&allow_no_indices=true" >/dev/null || exit 1
	say "Restoring $2..."
	res=$(api POST "/_snapshot/$repo/$2/_restore?wait_for_completion=true" "{\"indices\":\"$prefix*\",\"include_global_state\":false}")
	ok=$?
	api POST "/$prefix*/_open?expand_wildcards=closed&ignore_unavailable=true&allow_no_indices=true" >/dev/null
	[ $ok -eq 0 ] || exit 1
	case $res in
	*'"failed":0'*) say "Done. Start Signalith, then run: docker compose -f deploy/docker/docker-compose.yml exec signalith signalith cluster accept-restore -yes" ;;
	*) fail "The restore did not finish: $res" ;;
	esac
	;;
delete)
	[ -n "${2:-}" ] || fail "Name the snapshot to delete: sh snapshot.sh delete <name>"
	repository
	api DELETE "/_snapshot/$repo/$2" >/dev/null && say "Deleted $2."
	;;
*)
	fail "Usage: sh snapshot.sh create [name] | list | restore <name> | delete <name>"
	;;
esac
