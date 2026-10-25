#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Installs the Signalith Agent on a Linux computer: one program that runs
# the collectors for it. It fetches what to collect from Signalith every
# few minutes, writes Fluent Bit's configuration, keeps Fluent Bit running
# and reports how it is, so nobody edits a configuration file by hand.
#
# Add data > Signalith Agent gives one line that downloads this script
# from Signalith, checks its SHA-256, and runs it:
#
#    f=$(mktemp) && curl -fsSk --proto '=https' https://siem:7779/api/agent/install.sh -o "$f" &&
#   echo '<sha-256>  '"$f" | sha256sum -c --quiet &&
#   echo 'sgl_...' | sudo sh "$f" --from https://siem:7779 \
#     --ca-sha256 <hex> --version 0.4.0 --token - --osquery
#
# "--token -" reads the agent token from the standard input, so it is
# never on a command line other users of the computer could see. The line
# starts with a space, which keeps it out of bash's history where bash is
# set to (Ubuntu and Debian are).
#
# What it does, in order, stopping at the first problem with a plain
# message:
#   1. Checks the computer: root, systemd, processor and system.
#   2. Checks Signalith's certificate authority against the fingerprint in
#      the line (--ca-sha256), then asks Signalith, with the token, for the
#      agent's configuration: a revoked or wrong token stops here, before
#      anything is installed.
#   3. Adds Fluent Bit's own signed package repository, its key checked
#      against the fingerprint pinned below, and installs Fluent Bit. The
#      package's own service is masked: the agent runs Fluent Bit itself.
#   4. With --osquery: adds osquery's own signed package repository the
#      same way and installs osquery. Its package's service is masked too;
#      osquery runs as signalith-osquery.service with the flags the agent
#      writes, and enrolls in Signalith with the agent token.
#   5. Downloads the agent program from Signalith and checks its SHA-256,
#      writes the agent's settings, token and certificate authority, and
#      starts the agent's hardened systemd service.
#   6. Waits until the agent runs Fluent Bit (and osquery) with Signalith's
#      configuration and Signalith has its status.
#
# Run it again to repair, or to upgrade Fluent Bit and the agent: it
# changes only what differs. It keeps a copy of itself in
# /usr/local/lib/signalith-agent, whose --uninstall removes what it added
# (the list is /etc/signalith-agent/manifest).
#
# For tests only: SIGNALITH_AGENT_OS_RELEASE (for /etc/os-release).
set -eu

# --- Pinned signing key ------------------------------------------------
# The full fingerprint of Fluent Bit's repository signing key
# (packages.fluentbit.io/fluentbit.key), as published in Fluent Bit's
# documentation (installation/downloads/linux). A key downloaded from the
# publisher is used only when its fingerprint is this one. The network
# sensor's install script pins the same key.
KEY_FPR_FLUENTBIT=C3C0A28534B9293EAF51FABD9F9DDC083888C1CD
# osquery's repository signing key (pkg.osquery.io), as published in
# osquery's documentation (installation/install-linux).
KEY_FPR_OSQUERY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B

# --- Systems -----------------------------------------------------------
#   system                         Fluent Bit repository
#   Ubuntu 22.04, 24.04            ubuntu/jammy, ubuntu/noble
#   Debian 12, 13                  debian/bookworm, debian/trixie
#   RHEL, Rocky, Alma, Oracle 8, 9 centos/8, centos/9
#   Amazon Linux 2023              amazonlinux/2023
SYSTEMS='Ubuntu 22.04 or 24.04, Debian 12 or 13, Red Hat Enterprise Linux, Rocky Linux, AlmaLinux or Oracle Linux 8 or 9, and Amazon Linux 2023'

# Where the agent lives. The agent program reads the same paths
# (internal/agentd).
PROGRAM=/usr/local/sbin/signalith-agent
# A copy of this script, for --uninstall.
LIB_DIR=/usr/local/lib/signalith-agent
CONF_DIR=/etc/signalith-agent
STATE_DIR=/var/lib/signalith-agent
UNIT=signalith-agent.service
# osquery's service, and the path unit that restarts it when the agent
# writes new flags. The agent names the same service and flags file
# (internal/agentd).
OSQUERY_UNIT=signalith-osquery.service
OSQUERY_PATH=signalith-osquery-flags.path
OSQUERY_RESTART=signalith-osquery-flags.service
OSQUERYD=/opt/osquery/bin/osqueryd
# The updater, which installs a signed update the agent got ready. It runs
# outside the agent's sandbox, which cannot write the program, and a path
# unit starts it when the agent writes the ready file (internal/agentd).
UPDATE_UNIT=signalith-agent-update.service
UPDATE_PATH=signalith-agent-update.path

from=''
ca_sha=''
next_ca_sha=''
version=''
token=''
dryrun=''
uninstall=no
osquery=no
take_over=no

os_release=${SIGNALITH_AGENT_OS_RELEASE:-/etc/os-release}

say() { printf '%s\n' "$*"; }
ok() { printf '  \342\234\223 %s\n' "$*"; }
info() { printf '  - %s\n' "$*"; }
warned=0
# warn prints a warning and how to fix it; the install goes on.
warn() {
  warned=$((warned + 1))
  printf '  ! %s\n' "$1"
  if [ $# -gt 1 ]; then printf '      Fix: %s\n' "$2"; fi
}
fail() {
  printf '  \342\234\227 %s\n' "$1" >&2
  if [ $# -gt 1 ]; then printf '      Fix: %s\n' "$2" >&2; fi
  exit 1
}
usage() {
  cat <<'USAGE'
Usage: echo '<token>' | sudo sh install.sh --from https://<signalith>:7779
         [--ca-sha256 <hex>] [--next-ca-sha256 <hex>] [--version <v>] --token -
         [--osquery] [--take-over] [--dry-run <folder>]
       sudo sh install.sh --uninstall

  --from              Signalith's address, which the agent sends to.
  --ca-sha256         SHA-256 of Signalith's certificate authority; the
                      script refuses another one. Leave it out when
                      Signalith's certificate is from a public authority.
  --next-ca-sha256    The new certificate authority while Signalith switches.
  --version           Signalith's version.
  --token             The agent token, or - to read it from the standard
                      input. Left out on a run again, the agent keeps its own.
  --osquery           Also install osquery, from its publisher, for
                      inventory, file changes and live queries. A run again
                      keeps osquery once it is installed.
  --take-over         Stop and mask Fluent Bit's (or osquery's) own service
                      when it already runs here, sending somewhere else, say.
                      Without it the script stops before changing anything.
                      --uninstall starts it again.
  --dry-run           Write every file under this folder and print the
                      commands instead of running them.
  --uninstall         Remove what the script added.
USAGE
}

# need checks a flag has a value.
need() {
  [ "$2" -ge 2 ] || fail "$1 needs a value. Run with --help to see how this script is used."
}
while [ $# -gt 0 ]; do
  case "$1" in
    --from) need "$1" $#; from=$2; shift 2 ;;
    --from=*) from=${1#*=}; shift ;;
    --ca-sha256) need "$1" $#; ca_sha=$2; shift 2 ;;
    --ca-sha256=*) ca_sha=${1#*=}; shift ;;
    --next-ca-sha256) need "$1" $#; next_ca_sha=$2; shift 2 ;;
    --next-ca-sha256=*) next_ca_sha=${1#*=}; shift ;;
    --version) need "$1" $#; version=$2; shift 2 ;;
    --version=*) version=${1#*=}; shift ;;
    --token) need "$1" $#; token=$2; shift 2 ;;
    --token=*) token=${1#*=}; shift ;;
    --dry-run) need "$1" $#; dryrun=$2; shift 2 ;;
    --dry-run=*) dryrun=${1#*=}; shift ;;
    --uninstall) uninstall=yes; shift ;;
    --osquery) osquery=yes; shift ;;
    --take-over) take_over=yes; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; fail "Unknown option: $1" ;;
  esac
done

# R is the folder files are written under: / for real, the --dry-run
# folder for a dry run.
R=''
if [ -n "$dryrun" ]; then
  case "$dryrun" in
    /*) ;;
    *) dryrun=$(pwd)/$dryrun ;;
  esac
  R=${dryrun%/}
  mkdir -p "$R"
fi
manifest=$R$CONF_DIR/manifest

again='Copy the whole line again from Add data > Signalith Agent.'

# hex64 checks a SHA-256 written in hexadecimal, and prints it in lower case.
hex64() {
  case "$2" in
    *[!0-9a-fA-F]*) fail "$1 must be 64 hexadecimal characters." "$again" ;;
  esac
  [ ${#2} -eq 64 ] || fail "$1 must be 64 hexadecimal characters." "$again"
  printf '%s' "$2" | tr 'A-F' 'a-f'
}

check_args() {
  case "$from" in
    https://*) ;;
    '') fail "--from is missing: the address of your Signalith." "$again" ;;
    *) fail "--from must be an https:// address: the agent sends only over HTTPS." ;;
  esac
  hostport=${from#https://}
  case "$hostport" in
    '' | */* | *[!A-Za-z0-9.:[\]-]*) fail "--from must be Signalith's address and nothing else, like https://siem.example.com:7779 (no path)." ;;
  esac
  [ -z "$ca_sha" ] || ca_sha=$(hex64 --ca-sha256 "$ca_sha")
  [ -z "$next_ca_sha" ] || next_ca_sha=$(hex64 --next-ca-sha256 "$next_ca_sha")
  if [ -n "$next_ca_sha" ] && [ -z "$ca_sha" ]; then
    fail "--next-ca-sha256 needs --ca-sha256 too."
  fi
  case "$version" in
    '') version=unknown ;;
    *[!A-Za-z0-9.+-]*) fail "--version must be a version number, like 0.4.0." ;;
  esac
  if [ "$token" = - ]; then
    IFS= read -r token || [ -n "$token" ] || fail "No token on the standard input." "$again It starts with echo 'sgl_...'."
    token=$(printf '%s' "$token" | tr -d '[:space:]')
    [ -n "$token" ] || fail "No token on the standard input." "$again It starts with echo 'sgl_...'."
  fi
  if [ -z "$token" ] && [ -r "$R$CONF_DIR/token" ]; then
    # A run again without a token keeps the agent's token.
    token=$(tr -d '[:space:]' <"$R$CONF_DIR/token")
  fi
  case "$token" in
    '') fail "--token is missing." "$again It holds the agent's token." ;;
    sgl_*) ;;
    *) fail "This is not a Signalith agent token (they start with sgl_)." "$again" ;;
  esac
  case "${token#sgl_}" in
    *[!a-z2-7]*) fail "The token is not whole: a Signalith agent token is sgl_ and 52 letters and digits." "$again" ;;
  esac
  [ ${#token} -eq 56 ] || fail "The token is not whole: a Signalith agent token is sgl_ and 52 letters and digits." "$again"
}

# --- Running and writing -----------------------------------------------

# run runs a command, or prints it in a dry run.
run() {
  if [ -n "$dryrun" ]; then
    printf '    would run: %s\n' "$*"
  else
    "$@"
  fi
}
# quiet runs a command with its output kept for when it fails.
quiet() {
  if [ -n "$dryrun" ]; then
    printf '    would run: %s\n' "$*"
    return 0
  fi
  if ! "$@" >"$tmp/out" 2>&1; then
    tail -n 20 "$tmp/out" >&2
    return 1
  fi
}

tmp=''
newfile=''
cleanup() {
  if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
  # A file put_file had not finished (the run was stopped).
  if [ -n "$newfile" ]; then rm -f "$newfile"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
tmp=$(mktemp -d)
chmod 0700 "$tmp"

# manifest_add records what the script added, for --uninstall.
manifest_add() {
  if [ ! -f "$manifest" ]; then
    mkdir -p "${manifest%/*}"
    (umask 077 && printf '# Written by the Signalith Agent install script: what it added, for --uninstall.\n' >"$manifest")
  fi
  grep -qxF "$*" "$manifest" || printf '%s\n' "$*" >>"$manifest"
}
manifest_has() {
  [ -f "$manifest" ] && grep -qxF "$*" "$manifest"
}

changed=''
# same_file is true when files $1 and $2 hold the same bytes.
same_file() {
  [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]
}
# no_link stops when $1 is a symbolic link: root never follows one where
# it writes.
no_link() {
  if [ -L "$1" ]; then
    fail "$1 is a symbolic link, which the script does not follow." "Look at what made it (it should be a plain file or folder), remove it, and run the line again."
  fi
}
set_owner() {
  no_link "$1"
  chmod "$2" "$1"
  [ -n "$dryrun" ] || chown -h "$3" "$1"
}
# folder makes a folder with a mode and owner.
folder() {
  no_link "$R$1"
  mkdir -p "$R$1"
  set_owner "$R$1" "$2" "$3"
}
# put_file writes file $1 (mode $2, owner $3) from $4 when it differs from
# what is there, and notes group $5 as changed. The new file is made
# readable by root only, and gets its mode once it holds the whole content.
put_file() {
  dest=$R$1
  no_link "$dest"
  if [ -f "$dest" ] && same_file "$4" "$dest"; then
    set_owner "$dest" "$2" "$3"
    return 0
  fi
  mkdir -p "${dest%/*}"
  rm -f "$dest.signalith-new"
  newfile=$dest.signalith-new
  (umask 077 && cp "$4" "$dest.signalith-new")
  set_owner "$dest.signalith-new" "$2" "$3"
  mv -f "$dest.signalith-new" "$dest"
  newfile=''
  manifest_add "file $1"
  case " $changed " in
    *" $5 "*) ;;
    *) changed="$changed $5" ;;
  esac
}
# put writes standard input to a file with put_file.
put() {
  (umask 077 && cat >"$tmp/put")
  put_file "$1" "$2" "$3" "$tmp/put" "$4"
}

# --- The computer ------------------------------------------------------

os_id='' os_ver='' os_name='' pkg='' codename='' fb_repo='' arch=''
check_os() {
  [ -r "$os_release" ] || fail "This computer does not say which Linux it is (no /etc/os-release). The agent runs on $SYSTEMS."
  os_id=$(sed -n 's/^ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$os_release" | head -n 1)
  os_ver=$(sed -n 's/^VERSION_ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$os_release" | head -n 1)
  os_name=$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$os_release" | head -n 1)
  [ -n "$os_name" ] || os_name="$os_id $os_ver"
  case "$os_id:$os_ver" in
    ubuntu:22.04) pkg=apt codename=jammy fb_repo=ubuntu/jammy ;;
    ubuntu:24.04) pkg=apt codename=noble fb_repo=ubuntu/noble ;;
    debian:12*) pkg=apt codename=bookworm fb_repo=debian/bookworm ;;
    debian:13*) pkg=apt codename=trixie fb_repo=debian/trixie ;;
    rhel:8* | rocky:8* | almalinux:8* | ol:8*) pkg=dnf fb_repo=centos/8 ;;
    rhel:9* | rocky:9* | almalinux:9* | ol:9*) pkg=dnf fb_repo=centos/9 ;;
    amzn:2023*) pkg=dnf fb_repo=amazonlinux/2023 ;;
    *) fail "The agent runs on $SYSTEMS; this computer runs $os_name, which is not supported yet." "Set up Fluent Bit by hand from Add data > Linux instead." ;;
  esac
  ok "system: $os_name"
}

check_machine() {
  if [ -n "$dryrun" ]; then
    info "dry run: files go under $R, commands are printed, nothing else changes"
  else
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: it installs a package and a service." "Put sudo before sh in the line, as Add data shows it."
    ok "running as root"
    if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
      fail "This computer does not run systemd, which the agent's service needs." "Use $SYSTEMS."
    fi
    ok "systemd"
  fi
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "The agent runs on 64-bit x86 (amd64) and 64-bit ARM (arm64), not $(uname -m)." ;;
  esac
  ok "processor: $arch"
  check_os
  for tool in curl sha256sum base64 sed awk; do
    command -v "$tool" >/dev/null 2>&1 || fail "This script needs $tool, which this computer does not have." "sudo apt-get install curl coreutils (or sudo dnf install curl coreutils), then run the line again."
  done
}

# --- Signalith ---------------------------------------------------------

# pem_sha256 prints the SHA-256 of the first certificate in a PEM file.
pem_sha256() {
  awk '/-----BEGIN CERTIFICATE-----/ { f = 1; next } /-----END CERTIFICATE-----/ { exit } f' "$1" |
    tr -d '\r\n ' | base64 -d 2>/dev/null | sha256sum | awk '{ print $1 }'
}
# fetch_ca downloads one of Signalith's certificate authorities (which=$1)
# and checks it is the one the line names ($2). Signalith hands out one
# certificate each time: a file with more is refused, as someone in
# between could add their own after the real one.
fetch_ca() {
  q=''
  [ "$1" = current ] || q="?which=$1"
  # Not checked by a certificate: the fingerprint below is.
  code=$(curl -sSk --proto '=https' --max-time 30 -o "$tmp/ca-$1.pem" -w '%{http_code}' "$from/api/tls/ca.pem$q") ||
    fail "Could not reach Signalith at $from." "Check that this computer can reach it (curl $from), that the address is right, and that no firewall is in between, then run the line again."
  [ "$code" = 200 ] || fail "Signalith at $from did not hand out its certificate authority (it answered $code)." "$again"
  n=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$tmp/ca-$1.pem") || n=0
  [ "$n" = 1 ] || fail "Signalith at $from handed out $n certificates where it hands out one." "$again If it still fails, someone may be in between this computer and Signalith."
  got=$(pem_sha256 "$tmp/ca-$1.pem")
  [ "$got" = "$2" ] || fail "This Signalith's certificate authority is not the one the line names." "$again If it still fails, someone may be in between this computer and Signalith."
  # Only the certificate checked above is kept.
  awk '/-----BEGIN CERTIFICATE-----/ { f = 1 } f { print } /-----END CERTIFICATE-----/ && f { exit }' "$tmp/ca-$1.pem" | tr -d '\r' >"$tmp/ca-$1.one"
  mv -f "$tmp/ca-$1.one" "$tmp/ca-$1.pem"
}
cafile=''
check_ca() {
  if [ -z "$ca_sha" ]; then
    curl -sS --proto '=https' --max-time 30 -o /dev/null "$from/" 2>"$tmp/err" ||
      fail "Could not reach Signalith at $from over HTTPS with this computer's trusted certificate authorities: $(tail -n 1 "$tmp/err")" "Check the address; if Signalith uses its own certificate authority, copy the line again from Add data: it then names it with --ca-sha256."
    ok "Signalith at $from (certificate checked by this computer's trusted authorities)"
    return 0
  fi
  fetch_ca current "$ca_sha"
  cafile=$tmp/ca.pem
  cp "$tmp/ca-current.pem" "$cafile"
  if [ -n "$next_ca_sha" ]; then
    fetch_ca next "$next_ca_sha"
    cat "$tmp/ca-next.pem" >>"$cafile"
  fi
  ok "Signalith at $from, its certificate authority is the one the line names"
}

# sig_get asks Signalith for $1 with the agent token, into file $2, and
# prints the HTTP status; the answer's headers go to $2.headers. The
# token is read from a file, never put on a command line.
sig_get() {
  if [ -n "$cafile" ]; then
    curl -gsS --proto '=https' --max-time "${3:-30}" --cacert "$cafile" -H "@$tmp/auth" -D "$2.headers" -o "$2" -w '%{http_code}' "$from$1"
  else
    curl -gsS --proto '=https' --max-time "${3:-30}" -H "@$tmp/auth" -D "$2.headers" -o "$2" -w '%{http_code}' "$from$1"
  fi
}
# sig_error prints the error message of Signalith's JSON answer in file $1.
sig_error() {
  sed -n 's/.*"error":"\([^"]*\)".*/\1/p' "$1" | head -n 1
}

check_token() {
  (umask 077 && printf 'Authorization: Bearer %s\n' "$token" >"$tmp/auth")
  code=$(sig_get "/api/agent/config?os=linux&arch=$arch&server=$from" "$tmp/config.json") ||
    fail "Could not reach Signalith at $from to check the token." "Check that this computer can reach it, then run the line again."
  case "$code" in
    200) ;;
    401 | 403) fail "Signalith refused the token: $(sig_error "$tmp/config.json")" "Make the line again on Add data > Signalith Agent." ;;
    503) fail "Signalith is still starting." "Run the line again in a minute." ;;
    *) fail "Signalith did not hand out the agent's configuration (it answered $code): $(sig_error "$tmp/config.json")" "$again" ;;
  esac
  ok "the token is an agent token Signalith knows"
}

# --- Fluent Bit --------------------------------------------------------

key_add() {
  if [ -n "$dryrun" ]; then
    printf '    would download %s and check its fingerprint is %s\n' "$2" "$3"
    return 0
  fi
  curl -fsSL --proto '=https' --max-time 60 -o "$tmp/key" "$2" ||
    fail "Could not download $1's signing key from $2." "Check that this computer can reach it, then run the line again."
  mkdir -p "$tmp/gnupg"
  chmod 0700 "$tmp/gnupg"
  got=$(GNUPGHOME=$tmp/gnupg gpg --batch --show-keys --with-colons "$tmp/key" 2>/dev/null |
    awk -F: '$1 == "pub" { p = 1; next } $1 == "fpr" && p { print $10; p = 0 }')
  [ "$got" = "$3" ] || fail "$1's signing key downloaded from $2 is not the one this script pins ($3), so its repository was not added." "Run the line again later; if it keeps failing, the key changed: update Signalith, or tell us."
  # apt reads binary keys (.gpg), dnf text ones (.asc); publishers hand
  # out either.
  armored=no
  if head -n 1 "$tmp/key" | grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----'; then armored=yes; fi
  rm -f "$tmp/key.out"
  case "$4:$armored" in
    *.gpg:yes) GNUPGHOME=$tmp/gnupg gpg --batch --yes --dearmor -o "$tmp/key.out" "$tmp/key" ;;
    *.gpg:no) cp "$tmp/key" "$tmp/key.out" ;;
    *:yes) cp "$tmp/key" "$tmp/key.out" ;;
    *)
      GNUPGHOME=$tmp/gnupg gpg --batch --quiet --import "$tmp/key" 2>/dev/null &&
        GNUPGHOME=$tmp/gnupg gpg --batch --armor --export "$3" >"$tmp/key.out" ||
        fail "$1's signing key from $2 could not be read."
      ;;
  esac
  put_file "$4" 0644 root:root "$tmp/key.out" repo
  ok "$1's signing key ($3)"
}

# pkg_has says whether package $1 is installed (in a dry run: whether an
# earlier dry run into the same folder installed it).
pkg_has() {
  if [ -n "$dryrun" ]; then
    manifest_has "package $1" || manifest_has "tool $1"
  elif [ "$pkg" = apt ]; then
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
  else
    rpm -q "$1" >/dev/null 2>&1
  fi
}
pkg_version() {
  if [ "$pkg" = apt ]; then
    dpkg-query -W -f='${Version}' "$1" 2>/dev/null
  else
    rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null
  fi
}
installed=''
# pkg_add installs the packages in $2... that are missing, and records
# them as $1 (package: --uninstall removes it; tool: it stays).
pkg_add() {
  kind=$1
  shift
  missing=''
  for p in "$@"; do
    pkg_has "$p" || missing="$missing $p"
  done
  [ -n "$missing" ] || return 0
  if [ "$pkg" = dnf ]; then
    set -- dnf install -y "$@"
  else
    set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
  fi
  quiet "$@" || fail "Installing$missing failed (see above)." "Run the line again; if it fails again, check that this computer reaches its package repositories."
  for p in $missing; do
    if [ "$kind" = package ] || [ -n "$dryrun" ]; then manifest_add "$kind $p"; fi
  done
  if [ "$kind" = package ]; then installed="$installed$missing"; fi
  ok "installed$missing"
}

fluentbit_repo() {
  if [ "$pkg" = apt ]; then
    quiet env DEBIAN_FRONTEND=noninteractive apt-get update || fail "apt-get update failed (see above)."
    pkg_add tool ca-certificates gnupg
    run mkdir -p /etc/apt/keyrings
    key_add "Fluent Bit" https://packages.fluentbit.io/fluentbit.key "$KEY_FPR_FLUENTBIT" /etc/apt/keyrings/signalith-fluentbit.gpg
    printf '# Written by the Signalith Agent install script.\n%s\n' \
      "deb [signed-by=/etc/apt/keyrings/signalith-fluentbit.gpg] https://packages.fluentbit.io/$fb_repo $codename main" |
      put /etc/apt/sources.list.d/signalith-fluent-bit.list 0644 root:root repo
    quiet env DEBIAN_FRONTEND=noninteractive apt-get update || fail "apt-get update failed with Fluent Bit's repository (see above)." "Check that this computer reaches packages.fluentbit.io."
  else
    pkg_add tool ca-certificates gnupg2
    key_add "Fluent Bit" https://packages.fluentbit.io/fluentbit.key "$KEY_FPR_FLUENTBIT" /etc/pki/rpm-gpg/signalith-fluentbit.asc
    put /etc/yum.repos.d/signalith-fluent-bit.repo 0644 root:root repo <<REPO
# Written by the Signalith Agent install script.
[signalith-fluent-bit]
name=Fluent Bit
baseurl=https://packages.fluentbit.io/$fb_repo/
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/signalith-fluentbit.asc
enabled=1
REPO
  fi
}

# vendor_running says whether the unit $1 runs, or is starting.
vendor_running() {
  case $(systemctl show -p ActiveState --value "$1" 2>/dev/null || true) in
    active | activating | reloading) return 0 ;;
  esac
  return 1
}

# vendor_checks finds Fluent Bit's or osquery's own service already running
# here (shipping logs somewhere else, say): installing stops and masks it,
# so the agent's copies are the only ones sending. That needs --take-over;
# a service a run before this one masked is the agent's already. A dry run
# checks too, where this computer has systemctl.
vendor_checks() {
  command -v systemctl >/dev/null 2>&1 || return 0
  vunits=fluent-bit.service
  if [ "$osquery" = yes ] || manifest_has osquery; then vunits="$vunits osqueryd.service"; fi
  for vu in $vunits; do
    if manifest_has "mask $vu"; then continue; fi
    case $(systemctl is-enabled "$vu" 2>/dev/null || true) in masked*) continue ;; esac
    vendor_running "$vu" || continue
    if [ "$take_over" = yes ]; then
      warn "$vu already runs here: it will be stopped and masked, so whatever it sends elsewhere stops (--take-over). --uninstall starts it again."
    else
      fail "$vu already runs here, probably for something else: installing would stop it and mask it. Nothing was changed." "Add --take-over to the line to stop it and let the agent run its own copy (--uninstall starts it again), or leave this computer to that service."
    fi
  done
}

# mask_vendor stops and masks a package's own service before the package
# is installed, so there is never a second copy sending; --uninstall
# unmasks it, and starts it again if it ran before.
mask_vendor() {
  if [ -n "$dryrun" ]; then
    manifest_has "mask $1" || run systemctl mask --now "$1"
    manifest_add "mask $1"
    return 0
  fi
  case $(systemctl is-enabled "$1" 2>/dev/null || true) in masked*) return 0 ;; esac
  vwas=no
  if vendor_running "$1"; then
    vwas=yes
    manifest_has "was running $1" || manifest_add "was running $1"
  fi
  if ! vout=$(systemctl mask --now "$1" 2>&1); then
    fail "Could not stop and mask $1: $vout" "Stop it by hand (sudo systemctl disable --now $1) and run the line again."
  fi
  manifest_add "mask $1"
  if [ "$vwas" = yes ]; then
    if vendor_running "$1"; then
      fail "$1 still runs after masking it." "Stop it by hand (sudo systemctl stop $1) and run the line again."
    fi
    info "stopped $1, which ran here before (--take-over); --uninstall starts it again"
  fi
}

upgraded=''
fluentbit_install() {
  fluentbit_repo
  mask_vendor fluent-bit.service
  if pkg_has fluent-bit; then
    before=$(pkg_version fluent-bit) || before=""
    if [ "$pkg" = dnf ]; then
      set -- dnf upgrade -y fluent-bit
    else
      set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade --no-install-recommends fluent-bit
    fi
    if ! quiet "$@"; then
      warn "Upgrading Fluent Bit failed (see above); the version installed keeps running." "Run the line again later."
    elif [ -z "$dryrun" ] && [ "$before" != "$(pkg_version fluent-bit)" ]; then
      upgraded=fluent-bit
      changed="$changed agent"
      ok "upgraded Fluent Bit to $(pkg_version fluent-bit)"
    else
      ok "Fluent Bit $before"
    fi
  else
    pkg_add package fluent-bit
  fi
}

# --- osquery -----------------------------------------------------------

osquery_repo() {
  if [ "$pkg" = apt ]; then
    key_add osquery https://pkg.osquery.io/deb/pubkey.gpg "$KEY_FPR_OSQUERY" /etc/apt/keyrings/signalith-osquery.gpg
    printf '# Written by the Signalith Agent install script.\n%s\n' \
      "deb [arch=$arch signed-by=/etc/apt/keyrings/signalith-osquery.gpg] https://pkg.osquery.io/deb deb main" |
      put /etc/apt/sources.list.d/signalith-osquery.list 0644 root:root repo
    quiet env DEBIAN_FRONTEND=noninteractive apt-get update || fail "apt-get update failed with osquery's repository (see above)." "Check that this computer reaches pkg.osquery.io, or run the line again without --osquery."
  else
    key_add osquery https://pkg.osquery.io/rpm/GPG "$KEY_FPR_OSQUERY" /etc/pki/rpm-gpg/signalith-osquery.asc
    # osquery signs each package; its repository's index is not signed.
    put /etc/yum.repos.d/signalith-osquery.repo 0644 root:root repo <<REPO
# Written by the Signalith Agent install script.
[signalith-osquery]
name=osquery
baseurl=https://pkg.osquery.io/rpm/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/signalith-osquery.asc
enabled=1
REPO
  fi
}

# osquery_install installs osquery and the services that run it with the
# agent's flags. Once installed, a run again keeps it.
osquery_install() {
  if [ "$osquery" != yes ] && ! manifest_has osquery; then
    return 0
  fi
  osquery=yes
  osquery_repo
  mask_vendor osqueryd.service
  if pkg_has osquery; then
    before=$(pkg_version osquery) || before=""
    if [ "$pkg" = dnf ]; then
      set -- dnf upgrade -y osquery
    else
      set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade --no-install-recommends osquery
    fi
    if ! quiet "$@"; then
      warn "Upgrading osquery failed (see above); the version installed keeps running." "Run the line again later."
    elif [ -z "$dryrun" ] && [ "$before" != "$(pkg_version osquery)" ]; then
      upgraded="$upgraded osquery"
      changed="$changed agent"
      ok "upgraded osquery to $(pkg_version osquery)"
    else
      ok "osquery $before"
    fi
  else
    pkg_add package osquery
  fi
  if [ -z "$dryrun" ] && [ ! -x "$OSQUERYD" ]; then
    fail "The osquery package has no $OSQUERYD." "Run the line again without --osquery to install the agent alone."
  fi
  manifest_add osquery
  put "/etc/systemd/system/$OSQUERY_UNIT" 0644 root:root agent <<UNIT
# Written by the Signalith Agent install script (deploy/agent/install.sh).
# osquery with the flags the Signalith Agent writes from Signalith's
# configuration: Signalith is its management server, and its enroll
# secret is the agent token. It runs while the flags file exists, in a
# service of its own because it reads the whole computer, which the
# agent's narrower service may not. Anything in the agent's service could
# write the flags file, so before osquery starts, the agent program checks
# it here, as root outside that service, and osquery runs with the
# checked copy in a folder only this service can write. Extensions stay
# off whatever the file says.
[Unit]
Description=osquery for the Signalith Agent
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/signalith-agent.md
Wants=network-online.target
After=network-online.target
ConditionPathExists=$CONF_DIR/osquery.flags

[Service]
RuntimeDirectory=signalith-osquery
RuntimeDirectoryMode=0700
ExecStartPre=$PROGRAM osquery-flags $CONF_DIR/osquery.flags /run/signalith-osquery/osquery.flags
ExecStart=$OSQUERYD --flagfile=/run/signalith-osquery/osquery.flags --disable_extensions=true
Restart=always
RestartSec=10
UMask=0077
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
# osquery's own watchdog keeps its worker near 200 MB and 10% of a CPU;
# these are the ceiling should it fail.
MemoryMax=512M
CPUQuota=100%
TasksMax=256

[Install]
WantedBy=multi-user.target
UNIT
  put "/etc/systemd/system/$OSQUERY_PATH" 0644 root:root agent <<UNIT
# Written by the Signalith Agent install script (deploy/agent/install.sh).
# Restarts osquery when the Signalith Agent writes new flags for it, or
# removes them.
[Unit]
Description=osquery flags of the Signalith Agent

[Path]
PathChanged=$CONF_DIR/osquery.flags
Unit=$OSQUERY_RESTART

[Install]
WantedBy=multi-user.target
UNIT
  put "/etc/systemd/system/$OSQUERY_RESTART" 0644 root:root agent <<UNIT
# Written by the Signalith Agent install script (deploy/agent/install.sh).
[Unit]
Description=Restart osquery for the Signalith Agent with its new flags

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart $OSQUERY_UNIT
UNIT
  manifest_add "unit $OSQUERY_PATH"
  manifest_add "unit $OSQUERY_UNIT"
  manifest_add "unit $OSQUERY_RESTART"
}

# --- The agent ---------------------------------------------------------

agent_program() {
  code=$(sig_get "/api/agent/program?os=linux&arch=$arch" "$tmp/agent" 300) ||
    fail "Could not download the agent program from Signalith." "Check that this computer can reach it, then run the line again."
  case "$code" in
    200) ;;
    404) fail "This Signalith has no agent program for Linux on $arch: $(sig_error "$tmp/agent")" "Install a released Signalith version, which carries the agent programs, or set up Fluent Bit by hand from Add data > Linux." ;;
    *) fail "Signalith did not hand out the agent program (it answered $code): $(sig_error "$tmp/agent")" "Run the line again." ;;
  esac
  want=$(tr -d '\r' <"$tmp/agent.headers" | sed -n 's/^[Xx]-[Ss]ignalith-[Ss][Hh][Aa]256: *\([0-9a-f]\{64\}\)$/\1/p' | head -n 1)
  [ -n "$want" ] || fail "Signalith did not say the agent program's SHA-256." "Run the line again."
  got=$(sha256sum <"$tmp/agent" | awk '{ print $1 }')
  [ "$got" = "$want" ] || fail "The agent program downloaded is not whole (its SHA-256 differs)." "Run the line again."
  put_file "$PROGRAM" 0755 root:root "$tmp/agent" agent
  ok "the agent program ($(printf '%s' "$got" | cut -c1-12))"
}

agent_files() {
  folder "$CONF_DIR" 0755 root:root
  folder "$STATE_DIR" 0700 root:root
  printf '%s\n' "$token" | put "$CONF_DIR/token" 0600 root:root agent
  if [ -n "$cafile" ]; then
    put_file "$CONF_DIR/ca.pem" 0644 root:root "$cafile" agent
  elif [ -f "$R$CONF_DIR/ca.pem" ] && manifest_has "file $CONF_DIR/ca.pem"; then
    rm -f "$R$CONF_DIR/ca.pem"
    changed="$changed agent"
  fi
  put_file "$LIB_DIR/install.sh" 0755 root:root "$0" script
  put "$CONF_DIR/agent.conf" 0644 root:root agent <<CONF
# Written by the Signalith Agent install script (deploy/agent/install.sh).
# Run the line from Add data again to change it.
SERVER=$from
SIGNALITH_VERSION=$version
OSQUERY=$osquery
CONF
  put "/etc/systemd/system/$UNIT" 0644 root:root agent <<'UNIT'
# Written by the Signalith Agent install script (deploy/agent/install.sh).
# The agent fetches what to collect from Signalith, writes Fluent Bit's
# configuration and runs Fluent Bit, which reads the logs. It runs as root
# so it can read every log, but keeps only the right to read files, and
# writes only its own folders.
[Unit]
Description=Signalith Agent
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/signalith-agent.md
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/signalith-agent run
Restart=always
RestartSec=5
UMask=0077
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/signalith-agent /var/lib/signalith-agent
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Fluent Bit runs in this service too. A busy computer's agent uses well
# under these; they stop a fault from taking the computer's memory or
# CPU, and systemd starts the service again if it is stopped for it.
MemoryHigh=384M
MemoryMax=512M
CPUQuota=200%
TasksMax=256

[Install]
WantedBy=multi-user.target
UNIT
  manifest_add "unit $UNIT"
  put "/etc/systemd/system/$UPDATE_UNIT" 0644 root:root agent <<UNIT
# Written by the Signalith Agent install script (deploy/agent/install.sh).
# Installs an update the agent got ready in $STATE_DIR/update. The agent's
# own service cannot write the program, so this service does it. It trusts
# nothing the agent left: it checks the release's signature with its own
# keys, copies the program here and checks the copy, keeps the version
# before, restarts the agent, and goes back to the version before if the
# new one does not work. It is fenced in too: it writes only the program,
# the copy of the version before and the update folder.
[Unit]
Description=Install a signed Signalith Agent update
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/signalith-agent.md

[Service]
Type=oneshot
ExecStart=$PROGRAM install-update
TimeoutStartSec=15min
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=${PROGRAM%/*} $LIB_DIR $STATE_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UNIT
  put "/etc/systemd/system/$UPDATE_PATH" 0644 root:root agent <<UNIT
# Written by the Signalith Agent install script (deploy/agent/install.sh).
# Starts the updater when the agent has an update ready.
[Unit]
Description=Signalith Agent updates

[Path]
PathExists=$STATE_DIR/update/ready
Unit=$UPDATE_UNIT

[Install]
WantedBy=multi-user.target
UNIT
  manifest_add "unit $UPDATE_PATH"
  manifest_add "unit $UPDATE_UNIT"
}

# health prints what the agent last wrote about item $1 in its health file
# (config, fluentbit, osquery, reported).
health() {
  sed -n "s/^$1=//p" "$STATE_DIR/health" 2>/dev/null | head -n 1
}

# osquery_ready is true when osquery is not installed, or runs.
osquery_ready() {
  [ "$osquery" != yes ] || [ "$(health osquery)" = running ]
}

agent_start() {
  run systemctl daemon-reload
  if [ -n "$dryrun" ]; then
    if [ "$osquery" = yes ]; then
      run systemctl enable --now "$OSQUERY_PATH"
      run systemctl enable "$OSQUERY_UNIT"
    fi
    run systemctl enable --now "$UPDATE_PATH"
    run systemctl enable --now "$UNIT"
    return 0
  fi
  systemctl enable --now "$UPDATE_PATH" >/dev/null 2>&1 || fail "Could not start the unit that installs agent updates." "sudo systemctl status $UPDATE_PATH"
  if [ "$osquery" = yes ]; then
    # Before the agent starts: its first flags start osquery.
    systemctl enable "$OSQUERY_UNIT" >/dev/null 2>&1 || fail "Could not enable osquery's service." "sudo systemctl status $OSQUERY_UNIT"
    systemctl enable --now "$OSQUERY_PATH" >/dev/null 2>&1 || fail "Could not start the unit that restarts osquery with new flags." "sudo systemctl status $OSQUERY_PATH"
    # A run again with the flags in place: osquery starts with them now.
    if [ -f "$CONF_DIR/osquery.flags" ]; then systemctl restart "$OSQUERY_UNIT" >/dev/null 2>&1 || true; fi
  fi
  systemctl enable "$UNIT" >/dev/null 2>&1 || fail "Could not enable the agent's service." "sudo systemctl status $UNIT"
  rm -f "$STATE_DIR/health"
  systemctl restart "$UNIT" || fail "The agent's service did not start." "sudo journalctl -u $UNIT -n 50"
  ok "started the agent"
  # The agent fetches its configuration, starts Fluent Bit and reports
  # within a few seconds; two minutes covers a slow network.
  i=0
  while [ $i -lt 60 ]; do
    if [ "$(health fluentbit)" = running ] && [ "$(health reported)" = yes ] && osquery_ready; then
      if [ "$osquery" = yes ]; then
        ok "Fluent Bit and osquery run with Signalith's configuration, and Signalith has the agent's status"
      else
        ok "Fluent Bit runs with Signalith's configuration, and Signalith has the agent's status"
      fi
      return 0
    fi
    sleep 2
    i=$((i + 1))
  done
  c=$(health config)
  fb=$(health fluentbit)
  [ "$c" = ok ] || fail "The agent could not get its configuration: ${c:-no answer yet}" "sudo journalctl -u $UNIT -n 50"
  case "$fb" in
    running) ;;
    *) fail "Fluent Bit is not running: ${fb:-not started}" "sudo journalctl -u $UNIT -n 50" ;;
  esac
  if [ "$(health reported)" != yes ]; then
    warn "Fluent Bit runs, but Signalith has not had the agent's status yet." "Check the Endpoints page in a few minutes; sudo journalctl -u $UNIT -n 50 says why."
  fi
  if ! osquery_ready; then
    oq=$(health osquery)
    warn "osquery is not running yet: ${oq:-the agent has not started it}" "Check the Endpoints page in a few minutes; sudo journalctl -u $OSQUERY_UNIT -n 50 says why."
  fi
}

uninstall() {
  if [ -z "$dryrun" ]; then
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: it removes a package and a service."
  fi
  [ -f "$manifest" ] || fail "This computer has no agent the script installed (no $manifest)."
  say "Signalith Agent: removing what the install script added"
  # shellcheck disable=SC2013 # names, one a line
  for u in $(sed -n 's/^unit //p' "$manifest"); do
    quiet systemctl disable --now "$u" || true
  done
  # shellcheck disable=SC2013 # names, one a line
  for u in $(sed -n 's/^mask //p' "$manifest"); do
    quiet systemctl unmask "$u" || true
  done
  # shellcheck disable=SC2013 # names, one a line
  for u in $(sed -n 's/^was running //p' "$manifest"); do
    quiet systemctl start "$u" || warn "Could not start $u again, which ran before the agent (see above)." "sudo systemctl start $u"
  done
  sed -n 's/^file //p' "$manifest" | while IFS= read -r f; do
    rm -f "$R$f"
  done
  ok "removed the files it wrote"
  pkgs=$(sed -n 's/^package //p' "$manifest" | awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) printf " %s", l[i] }')
  if [ -n "$pkgs" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      # shellcheck disable=SC2086 # a list of package names
      quiet env DEBIAN_FRONTEND=noninteractive apt-get purge -y --autoremove $pkgs || warn "Removing the packages$pkgs failed (see above); remove them by hand."
    else
      # shellcheck disable=SC2086 # a list of package names
      quiet dnf remove -y $pkgs || warn "Removing the packages$pkgs failed (see above); remove them by hand."
    fi
    ok "removed the packages$pkgs"
  fi
  rm -rf "$R$CONF_DIR" "$R$STATE_DIR" "$R$LIB_DIR"
  run systemctl daemon-reload || true
  say ""
  say "The agent is removed. If no other computer uses its token, revoke it in Signalith: Settings > Agent tokens."
}

# --- Main --------------------------------------------------------------

if [ "$uninstall" = yes ]; then
  uninstall
  exit 0
fi

check_args
say "Signalith Agent: checking this computer"
check_machine
say ""
say "Signalith"
check_ca
check_token
vendor_checks
say ""
# Left by a run that was stopped halfway (by a power cut, say).
rm -f "$R$CONF_DIR"/*.signalith-new
say "Installing"
fluentbit_install
osquery_install
agent_program
agent_files
say ""
if [ -z "$changed" ] && [ -z "$installed" ] && [ -z "$upgraded" ] && { [ -n "$dryrun" ] || systemctl is-active --quiet "$UNIT"; }; then
  say "Nothing to change: the agent is set up as the line says."
  exit 0
fi
say "Starting"
agent_start
say ""
if [ "$warned" -gt 0 ]; then
  say "Done, with $warned warning(s) above. This computer shows on the Endpoints page in Signalith."
else
  say "Done. This computer shows on the Endpoints page in Signalith, and its events in Search within a minute."
fi
