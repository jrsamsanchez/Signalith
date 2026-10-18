#!/bin/sh
# Installs the Signalith Agent on a Mac: one program that runs osquery for
# it, with Signalith as osquery's management server. It fetches what to
# collect from Signalith every few minutes, keeps osquery running with
# Signalith's settings and reports how it is, so nobody edits a
# configuration file by hand. On a Mac, osquery collects everything the
# agent sends: program starts (from Apple's EndpointSecurity), inventory,
# file changes and configuration checks.
#
# Add data > Signalith Agent > macOS gives one line that downloads this
# script from Signalith, checks its SHA-256, and runs it:
#
#    f=$(mktemp) && curl -fsSk --proto '=https' https://siem:7779/api/agent/install-macos.sh -o "$f" &&
#   echo '<sha-256>  '"$f" | shasum -a 256 -c -s &&
#   echo 'sgl_...' | sudo sh "$f" --from https://siem:7779 \
#     --ca-sha256 <hex> --version 0.4.0 --token -
#
# "--token -" reads the agent token from the standard input, so it is
# never on a command line other users of the computer could see.
#
# What it does, in order, stopping at the first problem with a plain
# message:
#   1. Checks the computer: root, macOS version and processor.
#   2. Checks Signalith's certificate authority against the fingerprint in
#      the line (--ca-sha256), then asks Signalith, with the token, for the
#      agent's configuration: a revoked or wrong token stops here, before
#      anything is installed.
#   3. Installs osquery when the Mac does not have it: the package version
#      pinned below, from osquery's site, installed only when Apple's
#      installer says osquery's own Developer ID signed it (or its SHA-256
#      is the one given with --osquery-sha256). osquery's program is checked
#      to be signed by osquery's developer team too.
#   4. Downloads the agent program from Signalith and checks its SHA-256,
#      writes the agent's settings, token and certificate authority, and
#      starts the agent's launchd service.
#   5. Waits until the agent runs osquery with Signalith's configuration
#      and Signalith has its status.
#
# osquery needs Full Disk Access to see programs start and watch files;
# only a person (System Settings) or an MDM profile can give it, so the
# script says how at the end.
#
# Run it again to repair, or to upgrade the agent: it changes only what
# differs. It keeps a copy of itself in /opt/signalith-agent/lib, whose
# --uninstall removes what it added (the list is
# /etc/signalith-agent/manifest).
#
# For tests only: SIGNALITH_AGENT_MACOS_VERSION (for sw_vers).
set -eu

# --- Pinned osquery ----------------------------------------------------
# The osquery version installed on a Mac that has none, and the Apple
# developer team that signs osquery's package and programs (osquery's
# documentation, deployment/process-auditing: the code requirement for
# Full Disk Access).
OSQUERY_VERSION=5.12.1
OSQUERY_URL=https://pkg.osquery.io/darwin/osquery-$OSQUERY_VERSION.pkg
OSQUERY_TEAM=3522FA9PXF
OSQUERY_PKG_ID=io.osquery.agent
OSQUERY_APP=/opt/osquery/lib/osquery.app
OSQUERYD=$OSQUERY_APP/Contents/MacOS/osqueryd

SYSTEMS='macOS 12 or later (Apple silicon or Intel)'

# Where the agent lives. The agent program reads the same paths
# (internal/agentd). /opt, not /usr/local, which Homebrew hands to the
# user on Intel Macs: root runs the program, so only root may change it.
AGENT_DIR=/opt/signalith-agent
PROGRAM=$AGENT_DIR/bin/signalith-agent
# A copy of this script, for --uninstall, and the version before an
# update.
LIB_DIR=$AGENT_DIR/lib
CONF_DIR=/etc/signalith-agent
STATE_DIR=/var/lib/signalith-agent
LABEL=io.signalith.agent
PLIST=/Library/LaunchDaemons/$LABEL.plist

from=''
ca_sha=''
next_ca_sha=''
version=''
token=''
osquery_sha=''
dryrun=''
uninstall=no

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
Usage: echo '<token>' | sudo sh install-macos.sh --from https://<signalith>:7779
         [--ca-sha256 <hex>] [--next-ca-sha256 <hex>] [--version <v>] --token -
         [--osquery-sha256 <hex>] [--dry-run <folder>]
       sudo sh install-macos.sh --uninstall

  --from              Signalith's address, which the agent sends to.
  --ca-sha256         SHA-256 of Signalith's certificate authority; the
                      script refuses another one. Leave it out when
                      Signalith's certificate is from a public authority.
  --next-ca-sha256    The new certificate authority while Signalith switches.
  --version           Signalith's version.
  --token             The agent token, or - to read it from the standard
                      input. Left out on a run again, the agent keeps its own.
  --osquery-sha256    Install osquery's package only when its SHA-256 is
                      this one, instead of checking its signature.
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
    --osquery-sha256) need "$1" $#; osquery_sha=$2; shift 2 ;;
    --osquery-sha256=*) osquery_sha=${1#*=}; shift ;;
    --dry-run) need "$1" $#; dryrun=$2; shift 2 ;;
    --dry-run=*) dryrun=${1#*=}; shift ;;
    --uninstall) uninstall=yes; shift ;;
    # The Linux line's option: osquery is always installed on a Mac.
    --osquery) shift ;;
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
  [ -z "$osquery_sha" ] || osquery_sha=$(hex64 --osquery-sha256 "$osquery_sha")
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

# sha256 prints the SHA-256 of file $1.
sha256() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

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
# no_link stops when $1 is a symbolic link: root never follows one where
# it writes.
no_link() {
  if [ -L "$1" ]; then
    fail "$1 is a symbolic link, which the script does not follow." "Look at what made it (it should be a plain file or folder), remove it, and run the line again."
  fi
}
# root_only stops when folder $1 is not root's, or others can change it:
# root runs what is in it.
root_only() {
  [ -z "$dryrun" ] || return 0
  [ -d "$1" ] || return 0
  [ "$(stat -f '%u' "$1")" = 0 ] ||
    fail "$1 belongs to another user than root, so the agent is not put there." "sudo chown root:wheel '$1', then run the line again."
  if [ -n "$(find "$1" -maxdepth 0 \( -perm -020 -o -perm -002 \) 2>/dev/null)" ]; then
    fail "$1 can be changed by users other than root, so the agent is not put there." "sudo chmod go-w '$1', then run the line again."
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
  if [ -f "$dest" ] && [ "$(sha256 "$4")" = "$(sha256 "$dest")" ]; then
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

arch='' mac_ver=''
check_machine() {
  if [ -n "${SIGNALITH_AGENT_MACOS_VERSION:-}" ]; then
    mac_ver=$SIGNALITH_AGENT_MACOS_VERSION
  else
    [ "$(uname -s)" = Darwin ] || fail "This script is for Macs; this computer runs $(uname -s)." "On Linux, use the Linux line from Add data > Signalith Agent."
    mac_ver=$(sw_vers -productVersion 2>/dev/null) || mac_ver=''
  fi
  if [ -n "$dryrun" ]; then
    info "dry run: files go under $R, commands are printed, nothing else changes"
  else
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: it installs osquery and a service." "Put sudo before sh in the line, as Add data shows it."
    ok "running as root"
  fi
  major=${mac_ver%%.*}
  case "$major" in
    '' | *[!0-9]*) fail "This computer does not say which macOS it runs. The agent runs on $SYSTEMS." ;;
  esac
  [ "$major" -ge 12 ] || fail "The agent runs on $SYSTEMS; this Mac runs macOS $mac_ver." "Update macOS, or set osquery up by hand from Add data > osquery."
  ok "system: macOS $mac_ver"
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "The agent runs on Apple silicon (arm64) and Intel (x86_64) Macs, not $(uname -m)." ;;
  esac
  ok "processor: $arch"
  for tool in curl shasum base64 sed awk; do
    command -v "$tool" >/dev/null 2>&1 || fail "This script needs $tool, which this Mac does not have." "It comes with macOS; check that /usr/bin is on the PATH, then run the line again."
  done
  for d in /opt "$AGENT_DIR" "$AGENT_DIR/bin" "$LIB_DIR" /var/lib; do
    no_link "$R$d"
    root_only "$d"
  done
}

# --- Signalith ---------------------------------------------------------

# pem_sha256 prints the SHA-256 of the first certificate in a PEM file.
pem_sha256() {
  awk '/-----BEGIN CERTIFICATE-----/ { f = 1; next } /-----END CERTIFICATE-----/ { exit } f' "$1" |
    tr -d '\r\n ' | base64 -d >"$tmp/der" 2>/dev/null || true
  sha256 "$tmp/der"
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
    fail "Could not reach Signalith at $from." "Check that this Mac can reach it (curl $from), that the address is right, and that no firewall is in between, then run the line again."
  [ "$code" = 200 ] || fail "Signalith at $from did not hand out its certificate authority (it answered $code)." "$again"
  n=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$tmp/ca-$1.pem") || n=0
  [ "$n" = 1 ] || fail "Signalith at $from handed out $n certificates where it hands out one." "$again If it still fails, someone may be in between this Mac and Signalith."
  got=$(pem_sha256 "$tmp/ca-$1.pem")
  [ "$got" = "$2" ] || fail "This Signalith's certificate authority is not the one the line names." "$again If it still fails, someone may be in between this Mac and Signalith."
  # Only the certificate checked above is kept.
  awk '/-----BEGIN CERTIFICATE-----/ { f = 1 } f { print } /-----END CERTIFICATE-----/ && f { exit }' "$tmp/ca-$1.pem" | tr -d '\r' >"$tmp/ca-$1.one"
  mv -f "$tmp/ca-$1.one" "$tmp/ca-$1.pem"
}
cafile=''
check_ca() {
  if [ -z "$ca_sha" ]; then
    curl -sS --proto '=https' --max-time 30 -o /dev/null "$from/" 2>"$tmp/err" ||
      fail "Could not reach Signalith at $from over HTTPS with this Mac's trusted certificate authorities: $(tail -n 1 "$tmp/err")" "Check the address; if Signalith uses its own certificate authority, copy the line again from Add data: it then names it with --ca-sha256."
    ok "Signalith at $from (certificate checked by this Mac's trusted authorities)"
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
  code=$(sig_get "/api/agent/config?os=darwin&arch=$arch&server=$from" "$tmp/config.json") ||
    fail "Could not reach Signalith at $from to check the token." "Check that this Mac can reach it, then run the line again."
  case "$code" in
    200) ;;
    401 | 403) fail "Signalith refused the token: $(sig_error "$tmp/config.json")" "Make the line again on Add data > Signalith Agent." ;;
    503) fail "Signalith is still starting." "Run the line again in a minute." ;;
    *) fail "Signalith did not hand out the agent's configuration (it answered $code): $(sig_error "$tmp/config.json")" "$again" ;;
  esac
  ok "the token is an agent token Signalith knows"
}

# --- osquery -----------------------------------------------------------

# osquery_signed checks osqueryd is signed by osquery's developer team.
osquery_signed() {
  if [ -n "$dryrun" ]; then
    run codesign --verify --strict -R="anchor apple generic and certificate leaf[subject.OU] = \"$OSQUERY_TEAM\"" "$OSQUERYD"
    return 0
  fi
  codesign --verify --strict -R="anchor apple generic and certificate leaf[subject.OU] = \"$OSQUERY_TEAM\"" "$OSQUERYD" 2>"$tmp/codesign" ||
    fail "$OSQUERYD is not signed by osquery's developer ($OSQUERY_TEAM), so the agent does not run it: $(tail -n 1 "$tmp/codesign")" "Remove osquery (sudo rm -rf /opt/osquery; sudo pkgutil --forget $OSQUERY_PKG_ID) and run the line again: it installs osquery's own package."
}

# osquery_install installs osquery's package when the Mac has no osquery.
# One that is there stays, whoever installed it, once it checks out.
# osquery_pkg_signed says whether pkgutil --check-signature's output (in
# $1) shows an Apple-issued Developer ID Installer certificate whose leaf,
# the first in the chain, ends with osquery's team ID.
osquery_pkg_signed() {
  grep -q '^ *Status: signed by a developer certificate issued by Apple' "$1" &&
    grep -Eq "^ *1\. Developer ID Installer: .* \($OSQUERY_TEAM\)\$" "$1"
}

osquery_install() {
  if [ -f /Library/LaunchDaemons/io.osquery.agent.plist ] && [ -z "$dryrun" ]; then
    warn "osquery's own service is set up on this Mac too, so osquery may run twice." "If nothing else uses it: sudo launchctl bootout system/io.osquery.agent"
  fi
  if { [ -n "$dryrun" ] && manifest_has osquery-pkg; } || { [ -z "$dryrun" ] && [ -x "$OSQUERYD" ]; }; then
    osquery_signed
    ok "osquery is installed"
    return 0
  fi
  changed="$changed agent"
  if [ -n "$dryrun" ]; then
    printf '    would download %s and check it is signed by osquery (%s)\n' "$OSQUERY_URL" "$OSQUERY_TEAM"
    run installer -pkg "$tmp/osquery.pkg" -target /
    manifest_add osquery-pkg
    osquery_signed
    ok "installed osquery $OSQUERY_VERSION"
    return 0
  fi
  curl -fsSL --proto '=https' --max-time 300 -o "$tmp/osquery.pkg" "$OSQUERY_URL" ||
    fail "Could not download osquery from $OSQUERY_URL." "Check that this Mac can reach pkg.osquery.io, then run the line again."
  if [ -n "$osquery_sha" ]; then
    got=$(sha256 "$tmp/osquery.pkg")
    [ "$got" = "$osquery_sha" ] || fail "The osquery package is not the one expected (its SHA-256 is $got, not $osquery_sha), so it was not installed." "Download it again; if it keeps failing, it was changed on its way here."
    ok "osquery package checked (SHA-256 $(printf '%s' "$got" | cut -c1-12))"
  else
    pkgutil --check-signature "$tmp/osquery.pkg" >"$tmp/pkgsig" 2>&1 || true
    if ! osquery_pkg_signed "$tmp/pkgsig"; then
      fail "The osquery package is not signed by osquery's developer ($OSQUERY_TEAM), so it was not installed: $(grep -m 1 'Status:' "$tmp/pkgsig" || true)" "Run the line again later; or check the package's SHA-256 against the one on osquery.io/downloads and run the line again with --osquery-sha256 <it>."
    fi
    ok "osquery package signed by osquery's developer ($OSQUERY_TEAM)"
  fi
  quiet installer -pkg "$tmp/osquery.pkg" -target / || fail "Installing osquery failed (see above)." "Run the line again."
  manifest_add osquery-pkg
  [ -x "$OSQUERYD" ] || fail "The osquery package has no $OSQUERYD." "Tell us: osquery's package may have changed."
  osquery_signed
  ok "installed osquery $OSQUERY_VERSION"
}

# --- The agent ---------------------------------------------------------

agent_program() {
  code=$(sig_get "/api/agent/program?os=darwin&arch=$arch" "$tmp/agent" 300) ||
    fail "Could not download the agent program from Signalith." "Check that this Mac can reach it, then run the line again."
  case "$code" in
    200) ;;
    404) fail "This Signalith has no agent program for macOS on $arch: $(sig_error "$tmp/agent")" "Install a released Signalith version, which carries the agent programs, or set osquery up by hand from Add data > osquery." ;;
    *) fail "Signalith did not hand out the agent program (it answered $code): $(sig_error "$tmp/agent")" "Run the line again." ;;
  esac
  want=$(tr -d '\r' <"$tmp/agent.headers" | sed -n 's/^[Xx]-[Ss]ignalith-[Ss][Hh][Aa]256: *\([0-9a-f]\{64\}\)$/\1/p' | head -n 1)
  [ -n "$want" ] || fail "Signalith did not say the agent program's SHA-256." "Run the line again."
  got=$(sha256 "$tmp/agent")
  [ "$got" = "$want" ] || fail "The agent program downloaded is not whole (its SHA-256 differs)." "Run the line again."
  folder "$AGENT_DIR" 0755 root:wheel
  folder "$AGENT_DIR/bin" 0755 root:wheel
  folder "$LIB_DIR" 0755 root:wheel
  put_file "$PROGRAM" 0755 root:wheel "$tmp/agent" agent
  # Downloaded by curl, so macOS puts no quarantine on it; the agent
  # program is not notarized, so make sure none is there.
  [ -n "$dryrun" ] || xattr -d com.apple.quarantine "$PROGRAM" 2>/dev/null || true
  ok "the agent program ($(printf '%s' "$got" | cut -c1-12))"
}

agent_files() {
  folder "$CONF_DIR" 0755 root:wheel
  folder /var/lib 0755 root:wheel
  folder "$STATE_DIR" 0700 root:wheel
  printf '%s\n' "$token" | put "$CONF_DIR/token" 0600 root:wheel agent
  if [ -n "$cafile" ]; then
    put_file "$CONF_DIR/ca.pem" 0644 root:wheel "$cafile" agent
  elif [ -f "$R$CONF_DIR/ca.pem" ] && manifest_has "file $CONF_DIR/ca.pem"; then
    rm -f "$R$CONF_DIR/ca.pem"
    changed="$changed agent"
  fi
  put_file "$LIB_DIR/install-macos.sh" 0755 root:wheel "$0" script
  put "$CONF_DIR/agent.conf" 0644 root:wheel agent <<CONF
# Written by the Signalith Agent install script (deploy/agent/install-macos.sh).
# Run the line from Add data again to change it.
SERVER=$from
SIGNALITH_VERSION=$version
OSQUERY=yes
CONF
  put "$PLIST" 0644 root:wheel agent <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by the Signalith Agent install script (deploy/agent/install-macos.sh).
     The agent fetches what to collect from Signalith and runs osquery with
     it. It logs to $STATE_DIR/agent.log. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$PROGRAM</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>Umask</key>
	<integer>63</integer>
	<!-- The updater the agent starts restarts this service; it must outlive it. -->
	<key>AbandonProcessGroup</key>
	<true/>
</dict>
</plist>
PLIST
  manifest_add "launchd $LABEL"
}

# health prints what the agent last wrote about item $1 in its health file
# (config, osquery, reported).
health() {
  sed -n "s/^$1=//p" "$STATE_DIR/health" 2>/dev/null | head -n 1
}

agent_start() {
  if [ -n "$dryrun" ]; then
    run launchctl bootout "system/$LABEL"
    run launchctl bootstrap system "$PLIST"
    run launchctl enable "system/$LABEL"
    return 0
  fi
  launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  rm -f "$STATE_DIR/health"
  # bootout returns before the service has stopped.
  i=0
  while launchctl print "system/$LABEL" >/dev/null 2>&1 && [ $i -lt 10 ]; do
    sleep 1
    i=$((i + 1))
  done
  launchctl bootstrap system "$PLIST" 2>"$tmp/err" || fail "The agent's service did not start: $(tail -n 1 "$tmp/err")" "sudo launchctl print system/$LABEL; the agent's log is $STATE_DIR/agent.log."
  launchctl enable "system/$LABEL" >/dev/null 2>&1 || true
  ok "started the agent"
  # The agent fetches its configuration, starts osquery and reports within
  # a few seconds; two minutes covers a slow network.
  i=0
  while [ $i -lt 60 ]; do
    if [ "$(health osquery)" = running ] && [ "$(health reported)" = yes ]; then
      ok "osquery runs with Signalith's configuration, and Signalith has the agent's status"
      return 0
    fi
    sleep 2
    i=$((i + 1))
  done
  c=$(health config)
  [ "$c" = ok ] || fail "The agent could not get its configuration: ${c:-no answer yet}" "The agent's log is $STATE_DIR/agent.log."
  oq=$(health osquery)
  case "$oq" in
    running) ;;
    *) warn "osquery is not running yet: ${oq:-the agent has not started it}" "Check the Endpoints page in a few minutes; $STATE_DIR/agent.log says why." ;;
  esac
  if [ "$(health reported)" != yes ]; then
    warn "Signalith has not had the agent's status yet." "Check the Endpoints page in a few minutes; $STATE_DIR/agent.log says why."
  fi
}

uninstall() {
  if [ -z "$dryrun" ]; then
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: it removes osquery and a service."
  fi
  [ -f "$manifest" ] || fail "This Mac has no agent the script installed (no $manifest)."
  say "Signalith Agent: removing what the install script added"
  # shellcheck disable=SC2013 # names, one a line
  for l in $(sed -n 's/^launchd //p' "$manifest"); do
    quiet launchctl bootout "system/$l" || true
  done
  sed -n 's/^file //p' "$manifest" | while IFS= read -r f; do
    rm -f "$R$f"
  done
  ok "removed the files it wrote"
  if manifest_has osquery-pkg; then
    run rm -rf "$R/opt/osquery" "$R/usr/local/bin/osqueryi" "$R/usr/local/bin/osqueryctl"
    quiet pkgutil --forget "$OSQUERY_PKG_ID" || true
    ok "removed osquery"
  fi
  rm -rf "$R$CONF_DIR" "$R$STATE_DIR" "$R$AGENT_DIR"
  say ""
  say "The agent is removed. If no other computer uses its token, revoke it in Signalith: Settings > Agent tokens."
}

# --- Main --------------------------------------------------------------

if [ "$uninstall" = yes ]; then
  uninstall
  exit 0
fi

check_args
say "Signalith Agent: checking this Mac"
check_machine
say ""
say "Signalith"
check_ca
check_token
say ""
# Left by a run that was stopped halfway (by a power cut, say).
rm -f "$R$CONF_DIR"/*.signalith-new
say "Installing"
osquery_install
agent_program
agent_files
say ""
if [ -z "$changed" ] && { [ -n "$dryrun" ] || launchctl print "system/$LABEL" >/dev/null 2>&1; }; then
  say "Nothing to change: the agent is set up as the line says."
  exit 0
fi
say "Starting"
agent_start
say ""
say "One more step on this Mac: give osquery Full Disk Access, so it can see programs start and watch files."
say "  System Settings > Privacy & Security > Full Disk Access > + > press Cmd+Shift+G, type"
say "  $OSQUERY_APP and choose Open. (With an MDM, push a privacy profile instead; see the Signalith docs.)"
say ""
if [ "$warned" -gt 0 ]; then
  say "Done, with $warned warning(s) above. This Mac shows on the Endpoints page in Signalith."
else
  say "Done. This Mac shows on the Endpoints page in Signalith, and its events in Search within a few minutes."
fi
