#!/bin/sh
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
#     --ca-sha256 <hex> --version 0.4.0 --token -
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
#   4. Downloads the agent program from Signalith and checks its SHA-256,
#      writes the agent's settings, token and certificate authority, and
#      starts the agent's hardened systemd service.
#   5. Waits until the agent runs Fluent Bit with Signalith's configuration
#      and Signalith has its status.
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

from=''
ca_sha=''
next_ca_sha=''
version=''
token=''
dryrun=''
uninstall=no

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
         [--dry-run <folder>]
       sudo sh install.sh --uninstall

  --from              Signalith's address, which the agent sends to.
  --ca-sha256         SHA-256 of Signalith's certificate authority; the
                      script refuses another one. Leave it out when
                      Signalith's certificate is from a public authority.
  --next-ca-sha256    The new certificate authority while Signalith switches.
  --version           Signalith's version.
  --token             The agent token, or - to read it from the standard
                      input. Left out on a run again, the agent keeps its own.
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
  head -n 1 "$tmp/key" | grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----' ||
    fail "$1's signing key from $2 is not a text (armoured) key."
  case "$4" in
    *.gpg) GNUPGHOME=$tmp/gnupg gpg --batch --yes --dearmor -o "$tmp/key.out" "$tmp/key" ;;
    *) cp "$tmp/key" "$tmp/key.out" ;;
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

# mask_vendor stops and masks Fluent Bit's own service, so there is never
# a second copy sending; --uninstall unmasks it.
mask_vendor() {
  if [ -n "$dryrun" ]; then
    manifest_has "mask $1" || run systemctl mask --now "$1"
    manifest_add "mask $1"
    return 0
  fi
  if [ "$(systemctl is-enabled "$1" 2>/dev/null)" != masked ]; then
    if systemctl is-active --quiet "$1"; then manifest_add "was running $1"; fi
    systemctl mask --now "$1" >/dev/null 2>&1 || true
    manifest_add "mask $1"
  fi
}

upgraded=''
fluentbit_install() {
  fluentbit_repo
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
  mask_vendor fluent-bit.service
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

[Install]
WantedBy=multi-user.target
UNIT
  manifest_add "unit $UNIT"
}

# health prints what the agent last wrote about item $1 in its health file
# (config, fluentbit, reported).
health() {
  sed -n "s/^$1=//p" "$STATE_DIR/health" 2>/dev/null | head -n 1
}

agent_start() {
  run systemctl daemon-reload
  if [ -n "$dryrun" ]; then
    run systemctl enable --now "$UNIT"
    return 0
  fi
  systemctl enable "$UNIT" >/dev/null 2>&1 || fail "Could not enable the agent's service." "sudo systemctl status $UNIT"
  rm -f "$STATE_DIR/health"
  systemctl restart "$UNIT" || fail "The agent's service did not start." "sudo journalctl -u $UNIT -n 50"
  ok "started the agent"
  # The agent fetches its configuration, starts Fluent Bit and reports
  # within a few seconds; two minutes covers a slow network.
  i=0
  while [ $i -lt 60 ]; do
    if [ "$(health fluentbit)" = running ] && [ "$(health reported)" = yes ]; then
      ok "Fluent Bit runs with Signalith's configuration, and Signalith has the agent's status"
      return 0
    fi
    sleep 2
    i=$((i + 1))
  done
  c=$(health config)
  fb=$(health fluentbit)
  [ "$c" = ok ] || fail "The agent could not get its configuration: ${c:-no answer yet}" "sudo journalctl -u $UNIT -n 50"
  case "$fb" in
    running) warn "Fluent Bit runs, but Signalith has not had the agent's status yet." "Check the Endpoints page in a few minutes; sudo journalctl -u $UNIT -n 50 says why." ;;
    *) fail "Fluent Bit is not running: ${fb:-not started}" "sudo journalctl -u $UNIT -n 50" ;;
  esac
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
say ""
# Left by a run that was stopped halfway (by a power cut, say).
rm -f "$R$CONF_DIR"/*.signalith-new
say "Installing"
fluentbit_install
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
