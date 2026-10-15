#!/bin/sh
# Builds a Signalith network sensor: Zeek and Suricata watch a copy of
# your network's traffic (a switch's mirror port, or a TAP) and the Fluent
# Bit agent sends what they log to Signalith.
#
# Add data > Network sensor > Set up a new sensor gives one line that
# downloads this script from Signalith, checks its SHA-256, and runs it:
#
#    f=$(mktemp) && curl -fsSk --proto '=https' https://siem:8080/api/sensor/install.sh -o "$f" &&
#   echo '<sha-256>  '"$f" | sha256sum -c --quiet &&
#   echo 'sgl_...' | sudo sh "$f" --role sensor --from https://siem:8080 \
#     --ca-sha256 <hex> --version 1.6.0 --token -
#
# "--token -" reads the sensor's agent token from the standard input, so it
# is never on a command line other users of the machine could see. The
# line starts with a space, which keeps it out of bash's history where
# bash is set to (Ubuntu and Debian are; Rocky and Alma are not).
#
# What it does, in order, stopping at the first problem with a plain
# message:
#   1. Checks the machine (system, processor, memory, disk, clock) and
#      prints a checklist: problems that stop it, warnings that do not.
#   2. Checks Signalith's certificate authority against the fingerprint
#      in the line (--ca-sha256), then asks Signalith, with the token, for
#      the agent's configuration: a revoked or wrong token stops here,
#      before anything is installed.
#   3. Chooses the capture port: --interface, or the one network port
#      that does not reach the network (it asks when there are several).
#   4. Adds the publishers' own signed package repositories, each key
#      checked against a fingerprint pinned below, and installs Zeek (LTS),
#      Suricata and Fluent Bit. With --docker it pulls their images
#      instead, pinned by digest.
#   5. Writes the configuration, the hardened systemd units and timers
#      (Zeek and the agent run as their own users, with only the rights
#      they need), tests Suricata's configuration, downloads the rules,
#      starts everything, and waits until Signalith has heard from the
#      sensor.
#
# Run it again to repair, or to upgrade Zeek, Suricata and Fluent Bit to
# their publishers' newest packages: it changes only what differs, and says
# "Nothing to change" when nothing does. It keeps a copy of itself in
# /usr/lib/signalith-sensor/install.sh; --uninstall removes what it added
# (the list is /etc/signalith-sensor/manifest).
#
# For tests only: SIGNALITH_SENSOR_SYSFS (a folder standing for /sys),
# SIGNALITH_SENSOR_OS_RELEASE (for /etc/os-release),
# SIGNALITH_SENSOR_PROC (for /proc) and SIGNALITH_SENSOR_SAMPLE_SECONDS
# (how long to count packets on the ports, 10 by default).
set -eu

# --- Pinned signing keys -----------------------------------------------
# The full fingerprint of each publisher's repository signing key. A key
# downloaded from the publisher is used only when its fingerprint is this
# one. An empty one is not verified yet: the script then refuses to add
# that repository (see docs/network-sensor.md, "Signing keys").
#
# Fluent Bit (packages.fluentbit.io/fluentbit.key), as published in Fluent
# Bit's documentation (installation/downloads/linux).
KEY_FPR_FLUENTBIT=C3C0A28534B9293EAF51FABD9F9DDC083888C1CD
# OISF's Suricata PPA (ppa:oisf/suricata-stable), as Launchpad shows it on
# the PPA's page; the key is fetched from keyserver.ubuntu.com by it.
KEY_FPR_OISF_PPA=121504ADE276E141AD704A75AC10378CF205C960
# Zeek's openSUSE Build Service project (security:zeek, Release.key).
KEY_FPR_ZEEK_OBS=F9FA0223B56B116C363737EF5DA57BDD6DD785CA
# OISF's Fedora COPR for Rocky and Alma Linux (@oisf/suricata-8.0).
KEY_FPR_OISF_COPR=76F7EC544835D6B60BB559799E86AAEAE704C1FB
# The two empty ones could not be checked against their publishers when
# this was written. Until they are filled in, the checklist says so before
# anything is installed (sensor_sources), and points to what works:
# --docker, or leaving that program out.

# Zeek's long-term support line (OBS package zeek-<LTS>).
ZEEK_PACKAGE='zeek-8.0'

# --docker: the publishers' images, pinned by version and digest.
IMAGE_ZEEK=zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
IMAGE_SURICATA=jasonish/suricata:8.0.7@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26
IMAGE_FLUENTBIT=fluent/fluent-bit:5.1.4@sha256:a9cc9627aeabb8bb33077ee85b6ec8c0fe40aff8e7000bb4e8cd924511fa626c

# --- Systems -----------------------------------------------------------
# Where each supported system gets the three programs:
#
#   system          Zeek (OBS)       Suricata                  Fluent Bit
#   Ubuntu 22.04    xUbuntu_22.04    ppa:oisf/suricata-stable  ubuntu/jammy
#   Ubuntu 24.04    xUbuntu_24.04    ppa:oisf/suricata-stable  ubuntu/noble
#   Debian 12       Debian_12        bookworm-backports        debian/bookworm
#   Debian 13       Debian_13        trixie (Debian's own)     debian/trixie
#   Rocky/Alma 9    (none)           COPR @oisf/suricata-8.0   centos/9
#
# Zeek publishes no packages for Rocky, Alma or RHEL: there, use --no-zeek,
# or --docker.
SYSTEMS='Ubuntu 22.04 or 24.04, Debian 12 or 13, Rocky Linux 9 or AlmaLinux 9'

role=''
from=''
ca_sha=''
next_ca_sha=''
version=''
token=''
name=''
iface=''
old_iface=''
networks=''
zeek=yes
suricata=yes
protocols=no
local_rules=''
zeek_workers=''
suricata_threads=''
docker=no
check_only=no
dryrun=''
uninstall=no
purge=no

sysfs=${SIGNALITH_SENSOR_SYSFS:-/sys}
os_release=${SIGNALITH_SENSOR_OS_RELEASE:-/etc/os-release}
procfs=${SIGNALITH_SENSOR_PROC:-/proc}
sample=${SIGNALITH_SENSOR_SAMPLE_SECONDS:-10}
default_networks=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8

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
# why prints the last lines a command wrote to $tmp/out, under a warning.
why() {
  tail -n 5 "$tmp/out" 2>/dev/null | sed 's/^/      | /'
}
fail() {
  printf '  \342\234\227 %s\n' "$1" >&2
  if [ $# -gt 1 ]; then printf '      Fix: %s\n' "$2" >&2; fi
  exit 1
}
usage() {
  cat <<'USAGE'
Usage: echo '<token>' | sudo sh install.sh --role sensor --from https://<signalith>:8080
         [--ca-sha256 <hex>] [--next-ca-sha256 <hex>] [--version <v>] --token -
         [--name <name>] [--interface <port>] [--networks <cidr,...>]
         [--no-zeek | --no-suricata] [--suricata-protocols] [--local-rules <file>]
         [--zeek-workers <n>] [--suricata-threads <n>] [--docker]
         [--check-only] [--dry-run <folder>]
       sudo sh install.sh --uninstall [--purge]

  --role              What to build: sensor (the only role for now).
  --from              Signalith's address, which the sensor sends to.
  --ca-sha256         SHA-256 of Signalith's certificate authority; the
                      script refuses another one. Leave it out when
                      Signalith's certificate is from a public authority.
  --next-ca-sha256    The new certificate authority while Signalith switches.
  --version           Signalith's version, for the Endpoints page.
  --token             The sensor's agent token, or - to read it from the
                      standard input.
  --name              The sensor's name in Signalith (default: the host name).
  --interface         The capture port (plugged into the mirror port or TAP).
  --networks          Your own networks (default: the private ranges).
  --no-zeek           Suricata only.
  --no-suricata       Zeek only.
  --suricata-protocols  Suricata also logs flows, DNS, HTTP and TLS (on when
                      there is no Zeek).
  --local-rules       A file of your own Suricata rules to add.
  --zeek-workers      Zeek processes reading the port (default from the cores).
  --suricata-threads  Suricata capture threads (default: half the cores).
  --docker            Run the three programs in containers (Docker Engine).
  --check-only        Check the machine and Signalith, change nothing.
  --dry-run           Write every file under this folder and print the
                      commands instead of running them.
  --uninstall         Remove what the script added (--purge: logs too).
USAGE
}

# need checks a flag has a value.
need() {
  [ "$2" -ge 2 ] || fail "$1 needs a value. Run with --help to see how this script is used."
}
while [ $# -gt 0 ]; do
  case "$1" in
    --role) need "$1" $#; role=$2; shift 2 ;;
    --role=*) role=${1#*=}; shift ;;
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
    --name) need "$1" $#; name=$2; shift 2 ;;
    --name=*) name=${1#*=}; shift ;;
    --interface) need "$1" $#; iface=$2; shift 2 ;;
    --interface=*) iface=${1#*=}; shift ;;
    --networks) need "$1" $#; networks=$2; shift 2 ;;
    --networks=*) networks=${1#*=}; shift ;;
    --no-zeek) zeek=no; shift ;;
    --no-suricata) suricata=no; shift ;;
    --suricata-protocols) protocols=yes; shift ;;
    --local-rules) need "$1" $#; local_rules=$2; shift 2 ;;
    --local-rules=*) local_rules=${1#*=}; shift ;;
    --zeek-workers) need "$1" $#; zeek_workers=$2; shift 2 ;;
    --zeek-workers=*) zeek_workers=${1#*=}; shift ;;
    --suricata-threads) need "$1" $#; suricata_threads=$2; shift 2 ;;
    --suricata-threads=*) suricata_threads=${1#*=}; shift ;;
    --docker) docker=yes; shift ;;
    --check-only) check_only=yes; shift ;;
    --dry-run) need "$1" $#; dryrun=$2; shift 2 ;;
    --dry-run=*) dryrun=${1#*=}; shift ;;
    --uninstall) uninstall=yes; shift ;;
    --purge) purge=yes; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; fail "Unknown option: $1" ;;
  esac
done

# --- Common: checks of the flags -------------------------------------

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
manifest=$R/etc/signalith-sensor/manifest
conf=$R/etc/signalith-sensor/sensor.conf

# hex64 checks a SHA-256 written in hexadecimal, and prints it in lower case.
hex64() {
  case "$2" in
    *[!0-9a-fA-F]*) fail "$1 must be 64 hexadecimal characters." "Copy the whole line again from Add data > Network sensor." ;;
  esac
  [ ${#2} -eq 64 ] || fail "$1 must be 64 hexadecimal characters." "Copy the whole line again from Add data > Network sensor."
  printf '%s' "$2" | tr 'A-F' 'a-f'
}
# count checks a number of processes or threads.
count() {
  case "$2" in
    '' | *[!0-9]*) fail "$1 must be a number from 1 to 64." ;;
  esac
  if [ "$2" -lt 1 ] || [ "$2" -gt 64 ]; then fail "$1 must be a number from 1 to 64."; fi
}
# conf_get prints a value the last run wrote to sensor.conf.
conf_get() {
  sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$conf" 2>/dev/null | head -n 1
}

common_args() {
  case "$role" in
    sensor) ;;
    '') fail "--role is missing." "Copy the whole line again from Add data > Network sensor; it says --role sensor." ;;
    *) fail "Unknown role: $role. This script builds a network sensor: --role sensor." ;;
  esac
  case "$from" in
    https://*) ;;
    '') fail "--from is missing: the address of your Signalith." "Copy the whole line again from Add data > Network sensor." ;;
    *) fail "--from must be an https:// address: a sensor sends only over HTTPS." ;;
  esac
  hostport=${from#https://}
  case "$hostport" in
    '' | */* | *[!A-Za-z0-9.:[\]-]*) fail "--from must be Signalith's address and nothing else, like https://siem.example.com:8080 (no path)." ;;
  esac
  [ -z "$ca_sha" ] || ca_sha=$(hex64 --ca-sha256 "$ca_sha")
  [ -z "$next_ca_sha" ] || next_ca_sha=$(hex64 --next-ca-sha256 "$next_ca_sha")
  if [ -n "$next_ca_sha" ] && [ -z "$ca_sha" ]; then
    fail "--next-ca-sha256 needs --ca-sha256 too."
  fi
  case "$version" in
    '') version=unknown ;;
    *[!A-Za-z0-9.+-]*) fail "--version must be a version number, like 1.6.0." ;;
  esac
  if [ "$token" = - ]; then
    IFS= read -r token || [ -n "$token" ] || fail "No token on the standard input." "Copy the whole line again from Add data > Network sensor: it starts with echo 'sgl_...'."
    token=$(printf '%s' "$token" | tr -d '[:space:]')
    [ -n "$token" ] || fail "No token on the standard input." "Copy the whole line again from Add data > Network sensor: it starts with echo 'sgl_...'."
  fi
  if [ -z "$token" ] && [ -r "$R/etc/signalith-sensor/token.env" ]; then
    # A re-run without a token keeps the sensor's token.
    token=$(sed -n 's/^SIGNALITH_TOKEN=//p' "$R/etc/signalith-sensor/token.env" | head -n 1)
  fi
  case "$token" in
    '') fail "--token is missing." "Copy the whole line again from Add data > Network sensor: it holds the sensor's token." ;;
    sgl_*) ;;
    *) fail "This is not a Signalith agent token (they start with sgl_)." "Copy the whole line again from Add data > Network sensor." ;;
  esac
  case "${token#sgl_}" in
    *[!a-z2-7]*) fail "The token is not whole: a Signalith agent token is sgl_ and 52 letters and digits." "Copy the whole line again from Add data > Network sensor." ;;
  esac
  [ ${#token} -eq 56 ] || fail "The token is not whole: a Signalith agent token is sgl_ and 52 letters and digits." "Copy the whole line again from Add data > Network sensor."
  [ -n "$name" ] || name=$(conf_get NAME)
  [ -n "$name" ] || name=$(hostname -s 2>/dev/null || hostname)
  case "$name" in
    '' | -* | *[!A-Za-z0-9._-]*) fail "The sensor's name must be letters, digits, dots, dashes and underscores: $name" "Give one with --name, like --name nsm-01." ;;
  esac
  [ ${#name} -le 63 ] || fail "The sensor's name is longer than 63 characters." "Give a shorter one with --name."
  old_iface=$(conf_get INTERFACE)
  [ -n "$iface" ] || iface=$(conf_get INTERFACE)
  if [ -n "$iface" ]; then
    case "$iface" in
      *[!A-Za-z0-9_.:-]*) fail "--interface must be a network port's name, like ens192 (letters, digits, and . _ : -)." ;;
    esac
    [ ${#iface} -le 15 ] || fail "--interface must be a network port's name of at most 15 characters."
  fi
  [ -n "$networks" ] || networks=$(conf_get NETWORKS)
  [ -n "$networks" ] || networks=$default_networks
  check_networks
  if [ "$zeek" = no ] && [ "$suricata" = no ]; then
    fail "--no-zeek and --no-suricata leave the sensor nothing to run: keep at least one."
  fi
  if [ "$zeek" = no ]; then protocols=yes; fi
  [ -z "$zeek_workers" ] || count --zeek-workers "$zeek_workers"
  [ -z "$suricata_threads" ] || count --suricata-threads "$suricata_threads"
  if [ -n "$local_rules" ]; then
    [ -f "$local_rules" ] || fail "--local-rules $local_rules: there is no such file."
  fi
}

# check_networks checks --networks: addresses with a prefix length,
# separated by commas, like 10.0.0.0/8,fd00::/8.
check_networks() {
  [ ${#networks} -le 2000 ] || fail "--networks is too long: give at most a few dozen ranges."
  old_ifs=$IFS
  IFS=,
  for net in $networks; do
    bits=${net#*/}
    case "$net" in
      */*/* | *[!0-9a-fA-F.:/]* | /* | */ | */*[!0-9]*) IFS=$old_ifs; fail "--networks: $net is not a network like 10.0.0.0/8." ;;
      */*) ;;
      *) IFS=$old_ifs; fail "--networks: $net needs a prefix length, like 10.0.0.0/8." ;;
    esac
    case "$net" in
      *:*) [ "$bits" -le 128 ] || { IFS=$old_ifs; fail "--networks: $net has a prefix longer than 128."; } ;;
      *.*.*.*) [ "$bits" -le 32 ] || { IFS=$old_ifs; fail "--networks: $net has a prefix longer than 32."; } ;;
      *) IFS=$old_ifs; fail "--networks: $net is not a network like 10.0.0.0/8." ;;
    esac
  done
  IFS=$old_ifs
}

# --- Common: running and writing --------------------------------------

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
    (umask 077 && printf '# Written by the Signalith sensor install script: what it added, for --uninstall.\n' >"$manifest")
  fi
  grep -qxF "$*" "$manifest" || printf '%s\n' "$*" >>"$manifest"
}
manifest_has() {
  [ -f "$manifest" ] && grep -qxF "$*" "$manifest"
}

changed=''
# same_file is true when files $1 and $2 hold the same bytes (cmp is not
# on every minimal system).
same_file() {
  [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]
}

# no_link stops when $1 is a symbolic link: root never follows one where
# it writes, so a program that owns a folder cannot point root at another
# file (like /etc/shadow) through it.
no_link() {
  if [ -L "$1" ]; then
    fail "$1 is a symbolic link, which the script does not follow." "Look at what made it (it should be a plain file or folder), remove it, and run the line again."
  fi
}

# put_file writes file $1 (mode $2, owner $3) from $4 when it differs from
# what is there, and notes group $5 as changed (its service restarts). The
# file it replaces is kept once as <file>.signalith-orig when $6 is orig.
# The new file is made readable by root only, and gets its mode once it
# holds the whole content.
put_file() {
  dest=$R$1
  no_link "$dest"
  if [ -f "$dest" ] && same_file "$4" "$dest"; then
    set_owner "$dest" "$2" "$3"
    return 0
  fi
  mkdir -p "${dest%/*}"
  if [ -f "$dest" ]; then
    save=$tmp/prev$(printf '%s' "$1" | tr / _)
    cp -p "$dest" "$save"
    if [ "${6:-}" = orig ] && [ ! -e "$dest.signalith-orig" ] && ! manifest_has "file $1"; then
      cp -p "$dest" "$dest.signalith-orig"
      manifest_add "orig $1"
    fi
  fi
  rm -f "$dest.signalith-new"
  newfile=$dest.signalith-new
  (umask 077 && cp "$4" "$dest.signalith-new")
  set_owner "$dest.signalith-new" "$2" "$3"
  mv -f "$dest.signalith-new" "$dest"
  newfile=''
  manifest_has "orig $1" || manifest_add "file $1"
  case " $changed " in
    *" $5 "*) ;;
    *) changed="$changed $5" ;;
  esac
}
# put writes standard input to a file with put_file.
put() {
  (umask 077 && cat >"$tmp/put")
  put_file "$1" "$2" "$3" "$tmp/put" "$4" "${5:-}"
}
# restore puts back the file put_file replaced in this run.
restore() {
  save=$tmp/prev$(printf '%s' "$1" | tr / _)
  if [ -f "$save" ]; then
    cp -p "$save" "$R$1"
  else
    rm -f "$R$1"
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

# --- Common: the machine ----------------------------------------------

os_id='' os_ver='' os_name='' pkg='' codename=''
zeek_obs='' fb_repo='' backports=''
common_os() {
  [ -r "$os_release" ] || fail "This machine does not say which Linux it is (no /etc/os-release). The sensor runs on $SYSTEMS."
  os_id=$(sed -n 's/^ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$os_release" | head -n 1)
  os_ver=$(sed -n 's/^VERSION_ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$os_release" | head -n 1)
  os_name=$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$os_release" | head -n 1)
  [ -n "$os_name" ] || os_name="$os_id $os_ver"
  case "$os_id:$os_ver" in
    ubuntu:22.04) pkg=apt codename=jammy zeek_obs=xUbuntu_22.04 fb_repo=ubuntu/jammy ;;
    ubuntu:24.04) pkg=apt codename=noble zeek_obs=xUbuntu_24.04 fb_repo=ubuntu/noble ;;
    debian:12*) pkg=apt codename=bookworm zeek_obs=Debian_12 fb_repo=debian/bookworm backports=bookworm-backports ;;
    debian:13*) pkg=apt codename=trixie zeek_obs=Debian_13 fb_repo=debian/trixie ;;
    rocky:9* | almalinux:9* | rhel:9*) pkg=dnf fb_repo=centos/9 ;;
    *)
      if [ "$docker" = yes ]; then
        ok "system: $os_name (with Docker)"
        return 0
      fi
      fail "The sensor runs on $SYSTEMS; this machine runs $os_name, which is not supported yet." "Use Ubuntu 24.04, or run the programs in containers with --docker."
      ;;
  esac
  ok "system: $os_name"
}

common_machine() {
  if [ -n "$dryrun" ]; then
    info "dry run: files go under $R, commands are printed, nothing else changes"
  else
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: it installs packages and services." "Put sudo before sh in the line, as Add data shows it."
    ok "running as root"
    if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
      fail "This machine does not run systemd, which the sensor's services need." "Use $SYSTEMS."
    fi
    ok "systemd"
  fi
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "The sensor runs on 64-bit x86 (amd64) and 64-bit ARM (arm64), not $(uname -m)." ;;
  esac
  ok "processor: $arch"
  common_os
  for tool in curl sha256sum base64 sed awk; do
    command -v "$tool" >/dev/null 2>&1 || fail "This script needs $tool, which this machine does not have." "sudo apt-get install curl coreutils (or sudo dnf install curl coreutils), then run the line again."
  done
}

# sensor_sources checks, before anything is installed, that each program
# chosen can come from its publisher's signed packages on this system.
sensor_sources() {
  [ "$docker" = no ] || return 0
  if [ "$zeek" = yes ] && [ "$pkg" = dnf ]; then
    fail "Zeek publishes no packages for $os_name." "Run the line with --no-zeek (Suricata only), with --docker (Zeek in a container), or on Ubuntu or Debian."
  fi
  unpinned=''
  if [ "$zeek" = yes ] && [ -z "$KEY_FPR_ZEEK_OBS" ]; then unpinned=Zeek; fi
  if [ "$suricata" = yes ]; then
    if { [ "$pkg" = dnf ] && [ -z "$KEY_FPR_OISF_COPR" ]; } || { [ "$os_id" = ubuntu ] && [ -z "$KEY_FPR_OISF_PPA" ]; }; then
      unpinned="${unpinned:+$unpinned, }Suricata"
    fi
  fi
  if [ -z "$KEY_FPR_FLUENTBIT" ]; then unpinned="${unpinned:+$unpinned, }Fluent Bit"; fi
  if [ -z "$unpinned" ]; then
    ok "packages: from their publishers' signed repositories"
    return 0
  fi
  how="Run the line with --docker: the programs then run in their publishers' containers."
  if [ "$unpinned" = Zeek ] && [ "$suricata" = yes ]; then
    how="Run the line with --no-zeek (Suricata only), or with --docker (Zeek in a container)."
  fi
  if [ -n "$dryrun" ]; then
    warn "dry run: this version of the script cannot install $unpinned from packages, as it has no checked signing key for it; a real run stops here." "$how"
    return 0
  fi
  fail "This version of the script cannot install $unpinned from packages: it has no checked signing key for it, and it installs nothing it cannot check." "$how"
}

cores=1
sensor_resources() {
  cores=$(nproc 2>/dev/null || echo 1)
  case "$cores" in '' | *[!0-9]*) cores=1 ;; esac
  if [ "$cores" -lt 4 ]; then
    warn "$cores processor cores: a sensor needs 4 or more, or Zeek and Suricata drop packets on a busy link." "Give the machine 4 or more cores."
  else
    ok "$cores processor cores"
  fi
  mem=$(awk '/^MemTotal:/ { print int($2 / 1024 / 1024 + 0.5) }' "$procfs/meminfo" 2>/dev/null)
  case "$mem" in '' | *[!0-9]*) mem=0 ;; esac
  if [ "$mem" -lt 8 ]; then
    warn "${mem} GB of memory: a sensor needs 8 GB or more." "Give the machine 8 GB of memory or more."
  else
    ok "${mem} GB of memory"
  fi
  for dir in /var /opt; do
    d=$R$dir
    [ -d "$d" ] || d=$R/
    free=$(df -Pk "$d" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024 / 1024) }')
    case "$free" in '' | *[!0-9]*) free=0 ;; esac
    if [ "$free" -lt 50 ]; then
      warn "${free} GB free under $dir: logs and the agent's buffer need 50 GB or more." "Give $dir a bigger disk."
    else
      ok "${free} GB free under $dir"
    fi
  done
  if command -v timedatectl >/dev/null 2>&1; then
    if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; then
      ok "the clock is synchronised"
    else
      warn "The clock is not synchronised, so the times of what the sensor sees may be off." "sudo timedatectl set-ntp true"
    fi
  fi
  if command -v lsblk >/dev/null 2>&1 && lsblk -nro TYPE 2>/dev/null | grep -qx crypt; then
    ok "the disk is encrypted"
  else
    info "the disk is not encrypted (LUKS): the logs hold what people do on your network, so an encrypted disk is better"
  fi
}

# --- Common: Signalith -------------------------------------------------

cafile=''
# pem_sha256 prints the SHA-256 of the first certificate in a PEM file.
pem_sha256() {
  awk '/-----BEGIN CERTIFICATE-----/ { f = 1; next } /-----END CERTIFICATE-----/ { exit } f' "$1" |
    tr -d '\r\n ' | base64 -d 2>/dev/null | sha256sum | awk '{ print $1 }'
}
# fetch_ca downloads one of Signalith's certificate authorities (which=$1)
# and checks it is the one the line names ($2). Signalith hands out one
# certificate each time: a file with more is refused, as someone in between
# could add their own after the real one.
fetch_ca() {
  q=''
  [ "$1" = current ] || q="?which=$1"
  # Not checked by a certificate: the fingerprint below is.
  code=$(curl -sSk --proto '=https' --max-time 30 -o "$tmp/ca-$1.pem" -w '%{http_code}' "$from/api/tls/ca.pem$q") ||
    fail "Could not reach Signalith at $from." "Check that this machine can reach it (curl $from), that the address is right, and that no firewall is in between, then run the line again."
  [ "$code" = 200 ] || fail "Signalith at $from did not hand out its certificate authority (it answered $code)." "Copy the line again from Add data > Network sensor."
  n=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$tmp/ca-$1.pem") || n=0
  [ "$n" = 1 ] || fail "Signalith at $from handed out $n certificates where it hands out one." "Copy the line again from Add data > Network sensor; if it still fails, someone may be in between this machine and Signalith."
  got=$(pem_sha256 "$tmp/ca-$1.pem")
  [ "$got" = "$2" ] || fail "This Signalith's certificate authority is not the one the line names." "Copy the line again from Add data > Network sensor; if it still fails, someone may be in between this machine and Signalith."
  # Only the certificate checked above is kept: nothing else in the file
  # (another kind of PEM block, say) is ever trusted.
  awk '/-----BEGIN CERTIFICATE-----/ { f = 1 } f { print } /-----END CERTIFICATE-----/ && f { exit }' "$tmp/ca-$1.pem" | tr -d '\r' >"$tmp/ca-$1.one"
  mv -f "$tmp/ca-$1.one" "$tmp/ca-$1.pem"
}
common_ca() {
  if [ -z "$ca_sha" ]; then
    curl -sS --proto '=https' --max-time 30 -o /dev/null "$from/" 2>"$tmp/err" ||
      fail "Could not reach Signalith at $from over HTTPS with this machine's trusted certificate authorities: $(tail -n 1 "$tmp/err")" "Check the address; if Signalith uses its own certificate authority, copy the line again from Add data: it then names it with --ca-sha256."
    ok "Signalith at $from (certificate checked by this machine's trusted authorities)"
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

# sig_get asks Signalith for $1 with the sensor's token, into file $2, and
# prints the HTTP status. The token is read from a file, never put on a
# command line.
sig_get() {
  if [ -n "$cafile" ]; then
    curl -sS --proto '=https' --max-time 30 --cacert "$cafile" -H "@$tmp/auth" -o "$2" -w '%{http_code}' "$from$1"
  else
    curl -sS --proto '=https' --max-time 30 -H "@$tmp/auth" -o "$2" -w '%{http_code}' "$from$1"
  fi
}
# sig_error prints the error message of Signalith's JSON answer in file $1.
sig_error() {
  sed -n 's/.*"error":"\([^"]*\)".*/\1/p' "$1" | head -n 1
}

layout=packages
common_config() {
  (umask 077 && printf 'Authorization: Bearer %s\n' "$token" >"$tmp/auth")
  [ "$docker" = no ] || layout=docker
  z=true s=true p=false
  [ "$zeek" = yes ] || z=false
  [ "$suricata" = yes ] || s=false
  [ "$protocols" = no ] || p=true
  code=$(sig_get "/api/sensor/config?server=$from&layout=$layout&zeek=$z&suricata=$s&protocols=$p" "$tmp/fluent-bit.conf") ||
    fail "Could not reach Signalith at $from to check the token." "Check that this machine can reach it, then run the line again."
  case "$code" in
    200) ;;
    401 | 403) fail "Signalith refused the token: $(sig_error "$tmp/fluent-bit.conf")" "Make the line again on Add data > Network sensor > Set up a new sensor." ;;
    503) fail "Signalith is still starting." "Run the line again in a minute." ;;
    *) fail "Signalith did not hand out the agent's configuration (it answered $code): $(sig_error "$tmp/fluent-bit.conf")" "Copy the line again from Add data > Network sensor." ;;
  esac
  ok "the token is a sensor token Signalith knows, and the agent's configuration came with it"
}

# --- Sensor: the capture port ------------------------------------------

# routed prints the ports the machine's default routes go through.
routed() {
  {
    ip -o route show default 2>/dev/null
    ip -o -6 route show default 2>/dev/null
  } | sed -n 's/.* dev \([^ ]*\).*/\1/p' | sort -u
}
rx_packets() {
  n=$(cat "$sysfs/class/net/$1/statistics/rx_packets" 2>/dev/null) || n=0
  case "$n" in '' | *[!0-9]*) n=0 ;; esac
  echo "$n"
}
link_of() {
  l=$(cat "$sysfs/class/net/$1/operstate" 2>/dev/null) || l=unknown
  echo "${l:-unknown}"
}
# sample counts the packets each port in $@ receives in $sample seconds,
# into variables seen_<n> (n = its place in the list).
sample_ports() {
  i=0
  for p in "$@"; do
    i=$((i + 1))
    eval "before_$i=\$(rx_packets \"\$p\")"
  done
  if [ "$sample" -gt 0 ]; then
    say "  counting packets on $* for $sample seconds..."
    sleep "$sample"
  fi
  i=0
  for p in "$@"; do
    i=$((i + 1))
    eval "seen_$i=\$((\$(rx_packets \"\$p\") - before_$i))"
  done
}

# has_address says whether port $1 has an IP address of its own (not
# only a link-local one).
has_address() {
  command -v ip >/dev/null 2>&1 && [ -n "$(ip -o addr show dev "$1" scope global 2>/dev/null)" ]
}

ports=''
sensor_pick_port() {
  default=$(routed | tr '\n' ' ')
  candidates=''
  busy=''
  ports=''
  for d in "$sysfs"/class/net/*; do
    [ -e "$d/device" ] || continue
    p=${d##*/}
    ports="$ports $p"
    case " $default " in
      *" $p "*) continue ;;
    esac
    # A port in a bridge or bond, or with an address, carries some other
    # network (storage, backups, a second uplink): the script never picks
    # it on its own, as preparing it for capture would cut that off.
    if [ -e "$d/master" ] || has_address "$p"; then
      busy="$busy $p"
    else
      candidates="$candidates $p"
    fi
  done
  if [ -n "$iface" ]; then
    [ -d "$sysfs/class/net/$iface" ] || fail "This machine has no network port named $iface." "Name one of its ports with --interface:$(for d in "$sysfs"/class/net/*; do printf ' %s' "${d##*/}"; done)"
    case " $default " in
      *" $iface "*) warn "$iface is the port this machine reaches the network with: listening on it, the sensor can cut you off (SSH may drop)." "Use a second port for capture, plugged into the mirror port or TAP." ;;
    esac
    if [ -e "$sysfs/class/net/$iface/master" ]; then
      warn "$iface is part of a bridge or bond, so it carries another network: preparing it for capture can cut that off." "Use a port of its own for capture, plugged into the mirror port or TAP."
    fi
    ok "capture port: $iface"
    return 0
  fi
  # shellcheck disable=SC2086 # a list of port names
  set -- $candidates
  case $# in
    0)
      if [ -n "$busy" ]; then
        fail "No port is free for capture: besides the one this machine reaches the network with (${default% }), each has an IP address or is part of a bridge or bond:$busy." "If one of them is plugged into the mirror port or TAP, name it with --interface (and remove its address: a capture port should be silent); otherwise add a network port for capture."
      fi
      fail "This machine has no network port for capture besides the one it reaches the network with (${default% })." "Add a second network port, plug it into the switch's mirror (SPAN) port or a TAP, and run the line again; or name a port with --interface."
      ;;
    1)
      iface=$1
      ok "capture port: $iface (the only port that does not reach the network)"
      return 0
      ;;
  esac
  sample_ports "$@"
  say "  Network ports that could be the capture port:"
  i=0
  for p in "$@"; do
    i=$((i + 1))
    eval "n=\$seen_$i"
    printf '    %s) %-16s link %-8s %s packets in %s seconds\n' "$i" "$p" "$(link_of "$p")" "$n" "$sample"
  done
  if [ -n "$dryrun" ] || ! { : </dev/tty; } 2>/dev/null; then
    fail "This machine has $# ports that could be the capture port." "Add --interface <name> to the line (the port plugged into the mirror port or TAP, for example --interface $1) and run it again."
  fi
  printf '  Which one is plugged into the mirror port or TAP? Number: ' >/dev/tty
  read -r pick </dev/tty || pick=''
  case "$pick" in
    '' | *[!0-9]*) fail "No port chosen." "Add --interface <name> to the line and run it again." ;;
  esac
  if [ "$pick" -lt 1 ] || [ "$pick" -gt $# ]; then fail "There is no port $pick." "Add --interface <name> to the line and run it again."; fi
  eval "iface=\${$pick}"
  ok "capture port: $iface"
}

sensor_port_checks() {
  link=$(link_of "$iface")
  if [ "$link" = up ]; then
    ok "$iface has a link"
  else
    warn "$iface has no link ($link)." "Plug the cable from the switch's mirror (SPAN) port or TAP into $iface."
  fi
  seen_1=0
  sample_ports "$iface"
  if [ "$seen_1" -gt 0 ]; then
    ok "$iface receives traffic ($seen_1 packets in $sample seconds)"
  else
    warn "$iface received no packets in $sample seconds." "Check that the switch copies traffic to the mirror port $iface is plugged into."
  fi
  if has_address "$iface"; then
    warn "$iface has an IP address: a capture port should be silent, so nobody can reach the sensor through it." "Remove the address from $iface in the network settings: with netplan, give $iface no addresses and dhcp4: false in /etc/netplan/*.yaml, then sudo netplan apply; with NetworkManager, sudo nmcli device set $iface managed no. The sensor never changes the network settings itself."
  fi
  # shellcheck disable=SC2086 # a list of port names
  set -- $ports
  if [ $# -lt 2 ]; then
    warn "This machine has only one network port: a sensor needs one to reach Signalith and one for capture." "Add a second network port for capture."
  fi
}

# --- Common: repositories and packages ---------------------------------

# key_add downloads a repository's signing key from $2, checks its
# fingerprint is $3, and installs it as $4 (an apt keyring .gpg, or an rpm
# key .asc). $1 names the publisher in messages.
key_add() {
  if [ -z "$3" ]; then
    # sensor_sources said so already, before anything was installed.
    if [ -n "$dryrun" ]; then return 0; fi
    fail "This version of the script has no pinned fingerprint for $1's signing key, so it cannot add that repository safely." "Run the line with --docker."
  fi
  if [ -n "$dryrun" ]; then
    printf '    would download %s and check its fingerprint is %s\n' "$2" "$3"
    return 0
  fi
  curl -fsSL --proto '=https' --max-time 60 -o "$tmp/key" "$2" ||
    fail "Could not download $1's signing key from $2." "Check that this machine can reach it, then run the line again."
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
apt_release=''
installed=''
# pkg_install installs the packages in $@ that are missing, and records
# them, so --uninstall removes only what the script installed. Tools the
# script itself needs (pkg_tools) are not recorded: they stay.
pkg_install() {
  pkg_add package "$@"
}
pkg_tools() {
  pkg_add tool "$@"
}
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
  elif [ -n "$apt_release" ]; then
    set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -t "$apt_release" "$@"
  else
    set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
  fi
  quiet "$@" || fail "Installing$missing failed (see above)." "Run the line again; if it fails again, check that this machine reaches its package repositories."
  for p in $missing; do
    if [ "$kind" = package ] || [ -n "$dryrun" ]; then manifest_add "$kind $p"; fi
  done
  if [ "$kind" = package ]; then installed="$installed$missing"; fi
  ok "installed$missing"
}

# repo_list writes an apt source $1 holding line $2.
repo_list() {
  printf '# Written by the Signalith sensor install script.\n%s\n' "$2" | put "$1" 0644 root:root repo
}

common_repos() {
  if [ "$pkg" = apt ]; then
    quiet env DEBIAN_FRONTEND=noninteractive apt-get update || fail "apt-get update failed (see above)."
    # Not curl: the script runs with the machine's own (on Rocky and Alma
    # often curl-minimal, which a curl package would conflict with).
    pkg_tools ca-certificates gnupg ethtool iproute2
    run mkdir -p /etc/apt/keyrings
    if [ "$zeek" = yes ]; then
      key_add Zeek "https://download.opensuse.org/repositories/security:zeek/$zeek_obs/Release.key" "$KEY_FPR_ZEEK_OBS" /etc/apt/keyrings/signalith-zeek.gpg
      repo_list /etc/apt/sources.list.d/signalith-zeek.list "deb [signed-by=/etc/apt/keyrings/signalith-zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/$zeek_obs/ /"
    fi
    if [ "$suricata" = yes ]; then
      if [ "$os_id" = ubuntu ]; then
        key_add "OISF (Suricata)" "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$KEY_FPR_OISF_PPA" "$KEY_FPR_OISF_PPA" /etc/apt/keyrings/signalith-oisf.gpg
        repo_list /etc/apt/sources.list.d/signalith-oisf-suricata.list "deb [signed-by=/etc/apt/keyrings/signalith-oisf.gpg] https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu $codename main"
      elif [ -n "$backports" ] && ! grep -rqs "^[^#]*$backports" "$R/etc/apt/sources.list" "$R/etc/apt/sources.list.d"; then
        # Debian's own backports, signed by Debian's keys.
        repo_list /etc/apt/sources.list.d/signalith-debian-backports.list "deb http://deb.debian.org/debian $backports main"
      fi
    fi
    key_add "Fluent Bit" https://packages.fluentbit.io/fluentbit.key "$KEY_FPR_FLUENTBIT" /etc/apt/keyrings/signalith-fluentbit.gpg
    repo_list /etc/apt/sources.list.d/signalith-fluent-bit.list "deb [signed-by=/etc/apt/keyrings/signalith-fluentbit.gpg] https://packages.fluentbit.io/$fb_repo $codename main"
    quiet env DEBIAN_FRONTEND=noninteractive apt-get update || fail "apt-get update failed with the new repositories (see above)." "Check that this machine reaches download.opensuse.org, ppa.launchpadcontent.net and packages.fluentbit.io."
  else
    pkg_tools ca-certificates gnupg2 ethtool iproute
    if [ "$os_id" = rhel ]; then
      pkg_has epel-release || fail "Suricata on RHEL needs EPEL, which is not enabled." "sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(uname -m)-rpms && sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"
    else
      # EPEL from the system's own extras repository, signed by it.
      pkg_tools epel-release dnf-plugins-core
      quiet dnf config-manager --set-enabled crb || fail "Could not enable the CRB repository (see above)."
    fi
    if [ "$suricata" = yes ]; then
      key_add "OISF (Suricata COPR)" "https://download.copr.fedorainfracloud.org/results/@oisf/suricata-8.0/pubkey.gpg" "$KEY_FPR_OISF_COPR" /etc/pki/rpm-gpg/signalith-oisf-copr.asc
      put /etc/yum.repos.d/signalith-oisf-suricata.repo 0644 root:root repo <<'REPO'
# Written by the Signalith sensor install script.
[signalith-oisf-suricata]
name=Suricata 8.0 (OISF COPR)
baseurl=https://download.copr.fedorainfracloud.org/results/@oisf/suricata-8.0/epel-9-$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/signalith-oisf-copr.asc
enabled=1
REPO
    fi
    key_add "Fluent Bit" https://packages.fluentbit.io/fluentbit.key "$KEY_FPR_FLUENTBIT" /etc/pki/rpm-gpg/signalith-fluentbit.asc
    put /etc/yum.repos.d/signalith-fluent-bit.repo 0644 root:root repo <<'REPO'
# Written by the Signalith sensor install script.
[signalith-fluent-bit]
name=Fluent Bit
baseurl=https://packages.fluentbit.io/centos/9/
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/signalith-fluentbit.asc
enabled=1
REPO
  fi
}

# mask_vendor stops and masks a package's own unit, so there is never a
# second copy capturing or sending; --uninstall unmasks it.
mask_vendor() {
  if [ -n "$dryrun" ]; then
    manifest_has "mask $1" || run systemctl mask --now "$1"
    manifest_add "mask $1"
    return 0
  fi
  if [ "$(systemctl is-enabled "$1" 2>/dev/null)" != masked ]; then
    # --uninstall starts it again.
    if systemctl is-active --quiet "$1"; then manifest_add "was running $1"; fi
    systemctl mask --now "$1" >/dev/null 2>&1 || true
    manifest_add "mask $1"
  fi
}

sensor_packages() {
  common_repos
  # The packages' own units are masked before they are installed, so they
  # never start.
  if [ "$suricata" = yes ]; then mask_vendor suricata.service; fi
  mask_vendor fluent-bit.service
  # Packages that make their own account (Suricata's does) leave it behind
  # when removed: one they make on this run is recorded, so --uninstall
  # removes it too.
  had_accounts=''
  for a in zeek suricata; do
    if getent passwd "$a" >/dev/null 2>&1; then had_accounts="$had_accounts $a"; fi
    if getent group "$a" >/dev/null 2>&1; then had_accounts="$had_accounts group:$a"; fi
  done
  if [ "$zeek" = yes ]; then pkg_install "$ZEEK_PACKAGE"; fi
  if [ "$suricata" = yes ]; then
    if [ "$os_id" = debian ]; then
      apt_release=$backports
      pkg_install suricata suricata-update
      apt_release=''
    else
      pkg_install suricata
    fi
  fi
  pkg_install fluent-bit
  for a in zeek suricata; do
    case " $had_accounts " in *" group:$a "*) ;; *)
      if getent group "$a" >/dev/null 2>&1 && ! manifest_has "group $a"; then manifest_add "group $a"; fi ;;
    esac
    case " $had_accounts " in *" $a "*) ;; *)
      if getent passwd "$a" >/dev/null 2>&1 && ! manifest_has "account $a"; then manifest_add "account $a"; fi ;;
    esac
  done
  # Run again, the programs that were already here get their publishers'
  # newest packages (Zeek within its long-term support line).
  if [ "$zeek" = yes ]; then pkg_upgrade zeek "$ZEEK_PACKAGE"; fi
  if [ "$suricata" = yes ]; then
    if [ "$os_id" = debian ]; then
      apt_release=$backports
      pkg_upgrade suricata suricata suricata-update
      apt_release=''
    else
      pkg_upgrade suricata suricata
    fi
  fi
  pkg_upgrade agent fluent-bit
}

# pkg_version prints the version of package $1 that is installed.
pkg_version() {
  if [ "$pkg" = apt ]; then
    dpkg-query -W -f='${Version}' "$1" 2>/dev/null
  else
    rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null
  fi
}
upgraded=''
# pkg_upgrade upgrades the packages in $@ that were installed before this
# run, and notes group $1 as changed (its service restarts) when one
# was. A failed upgrade keeps the versions there.
pkg_upgrade() {
  group=$1
  shift
  todo=''
  for p in "$@"; do
    case " $installed " in *" $p "*) continue ;; esac
    if pkg_has "$p"; then todo="$todo $p"; fi
  done
  [ -n "$todo" ] || return 0
  before=''
  if [ -z "$dryrun" ]; then
    for p in $todo; do before="$before $(pkg_version "$p")"; done
  fi
  if [ "$pkg" = dnf ]; then
    # shellcheck disable=SC2086 # a list of package names
    set -- dnf upgrade -y $todo
  elif [ -n "$apt_release" ]; then
    # shellcheck disable=SC2086 # a list of package names
    set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade --no-install-recommends -t "$apt_release" $todo
  else
    # shellcheck disable=SC2086 # a list of package names
    set -- env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade --no-install-recommends $todo
  fi
  if ! quiet "$@"; then
    warn "Upgrading$todo failed (see above); the versions installed keep running." "Run the line again later; if it fails again, check that this machine reaches its package repositories."
    return 0
  fi
  [ -z "$dryrun" ] || return 0
  after=''
  for p in $todo; do after="$after $(pkg_version "$p")"; done
  if [ "$before" != "$after" ]; then
    upgraded="$upgraded$todo"
    case " $changed " in *" $group "*) ;; *) changed="$changed $group" ;; esac
    ok "upgraded$todo"
  fi
}

# --- Common: accounts --------------------------------------------------

nologin=/bin/false
for s in /usr/sbin/nologin /sbin/nologin; do
  if [ -x "$s" ]; then
    nologin=$s
    break
  fi
done
# account makes system account $1 (with group $1 and home $2) when it is
# missing, and records it.
account() {
  if ! getent group "$1" >/dev/null 2>&1 && ! manifest_has "group $1"; then
    run groupadd --system "$1"
    manifest_add "group $1"
  fi
  if ! getent passwd "$1" >/dev/null 2>&1 && ! manifest_has "account $1"; then
    run useradd --system --gid "$1" --no-create-home --home-dir "$2" --shell "$nologin" --comment "$3" "$1"
    manifest_add "account $1"
  fi
}

sensor_accounts() {
  # Both groups exist even when one program is left out: the agent's unit
  # names them. In containers, the images have their own.
  if [ "$layout" = packages ]; then
    account zeek /opt/zeek "Zeek (Signalith sensor)"
    account suricata /var/lib/suricata "Suricata (Signalith sensor)"
  fi
  account signalith-sensor /var/lib/signalith-sensor "Signalith sensor agent"
  folder /etc/signalith-sensor 0755 root:root
  folder /usr/lib/signalith-sensor 0755 root:root
  folder /var/lib/signalith-sensor 0755 root:root
  folder /var/lib/signalith-sensor/agent 0700 signalith-sensor:signalith-sensor
  folder /var/log/signalith-sensor 0750 root:signalith-sensor
  # The rule tuning: yours from /etc with Signalith's, which root's timers
  # write and Suricata reads.
  [ "$suricata" = no ] || folder /var/lib/signalith-sensor/tuning 0755 root:root
  if [ "$layout" = packages ]; then
    if [ "$zeek" = yes ]; then
      folder /opt/zeek/logs 0750 zeek:zeek
      folder /opt/zeek/spool 0750 zeek:zeek
    fi
    if [ "$suricata" = yes ]; then
      # The agent reaches Suricata's folder for the sensor through the
      # package's log folder: it may pass (not list) it.
      mkdir -p "$R/var/log/suricata"
      chmod o+x "$R/var/log/suricata"
      folder /var/log/suricata/signalith 0750 suricata:suricata
      folder /var/lib/suricata 0750 suricata:suricata
      # The rules, which root's daily update writes, are root's and only
      # readable by Suricata: never in a folder Suricata can change.
      folder /var/lib/signalith-sensor/suricata 0755 root:root
      folder /var/lib/signalith-sensor/suricata/rules 0755 root:root
    fi
  fi
  ok "accounts and folders"
}

# --- Sensor: configuration ---------------------------------------------

# zeek_nets prints --networks the way Zeek writes networks: IPv6 ones in
# brackets, separated by $1.
zeek_nets() {
  old_ifs=$IFS
  IFS=,
  sep=''
  for net in $networks; do
    case "$net" in
      *:*) printf '%s[%s]/%s' "$sep" "${net%/*}" "${net#*/}" ;;
      *) printf '%s%s' "$sep" "$net" ;;
    esac
    sep=$1
  done
  IFS=$old_ifs
}

zeek_workers_default() {
  if [ -n "$zeek_workers" ]; then
    echo "$zeek_workers"
  elif [ "$cores" -lt 8 ]; then
    # One process: below 8 cores a cluster's own processes cost more than
    # they bring.
    echo 0
  else
    w=$((cores / 4))
    [ "$w" -le 8 ] || w=8
    echo "$w"
  fi
}

sensor_zeek_config() {
  workers=$(zeek_workers_default)
  if [ "$workers" -eq 0 ]; then
    put /opt/zeek/etc/node.cfg 0644 root:root zeek orig <<EOF
# Written by the Signalith sensor install script: one Zeek process
# reading the capture port. Run the script again instead of editing this
# file: it is replaced (with 8 cores or more, a local cluster of workers).
[zeek]
type=standalone
host=localhost
interface=af_packet::$iface
EOF
    info "Zeek: one process (fewer than 8 cores)"
  else
    put /opt/zeek/etc/node.cfg 0644 root:root zeek orig <<EOF
# Written by the Signalith sensor install script: a cluster on this
# machine, $workers workers sharing the capture port (AF_PACKET fanout).
# Run the script again instead of editing this file: it is replaced.
[logger-1]
type=logger
host=localhost

[manager]
type=manager
host=localhost

[proxy-1]
type=proxy
host=localhost

[worker-1]
type=worker
host=localhost
interface=$iface
lb_method=af_packet
lb_procs=$workers
af_packet_fanout_id=23
af_packet_fanout_mode=AF_Packet::FANOUT_HASH
EOF
    info "Zeek: $workers workers"
  fi
  {
    printf '# Written by the Signalith sensor install script: your own networks\n'
    printf '# (--networks), which Zeek marks as local.\n'
    old_ifs=$IFS
    IFS=,
    for net in $networks; do
      printf '%s\tYour network\n' "$net"
    done
    IFS=$old_ifs
  } | put /opt/zeek/etc/networks.cfg 0644 root:root zeek orig
  put /opt/zeek/etc/zeekctl.cfg 0644 root:root zeek orig <<'EOF'
# Written by the Signalith sensor install script. Run the script again
# instead of editing this file: it is replaced. Signalith's own settings
# load from share/zeek/site/signalith.zeek, after local.zeek.
MailTo = root@localhost
SendMail =
MailConnectionSummary = 0
MailHostUpDown = 0
MinDiskSpace = 5
LogRotationInterval = 3600
LogExpireInterval = 2 day
StatsLogEnable = 1
StatsLogExpireInterval = 2
StatusCmdShowAll = 0
CrashExpireInterval = 2
SitePolicyScripts = local.zeek signalith.zeek
MetricsAddress = 127.0.0.1
LogDir = /opt/zeek/logs
SpoolDir = /opt/zeek/spool
CfgDir = /opt/zeek/etc
EOF
  zeek_script | put /opt/zeek/share/zeek/site/signalith.zeek 0644 root:root zeek
}

# zeek_script prints signalith.zeek: JSON logs with the Community ID, file
# hashes, and Zeek's own capture-loss and stats logs.
zeek_script() {
  cat <<'EOF'
# Written by the Signalith sensor install script: what Signalith needs from
# Zeek. Run the script again instead of editing this file: it is replaced;
# your own settings go in local.zeek.
@load policy/tuning/json-logs
@load policy/protocols/conn/community-id-logging
@load frameworks/files/hash-all-files
@load misc/capture-loss
@load misc/stats
# Network cards that compute checksums themselves (offload) hand captured
# packets over with checksums still unset; Zeek would drop those and log
# no DNS, HTTP or TLS for them. Suricata decides this for itself.
redef ignore_checksums = T;
EOF
  if [ "$layout" = docker ]; then
    cat <<EOF
redef Site::local_nets += { $(zeek_nets ', ') };
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_dir = "/logs/zeek/archive";
EOF
  fi
}

threads_default() {
  if [ -n "$suricata_threads" ]; then
    echo "$suricata_threads"
  else
    t=$((cores / 2))
    [ "$t" -ge 1 ] || t=1
    echo "$t"
  fi
}

# suricata_yaml prints signalith-sensor.yaml: Suricata's settings for the
# sensor, over the package's suricata.yaml (which it includes, unchanged).
# Keys at the top level replace the package's whole setting of the same
# name; vars.address-groups.HOME_NET replaces HOME_NET alone.
suricata_yaml() {
  logdir=/var/log/suricata/signalith/
  socket=/run/suricata/suricata-command.socket
  rulesdir=/var/lib/signalith-sensor/suricata/rules
  tuningdir=/var/lib/signalith-sensor/tuning
  if [ "$layout" = docker ]; then
    logdir=/var/log/suricata/
    socket=/var/run/suricata/suricata-command.socket
    rulesdir=/var/lib/suricata/rules
    tuningdir=/etc/suricata/signalith-tuning
  fi
  cat <<EOF
%YAML 1.1
---
include: suricata.yaml
# Written by the Signalith sensor install script: settings that replace the
# ones of the same name in suricata.yaml. Run the script again instead of
# editing this file: it is replaced. Tune the rules on Signalith (Settings >
# Network sensors), or in this machine's disable.conf and threshold.config.
vars.address-groups.HOME_NET: "[$networks]"
sensor-name: $name
EOF
  # The copy for suricata-update's test (any argument) has no run-as.
  if [ "$layout" = packages ] && [ $# -eq 0 ]; then
    # In a container, --user does this.
    cat <<'EOF'
run-as:
  user: suricata
  group: suricata
EOF
  fi
  cat <<EOF
default-log-dir: $logdir
default-rule-path: $rulesdir
rule-files:
  - suricata.rules
threshold-file: $tuningdir/threshold.config
unix-command:
  enabled: yes
  filename: $socket
stats:
  enabled: yes
  interval: 60
af-packet:
  - interface: $iface
    threads: $(threads_default)
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    tpacket-v3: yes
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types:
        - alert:
            payload: no
            payload-printable: no
            packet: no
            http-body: no
            http-body-printable: no
            metadata: yes
        - anomaly
        - files
        - stats:
            totals: yes
            threads: no
            deltas: no
EOF
  if [ "$protocols" = yes ]; then
    cat <<'EOF'
        - flow
        - dns
        - http
        - tls
EOF
  fi
}

sensor_suricata_config() {
  dir=/etc/suricata
  [ "$layout" = packages ] || dir=/etc/signalith-sensor/docker/suricata
  suricata_yaml | put "$dir/signalith-sensor.yaml" 0644 root:root suricata
  if [ "$layout" = packages ]; then
    # suricata-update tests new rules as root, in a folder only root can
    # write: the copy it reads has no run-as, which would drop to the
    # suricata user first.
    suricata_yaml test | put "$dir/signalith-sensor-test.yaml" 0644 root:root suricata
  fi
  for f in disable.conf threshold.config; do
    if [ ! -f "$R$dir/$f" ]; then
      printf '# Your tuning on this machine, added to the one set on Signalith (see docs/network-sensor.md, "Rule tuning").\n' |
        put "$dir/$f" 0644 root:root suricata
    fi
  done
  if [ -n "$local_rules" ]; then
    put_file /etc/signalith-sensor/local.rules 0644 root:root "$local_rules" rules
  elif [ ! -f "$R/etc/signalith-sensor/local.rules" ]; then
    : | put /etc/signalith-sensor/local.rules 0644 root:root rules
  fi
  if [ "$layout" = docker ]; then
    put_file "$dir/local.rules" 0644 root:root "$R/etc/signalith-sensor/local.rules" rules
    return 0
  fi
  put /etc/logrotate.d/signalith-suricata 0644 root:root suricata <<'EOF'
# Written by the Signalith sensor install script: Suricata's logs for the
# sensor, kept two days; the agent sends them as they are written.
/var/log/suricata/signalith/*.json /var/log/suricata/signalith/*.log {
    daily
    rotate 2
    missingok
    notifempty
    compress
    delaycompress
    create 0640 suricata suricata
    su suricata suricata
    sharedscripts
    postrotate
        /bin/systemctl kill -s HUP signalith-suricata.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

sensor_conf() {
  put /etc/signalith-sensor/sensor.conf 0644 root:root conf <<EOF
# Written by the Signalith sensor install script: the options it used,
# which a re-run, the status line and --uninstall read.
ROLE='sensor'
LAYOUT='$layout'
FROM='$from'
NAME='$name'
INTERFACE='$iface'
NETWORKS='$networks'
ZEEK='$zeek'
SURICATA='$suricata'
PROTOCOLS='$protocols'
SENSOR_VERSION='$version'
EOF
}

common_agent_config() {
  if [ -n "$cafile" ]; then
    put_file /etc/signalith-sensor/ca.pem 0644 root:root "$cafile" agent
  elif [ "$layout" = docker ]; then
    # Mounted into the agent's container either way.
    printf '# Signalith uses a certificate from a public authority: nothing pinned.\n' |
      put /etc/signalith-sensor/ca.pem 0644 root:root agent
  fi
  printf '# Written by the Signalith sensor install script. The sensor'"'"'s agent token:\n# anyone with it can send data as this sensor. Only root reads this file.\nSIGNALITH_TOKEN=%s\nHOSTNAME=%s\n' "$token" "$name" |
    put /etc/signalith-sensor/token.env 0600 root:root agent
  if [ "$layout" = docker ]; then
    put_file /etc/signalith-sensor/docker/fluent-bit.conf 0644 root:root "$tmp/fluent-bit.conf" agent
  else
    put_file /etc/signalith-sensor/fluent-bit.conf 0640 root:signalith-sensor "$tmp/fluent-bit.conf" agent
  fi
}

# --- Sensor: units and helpers -----------------------------------------

sensor_unit() {
  case "$1" in
    signalith-sensor-capture.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Prepares the capture port @IFACE@ before Zeek and Suricata start: up,
# listening to every packet (promiscuous), never answering (no ARP, no
# IPv6), and without the network card offloads that merge packets. When it
# stops (and on --uninstall), the port is put back as it was.
[Unit]
Description=Signalith sensor: prepare the capture port @IFACE@
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
BindsTo=@IFACE_UNIT@
After=@IFACE_UNIT@
Before=signalith-zeek.service signalith-suricata.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/signalith-sensor/capture-up.sh @IFACE@
ExecStop=/usr/lib/signalith-sensor/capture-up.sh --undo @IFACE@
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
# What the port was like before.
ReadWritePaths=/var/lib/signalith-sensor
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
      ;;
    signalith-zeek.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Zeek, run by zeekctl as the zeek user with only the right packet capture
# needs (CAP_NET_RAW; signalith-sensor-capture.service already made the
# port promiscuous, so Zeek cannot change the network settings). The zeek
# package's files stay read-only; Zeek writes only its logs and its spool
# folder.
[Unit]
Description=Signalith sensor: Zeek
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
Wants=network-online.target
After=network-online.target signalith-sensor-capture.service
Requires=signalith-sensor-capture.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=zeek
Group=zeek
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecReload=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
TimeoutStartSec=300
# Logs readable by the zeek group, which the agent is in.
UMask=0027
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/zeek/logs /opt/zeek/spool
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT
      ;;
    signalith-zeekctl-cron.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# zeekctl's housekeeping: restarts a Zeek process that stopped, and
# deletes logs older than two days (LogExpireInterval in zeekctl.cfg).
[Unit]
Description=Signalith sensor: Zeek housekeeping
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
After=signalith-zeek.service
Requisite=signalith-zeek.service

[Service]
Type=oneshot
User=zeek
Group=zeek
ExecStart=/opt/zeek/bin/zeekctl cron
# A Zeek process it restarts must keep running after this job ends.
KillMode=process
UMask=0027
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/zeek/logs /opt/zeek/spool
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK
UNIT
      ;;
    signalith-zeekctl-cron.timer)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
[Unit]
Description=Signalith sensor: Zeek housekeeping every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
      ;;
    signalith-suricata.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Suricata starts as root to open the capture port, then runs as the
# suricata user (run-as in /etc/suricata/signalith-sensor.yaml). Until then
# it needs CAP_DAC_OVERRIDE and CAP_CHOWN (it opens its log, in a folder
# that is the suricata user's, and hands it over) and CAP_SETPCAP (to drop
# the rest); it keeps only the capture rights after. It writes only its
# logs and /var/lib/suricata; the rules, in
# /var/lib/signalith-sensor/suricata/rules, are root's and only read.
[Unit]
Description=Signalith sensor: Suricata
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
Wants=network-online.target
After=network-online.target signalith-sensor-capture.service
Requires=signalith-sensor-capture.service

[Service]
Type=simple
ExecStartPre=+/bin/chown suricata:suricata /run/suricata
ExecStart=suricata -c /etc/suricata/signalith-sensor.yaml --af-packet --pidfile /run/suricata/suricata.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=10
RuntimeDirectory=suricata
RuntimeDirectoryMode=0750
# Logs readable by the suricata group, which the agent is in.
UMask=0027
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_NICE CAP_IPC_LOCK CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/suricata /var/lib/suricata
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT
      ;;
    signalith-suricata-update.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Downloads the Emerging Threats Open rules and the rule tuning set on
# Signalith, has Suricata test them, and only then loads them; a failed
# test keeps the rules in use. It runs as root and writes only root's
# folders (the rules are in /var/lib/signalith-sensor/suricata), never one
# the suricata user owns.
[Unit]
Description=Signalith sensor: update the Suricata rules
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/lib/signalith-sensor/rules-update.sh
# The sensor's token, to fetch the tuning (only root reads the file).
EnvironmentFile=/etc/signalith-sensor/token.env
# With --docker, the docker command keeps its settings here.
Environment=DOCKER_CONFIG=/var/lib/signalith-sensor/docker
NoNewPrivileges=yes
ProtectSystem=strict
# The rules are readable by all: they are the public Emerging Threats Open
# rules, and the suricata user reads them.
UMask=0022
ReadWritePaths=/var/lib/signalith-sensor -/run/suricata -/run/docker.sock
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
UNIT
      ;;
    signalith-suricata-update.timer)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
[Unit]
Description=Signalith sensor: update the Suricata rules every day

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
      ;;
    signalith-fluent-bit.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# The agent: reads Zeek's and Suricata's logs (as a member of their
# groups) and the status line, and sends them to Signalith over HTTPS. Its
# token is in token.env, which only root reads; systemd hands it over.
[Unit]
Description=Signalith sensor: Fluent Bit agent
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=signalith-sensor
Group=signalith-sensor
SupplementaryGroups=zeek suricata
EnvironmentFile=/etc/signalith-sensor/token.env
ExecStart=/opt/fluent-bit/bin/fluent-bit -c /etc/signalith-sensor/fluent-bit.conf
Restart=always
RestartSec=5
UMask=0077
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/signalith-sensor/agent
ProtectHome=yes
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
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
      ;;
    signalith-sensor-status.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Writes the sensor's status line (versions, rules, capture port, packet
# drops, disk) for the agent to send.
[Unit]
Description=Signalith sensor: status line
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md

[Service]
Type=oneshot
ExecStart=/usr/lib/signalith-sensor/status.sh
# With --docker, the docker command keeps its settings here.
Environment=DOCKER_CONFIG=/var/lib/signalith-sensor/docker
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/signalith-sensor /var/lib/signalith-sensor -/run/docker.sock
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
UNIT
      ;;
    signalith-sensor-status.timer)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
[Unit]
Description=Signalith sensor: status line every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
      ;;
    signalith-sensor-tuning.service)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Fetches the Suricata rule tuning set on Signalith (Settings > Network
# sensors) with the sensor's token and, only when it changed, has
# suricata-update rebuild and test the rules with it; a failed test keeps
# the tuning in use. It runs as root and writes only root's folders.
[Unit]
Description=Signalith sensor: fetch the Suricata rule tuning
Documentation=https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/lib/signalith-sensor/rules-update.sh tuning
# The sensor's token, to fetch the tuning (only root reads the file).
EnvironmentFile=/etc/signalith-sensor/token.env
# With --docker, the docker command keeps its settings here.
Environment=DOCKER_CONFIG=/var/lib/signalith-sensor/docker
NoNewPrivileges=yes
ProtectSystem=strict
# The rules and the tuning are readable by all: the suricata user reads
# them.
UMask=0022
ReadWritePaths=/var/lib/signalith-sensor -/run/suricata -/run/docker.sock
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
UNIT
      ;;
    signalith-sensor-tuning.timer)
      cat <<'UNIT'
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
[Unit]
Description=Signalith sensor: fetch the Suricata rule tuning every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
RandomizedDelaySec=2min

[Install]
WantedBy=timers.target
UNIT
      ;;
  esac
}

sensor_helper() {
  case "$1" in
    capture-up.sh)
      cat <<'HELPER'
#!/bin/sh
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Prepares the capture port named on the command line, for
# signalith-sensor-capture.service: up and listening to every packet
# (promiscuous), never answering (no ARP, no IPv6), and without the
# network card offloads that merge packets before Zeek and Suricata see
# them. Offloads a card does not have are skipped.
#
# What the port was like before is kept in
# /var/lib/signalith-sensor/capture-<port>.before; with --undo (when the
# service stops, and so on --uninstall) the port is put back that way.
#
# SIGNALITH_SENSOR_ROOT and SIGNALITH_SENSOR_SYSFS are for tests only: a
# folder standing for / and one standing for /sys.
set -u
R=${SIGNALITH_SENSOR_ROOT:-}
sysfs=${SIGNALITH_SENSOR_SYSFS:-/sys}
undo=no
if [ "${1:-}" = --undo ]; then
  undo=yes
  shift
fi
iface=${1:-}
case "$iface" in
  '' | *[!A-Za-z0-9_.:-]*)
    echo "capture-up: no capture port named (or a name with odd characters)" >&2
    exit 1
    ;;
esac
saved=$R/var/lib/signalith-sensor/capture-$iface.before
ipv6=$R/proc/sys/net/ipv6/conf/$iface/disable_ipv6
features='gro lro gso tso rx-gro-hw'
have_ethtool=no
if command -v ethtool >/dev/null 2>&1; then have_ethtool=yes; fi

# offload prints whether offload $1 is on for the port (on or off), by
# the name ethtool -k shows it under.
offload() {
  case "$1" in
    gro) long=generic-receive-offload ;;
    lro) long=large-receive-offload ;;
    gso) long=generic-segmentation-offload ;;
    tso) long=tcp-segmentation-offload ;;
    *) long=$1 ;;
  esac
  ethtool -k "$iface" 2>/dev/null | sed -n "s/^$long: \\([a-z]*\\).*/\\1/p" | head -n 1
}

if [ "$undo" = yes ]; then
  [ -r "$saved" ] || exit 0
  promisc=off arp=on v6=0 on=''
  read -r promisc arp v6 on <"$saved" || true
  case "$promisc" in on | off) ;; *) promisc=off ;; esac
  case "$arp" in on | off) ;; *) arp=on ;; esac
  case "$v6" in 0 | 1) ;; *) v6=0 ;; esac
  ip link set dev "$iface" promisc "$promisc" arp "$arp" || true
  if [ -w "$ipv6" ]; then echo "$v6" >"$ipv6"; fi
  if [ "$have_ethtool" = yes ]; then
    for feature in $(printf '%s' "$on" | tr ',' ' '); do
      case " $features " in
        *" $feature "*) ethtool -K "$iface" "$feature" on >/dev/null 2>&1 || true ;;
      esac
    done
  fi
  rm -f "$saved"
  exit 0
fi

# Once, before the first change: a restart keeps what the port was like
# before the sensor.
if [ ! -e "$saved" ]; then
  flags=$(cat "$sysfs/class/net/$iface/flags" 2>/dev/null) || flags=0
  case "$flags" in 0x[0-9a-fA-F]*) ;; *) flags=0 ;; esac
  promisc=off arp=on
  if [ $((flags & 256)) -ne 0 ]; then promisc=on; fi
  if [ $((flags & 128)) -ne 0 ]; then arp=off; fi
  v6=$(cat "$ipv6" 2>/dev/null) || v6=0
  case "$v6" in 0 | 1) ;; *) v6=0 ;; esac
  on=''
  if [ "$have_ethtool" = yes ]; then
    for feature in $features; do
      if [ "$(offload "$feature")" = on ]; then on="$on${on:+,}$feature"; fi
    done
  fi
  printf '%s %s %s %s\n' "$promisc" "$arp" "$v6" "$on" >"$saved.new" && mv -f "$saved.new" "$saved"
fi

ip link set dev "$iface" up promisc on arp off
if [ -w "$ipv6" ]; then
  echo 1 >"$ipv6"
fi
if [ "$have_ethtool" = yes ]; then
  for feature in $features; do
    ethtool -K "$iface" "$feature" off >/dev/null 2>&1 || true
  done
fi
exit 0
HELPER
      ;;
    status.sh)
      cat <<'HELPER'
#!/bin/sh
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# The sensor's status line, every 5 minutes (signalith-sensor-status.timer):
# appends one JSON line to /var/log/signalith-sensor/status.json, which the
# agent sends to Signalith (tag sensor.status) for the Endpoints and Health
# pages. Values read from commands and files are cut down to safe
# characters, so the line is always valid JSON.
#
# SIGNALITH_SENSOR_ROOT and SIGNALITH_SENSOR_SYSFS are for tests only: a
# folder standing for / and one standing for /sys.
set -u
R=${SIGNALITH_SENSOR_ROOT:-}
sysfs=${SIGNALITH_SENSOR_SYSFS:-/sys}
conf=$R/etc/signalith-sensor/sensor.conf
out=$R/var/log/signalith-sensor/status.json
counters=$R/var/lib/signalith-sensor/last-counters
umask 027

get() {
  sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$2" 2>/dev/null | head -n 1
}
safe() {
  printf '%s' "$1" | tr -cd 'A-Za-z0-9._:+-' | cut -c 1-64
}
num() {
  case "$1" in '' | *[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
}
have() {
  command -v "$1" >/dev/null 2>&1
}
warnings=''
warn() {
  warnings="$warnings${warnings:+,}\"$1\""
}

layout=$(safe "$(get LAYOUT "$conf")")
name=$(safe "$(get NAME "$conf")")
iface=$(safe "$(get INTERFACE "$conf")")
version=$(safe "$(get SENSOR_VERSION "$conf")")
zeek=$(get ZEEK "$conf")
suricata=$(get SURICATA "$conf")

dc() {
  docker compose -f /etc/signalith-sensor/docker/docker-compose.yml "$@"
}

# Versions and whether Zeek and Suricata run.
zv='' sv='' fv='' zr=false sr=false eve=''
if [ "$layout" = docker ]; then
  img() {
    safe "$(sed -n "s/^$1=[^:]*:\\([^@]*\\).*/\\1/p" "$R/etc/signalith-sensor/docker/.env" 2>/dev/null)"
  }
  zv=$(img SIGNALITH_IMAGE_ZEEK)
  sv=$(img SIGNALITH_IMAGE_SURICATA)
  fv=$(img SIGNALITH_IMAGE_FLUENTBIT)
  running=''
  if have docker; then
    running=$(dc ps --status running --services 2>/dev/null) || true
    # Housekeeping the host does for the containers: Zeek's rotated logs
    # go after two days, and Suricata's log is rolled at 512 MB.
    if [ "$zeek" = yes ]; then
      dc exec -T zeek find /logs/zeek/archive -type f -mmin +2880 -delete >/dev/null 2>&1 || true
    fi
    if [ "$suricata" = yes ]; then
      size=$(num "$(dc exec -T suricata stat -c %s /var/log/suricata/eve.json 2>/dev/null | tr -cd 0-9)")
      if [ "$size" -gt 536870912 ]; then
        if dc exec -T suricata mv -f /var/log/suricata/eve.json /var/log/suricata/eve.json.1 >/dev/null 2>&1; then
          dc kill -s HUP suricata >/dev/null 2>&1 || true
        fi
      fi
      eve=$(dc exec -T suricata tail -n 3000 /var/log/suricata/eve.json 2>/dev/null) || true
    fi
  fi
  if printf '%s\n' "$running" | grep -qx zeek; then zr=true; fi
  if printf '%s\n' "$running" | grep -qx suricata; then sr=true; fi
else
  if [ "$zeek" = yes ]; then
    zv=$(safe "$(/opt/zeek/bin/zeek --version 2>/dev/null | sed -n 's/.*version \([^ ]*\).*/\1/p' | head -n 1)")
    if have pgrep && pgrep -x zeek >/dev/null 2>&1; then zr=true; fi
  fi
  if [ "$suricata" = yes ]; then
    sv=$(safe "$(suricata -V 2>/dev/null | sed -n 's/.*version \([^ ]*\).*/\1/p' | head -n 1)")
    if have systemctl && systemctl is-active --quiet signalith-suricata.service; then sr=true; fi
    eve=$(tail -n 3000 "$R/var/log/suricata/signalith/eve.json" 2>/dev/null) || true
  fi
  fv=$(safe "$(/opt/fluent-bit/bin/fluent-bit --version 2>/dev/null | sed -n 's/.*v\([0-9][0-9.]*\).*/\1/p' | head -n 1)")
fi
if [ "$zeek" = yes ] && [ "$zr" = false ]; then warn zeek_stopped; fi
if [ "$suricata" = yes ] && [ "$sr" = false ]; then warn suricata_stopped; fi

# The rules: the last update's result, from rules-update.sh.
rules=''
if [ "$suricata" = yes ]; then
  state=$R/var/lib/signalith-sensor/rules.state
  ru=$(safe "$(get RULES_UPDATED "$state")")
  rc=$(num "$(get RULES_COUNT "$state")")
  rr=$(safe "$(get RULES_UPDATE "$state")")
  [ -n "$rr" ] || rr=never
  rules="\"rules\":{"
  if [ -n "$ru" ]; then
    rules="$rules\"updated\":\"$ru\","
    then=$(date -u -d "$ru" +%s 2>/dev/null) || then=''
    if [ -n "$then" ] && [ $(($(date -u +%s) - then)) -gt 259200 ]; then warn rules_old; fi
  fi
  rules="$rules\"count\":$rc,\"update\":\"$rr\"},"
  if [ "$rr" = failed ]; then warn rules_failed; fi
  # The rule tuning from Signalith (Settings > Network sensors), from
  # rules-update.sh: which one runs, and how its last fetch went.
  tstate=$R/var/lib/signalith-sensor/tuning/tuning.state
  th=$(get TUNING_HASH "$tstate" | tr -cd '0-9a-f' | cut -c 1-12)
  tr_=$(safe "$(get TUNING_RESULT "$tstate")")
  ta=$(safe "$(get TUNING_APPLIED "$tstate")")
  te=$(get TUNING_ERROR "$tstate" | tr -cd 'A-Za-z0-9 ._:,/()=+-' | cut -c 1-200)
  [ -n "$tr_" ] || tr_=never
  rules="$rules\"tuning\":{\"hash\":\"$th\",\"result\":\"$tr_\",\"applied\":\"$ta\",\"error\":\"$te\"},"
  if [ "$tr_" = failed ]; then warn tuning_failed; fi
fi

# The capture port: link, packets, and the share dropped since the last
# line (the kernel's drops on the port plus Suricata's capture drops).
net=$sysfs/class/net/$iface
link=$(safe "$(cat "$net/operstate" 2>/dev/null)")
[ -n "$link" ] || link=missing
rxp=$(num "$(cat "$net/statistics/rx_packets" 2>/dev/null)")
rxd=$(num "$(cat "$net/statistics/rx_dropped" 2>/dev/null)")
kd=$(printf '%s\n' "$eve" | grep '"event_type":"stats"' | tail -n 1 | sed -n 's/.*"kernel_drops":\([0-9]*\).*/\1/p')
lp=0 ld=0 lk=0 before=no
if [ -r "$counters" ]; then
  before=yes
  read -r lp ld lk <"$counters" || true
fi
lp=$(num "$lp") ld=$(num "$ld") lk=$(num "$lk")
# No stats line in the end of eve.json read above (a busy link): Suricata's
# drops are taken as they were at the last line, not as zero, so the next
# stats line is not counted as all new drops.
if [ -z "$kd" ]; then kd=$lk; fi
kd=$(num "$kd")
dp=$((rxp - lp)) dd=$((rxd - ld)) dk=$((kd - lk))
# A counter that went down was reset (a restart): count from zero.
[ "$dp" -ge 0 ] || dp=$rxp
[ "$dd" -ge 0 ] || dd=$rxd
[ "$dk" -ge 0 ] || dk=$kd
printf '%s %s %s\n' "$rxp" "$rxd" "$kd" >"$counters.new" 2>/dev/null && mv -f "$counters.new" "$counters"
drop=$(awk -v d=$((dd + dk)) -v p=$((dp + dd)) 'BEGIN { if (p <= 0) { print "0.0" } else { v = 100 * d / p; if (v > 100) v = 100; printf "%.1f", v } }')
if [ "$link" != up ]; then warn capture_link; fi
if [ "$dp" -eq 0 ] && [ "$before" = yes ]; then warn no_traffic; fi
if awk -v v="$drop" 'BEGIN { exit !(v > 5) }'; then warn drops; fi
if have ip && [ -n "$(ip -o addr show dev "$iface" scope global 2>/dev/null)" ]; then warn capture_ip; fi

# Free disk space where the logs and the agent's buffer are.
dpath=/var
if [ "$layout" = docker ] && [ -d "$R/var/lib/docker" ]; then dpath=/var/lib/docker; fi
# shellcheck disable=SC2046 # two numbers
set -- $(df -Pk "$R$dpath" 2>/dev/null | awk 'NR == 2 { print $2, $4 }')
total=$(num "${1:-}") avail=$(num "${2:-}")
free=$(awk -v a="$avail" -v t="$total" 'BEGIN { if (t <= 0) print "0.0"; else printf "%.1f", 100 * a / t }')
if awk -v v="$free" 'BEGIN { exit !(v < 10) }'; then warn disk_low; fi
encrypted=false
if have lsblk && lsblk -nro TYPE 2>/dev/null | grep -qx crypt; then encrypted=true; fi
synced=false
if have timedatectl && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; then synced=true; fi
if [ "$synced" = false ]; then warn time_not_synced; fi

tools=''
if [ "$zeek" = yes ]; then tools="\"zeek\":{\"version\":\"$zv\",\"running\":$zr},"; fi
if [ "$suricata" = yes ]; then tools="$tools\"suricata\":{\"version\":\"$sv\",\"running\":$sr},"; fi

line=$(printf '{"kind":"signalith-sensor-status","v":1,"time":"%s","host":"%s","role":"sensor","sensor_version":"%s","layout":"%s",%s"fluentbit":{"version":"%s"},%s"interface":{"name":"%s","link":"%s","rx_packets":%s,"rx_dropped":%s,"drop_percent":%s},"disk":{"path":"%s","free_bytes":%s,"free_percent":%s,"encrypted":%s},"time_synced":%s,"warnings":[%s]}' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$version" "$layout" "$tools" "$fv" "$rules" \
  "$iface" "$link" "$rxp" "$rxd" "$drop" "$dpath" $((avail * 1024)) "$free" "$encrypted" "$synced" "$warnings")

# Rolled at 1 MB; the agent follows the rename.
if [ -f "$out" ] && [ "$(wc -c <"$out")" -gt 1048576 ]; then
  mv -f "$out" "$out.1"
fi
printf '%s\n' "$line" >>"$out"
chgrp signalith-sensor "$out" 2>/dev/null || true
chmod 0640 "$out"
HELPER
      ;;
    rules-update.sh)
      cat <<'HELPER'
#!/bin/sh
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Updates the Suricata rules and applies the rule tuning set on Signalith
# (Settings > Network sensors). suricata-update has Suricata test the
# rules before it writes them; Suricata then loads them without stopping.
# A failed download or test keeps the rules and the tuning in use.
#
#   rules-update.sh          the daily update (signalith-suricata-update.timer):
#                            fetch the tuning, then download the rules
#   rules-update.sh tuning   every 10 minutes (signalith-sensor-tuning.timer):
#                            fetch the tuning and, only when it changed,
#                            rebuild the rules with it
#   rules-update.sh merge    rebuild the tuning files from the ones in /etc
#                            (the install script, after writing them)
#
# The tuning comes from GET /api/sensor/tuning, with the sensor's own
# token, over HTTPS only. It is written to files, never run: disable.conf
# and threshold.config are the ones in /etc (your hand edits) followed by
# Signalith's, in /var/lib/signalith-sensor/tuning, which only root
# writes; Signalith's own rules go next to your local.rules. Results go to
# rules.state and tuning/tuning.state, which the status line reports.
#
# With packages, the rules and suricata-update's downloads are kept in
# /var/lib/signalith-sensor/suricata, which only root writes: this runs as
# root, so it never works in a folder the suricata user could change.
#
# SIGNALITH_SENSOR_ROOT is for tests only: a folder standing for /.
set -u
R=${SIGNALITH_SENSOR_ROOT:-}
mode=${1:-daily}
conf=$R/etc/signalith-sensor/sensor.conf
lib=$R/var/lib/signalith-sensor
state=$lib/rules.state
tdir=$lib/tuning
tstate=$tdir/tuning.state

case "$mode" in
  daily | tuning | merge) ;;
  *)
    echo "usage: rules-update.sh [tuning | merge]" >&2
    exit 2
    ;;
esac

# get prints the value of KEY='value' in a file the install script wrote.
get() {
  sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$2" 2>/dev/null | head -n 1
}
# count prints how many rules a rule file holds (lines that are not
# comments), 0 when it cannot be read.
count() {
  n=$(grep -c '^[a-z]' 2>/dev/null) || true
  case "$n" in '' | *[!0-9]*) n=0 ;; esac
  echo "$n"
}
# text cuts a message down to safe characters.
text() {
  printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._:,/()=+-' | cut -c 1-200
}

layout=$(get LAYOUT "$conf")
hand=$R/etc/suricata
if [ "$layout" = docker ]; then hand=$R/etc/signalith-sensor/docker/suricata; fi
umask 022
mkdir -p "$tdir"

# merge writes the files Suricata and suricata-update read: yours from
# /etc, then Signalith's.
merge() {
  for f in disable.conf threshold.config; do
    {
      if [ -f "$hand/$f" ]; then cat "$hand/$f"; fi
      echo ""
      echo "# From Signalith (Settings > Network sensors), fetched by rules-update.sh:"
      if [ -f "$tdir/server.$f" ]; then cat "$tdir/server.$f"; fi
    } >"$tdir/$f.new" && mv -f "$tdir/$f.new" "$tdir/$f"
  done
  if [ ! -f "$tdir/server.local.rules" ]; then : >"$tdir/server.local.rules"; fi
}

if [ "$mode" = merge ]; then
  merge
  exit 0
fi

# One run at a time: the daily update, the tuning timer and the install
# script may start together.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$lib/rules.lock"
  flock -w 1800 9 || exit 1
fi
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
chmod 0700 "$tmp"

t_hash=$(get TUNING_HASH "$tstate")
t_result=$(get TUNING_RESULT "$tstate")
t_applied=$(get TUNING_APPLIED "$tstate")
t_error=$(get TUNING_ERROR "$tstate")
t_failed=$(get TUNING_FAILED "$tstate")
[ -n "$t_result" ] || t_result=never
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

save_tuning() {
  {
    echo "# Written by /usr/lib/signalith-sensor/rules-update.sh: the rule tuning from Signalith."
    echo "TUNING_HASH='$(printf '%s' "$t_hash" | tr -cd '0-9a-f')'"
    echo "TUNING_RESULT='$t_result'"
    echo "TUNING_APPLIED='$t_applied'"
    echo "TUNING_ERROR='$(text "$t_error")'"
    echo "TUNING_FAILED='$(printf '%s' "$t_failed" | tr -cd '0-9a-f')'"
    echo "TUNING_TRIED='$now'"
  } >"$tstate.new" && mv -f "$tstate.new" "$tstate"
}

# The sensor's token: from the unit's environment, or token.env, which
# only root reads (read as text, never run).
token=${SIGNALITH_TOKEN:-}
if [ -z "$token" ]; then
  token=$(sed -n 's/^SIGNALITH_TOKEN=//p' "$R/etc/signalith-sensor/token.env" 2>/dev/null | head -n 1)
fi
token=$(printf '%s' "$token" | tr -cd 'A-Za-z0-9_.-')

# fetch gets the tuning into $tmp/new and its SHA-256 into $new: 0 when it
# is new, 1 when the sensor runs it already, 2 when it could not be
# fetched ($t_error says why), 3 when it is the one that failed its test
# before, unchanged.
new=''
fetch() {
  from=$(get FROM "$conf")
  case "$from" in
    https://*) ;;
    *)
      t_error="no Signalith address in sensor.conf"
      return 2
      ;;
  esac
  if [ -z "$token" ]; then
    t_error="no token in token.env"
    return 2
  fi
  # The token goes to curl in a file only root reads, never on its
  # command line, which every user can see.
  printf 'Authorization: Bearer %s\n' "$token" >"$tmp/hdr"
  etag=$(head -c 80 "$tdir/etag" 2>/dev/null | tr -cd '0-9a-f')
  if [ -n "$etag" ]; then printf 'If-None-Match: "%s"\n' "$etag" >>"$tmp/hdr"; fi
  set -- --proto =https --max-time 60 --max-filesize 1048576
  if grep -q 'BEGIN CERTIFICATE' "$R/etc/signalith-sensor/ca.pem" 2>/dev/null; then
    set -- "$@" --cacert "$R/etc/signalith-sensor/ca.pem"
  fi
  code=$(curl -sS "$@" -H "@$tmp/hdr" -D "$tmp/head" -o "$tmp/body" -w '%{http_code}' "$from/api/sensor/tuning" 2>"$tmp/err") || code=000
  rm -f "$tmp/hdr"
  case "$code" in
    304) return 1 ;;
    200) ;;
    000)
      t_error="Signalith could not be reached: $(tail -n 1 "$tmp/err")"
      return 2
      ;;
    *)
      t_error="Signalith answered $code: $(head -c 200 "$tmp/body")"
      return 2
      ;;
  esac
  sum=$(sha256sum <"$tmp/body" | cut -c 1-64)
  got=$(tr -d '\r' <"$tmp/head" | sed -n 's/^[Ee][Tt][Aa][Gg]:[ ]*"\([0-9a-f]\{64\}\)"$/\1/p' | tail -n 1)
  if [ "$sum" != "$got" ]; then
    t_error="the tuning did not arrive whole (its SHA-256 is not its ETag)"
    return 2
  fi
  mkdir -p "$tmp/new"
  : >"$tmp/new/disable.conf"
  : >"$tmp/new/threshold.config"
  : >"$tmp/new/local.rules"
  # Lines are copied to files by section; nothing is run.
  if ! awk -v d="$tmp/new" '
    NR == 1 { if ($0 != "# signalith-sensor-tuning 1") { bad = 1; exit 1 } next }
    $0 == "[end]" { ended = 1; exit 0 }
    $0 == "[disable]" { out = d "/disable.conf"; next }
    $0 == "[threshold]" { out = d "/threshold.config"; next }
    $0 == "[local]" { out = d "/local.rules"; next }
    /^\[/ || out == "" { bad = 1; exit 1 }
    { print > out }
    END { if (bad || !ended) exit 1 }
  ' "$tmp/body"; then
    t_error="the tuning is not in the form this sensor reads; run the install line again"
    return 2
  fi
  new=$sum
  # A tuning that failed its test is not tried again until it changes.
  if [ "$new" = "$t_failed" ]; then return 3; fi
  return 0
}

# stage keeps the tuning in use in prev/ and puts the new one in place.
stage() {
  mkdir -p "$tdir/prev"
  for f in disable.conf threshold.config local.rules; do
    if [ -f "$tdir/server.$f" ]; then cp -p "$tdir/server.$f" "$tdir/prev/server.$f"; else : >"$tdir/prev/server.$f"; fi
    cp "$tmp/new/$f" "$tdir/server.$f.new" && mv -f "$tdir/server.$f.new" "$tdir/server.$f"
  done
  merge
}

# unstage puts the tuning of prev/ back.
unstage() {
  for f in disable.conf threshold.config local.rules; do
    if [ -f "$tdir/prev/server.$f" ]; then mv -f "$tdir/prev/server.$f" "$tdir/server.$f"; fi
  done
  merge
}

dc() {
  docker compose -f /etc/signalith-sensor/docker/docker-compose.yml "$@"
}

# update runs suricata-update with the tuning in place; with "offline",
# from its last download. Its output goes to $tmp/out.
update() {
  off=${1:-}
  if [ "$layout" = docker ]; then
    t=/etc/suricata/signalith-tuning
    set -- --etopen --suricata-conf /etc/suricata/signalith-sensor.yaml --disable-conf "$t/disable.conf" \
      --local /etc/suricata/local.rules --local "$t/server.local.rules" --no-reload --fail
    if [ -n "$off" ]; then set -- "$@" --offline; fi
    dc --profile update run --rm suricata-update "$@" >"$tmp/out" 2>&1
  else
    set -- --etopen --data-dir "$lib/suricata" --suricata-conf "$R/etc/suricata/signalith-sensor-test.yaml" \
      --disable-conf "$tdir/disable.conf" --no-reload --fail
    if [ -s "$R/etc/signalith-sensor/local.rules" ]; then
      set -- "$@" --local "$R/etc/signalith-sensor/local.rules"
    fi
    if [ -s "$tdir/server.local.rules" ]; then
      set -- "$@" --local "$tdir/server.local.rules"
    fi
    if [ -n "$off" ]; then set -- "$@" --offline; fi
    suricata-update "$@" >"$tmp/out" 2>&1
  fi
}

# cached says whether suricata-update has a download to rebuild from.
cached() {
  if [ "$layout" = docker ]; then
    dc --profile update run --rm --entrypoint sh suricata-update -c 'ls /var/lib/suricata/update/cache 2>/dev/null | grep -q .' >/dev/null 2>&1
  else
    for f in "$lib"/suricata/update/cache/*; do
      if [ -e "$f" ]; then return 0; fi
    done
    return 1
  fi
}

# rules_count prints how many rules Suricata has now.
rules_count() {
  if [ "$layout" = docker ]; then
    dc --profile update run --rm --entrypoint cat suricata-update /var/lib/suricata/rules/suricata.rules | count
  else
    count <"$lib/suricata/rules/suricata.rules"
  fi
}

reload() {
  if [ "$layout" = docker ]; then
    dc exec -T suricata suricatasc -c ruleset-reload-nonblocking /var/run/suricata/suricata-command.socket >/dev/null 2>&1 ||
      dc restart suricata >/dev/null 2>&1 || true
  elif systemctl is-active --quiet signalith-suricata.service; then
    suricatasc -c ruleset-reload-nonblocking /run/suricata/suricata-command.socket >/dev/null 2>&1 ||
      systemctl reload signalith-suricata.service || true
  fi
}

# why prints the last error suricata-update gave.
why() {
  l=$(grep -i 'error' "$tmp/out" 2>/dev/null | tail -n 1)
  [ -n "$l" ] || l=$(tail -n 1 "$tmp/out" 2>/dev/null)
  printf '%s' "$l" | sed 's/^[0-9/ :.-]*- *//'
}

save_rules() {
  {
    echo "# Written by /usr/lib/signalith-sensor/rules-update.sh: the last rules update."
    echo "RULES_UPDATE='$1'"
    echo "RULES_UPDATED='$2'"
    echo "RULES_COUNT='$3'"
    echo "RULES_TRIED='$4'"
  } >"$state.new" && mv -f "$state.new" "$state"
}

# applied records the tuning now in use.
applied() {
  printf '%s\n' "$new" >"$tdir/etag.new" && mv -f "$tdir/etag.new" "$tdir/etag"
  t_hash=$(printf '%s' "$new" | cut -c 1-12)
  t_result=ok t_applied=$now t_error='' t_failed=''
}

# refused records a tuning that failed its test; the one before stays.
refused() {
  t_result=failed t_error=$(why) t_failed=$new
  [ -n "$t_error" ] || t_error="suricata-update refused the rules"
}

fetch
fetched=$?
case "$fetched" in
  1)
    # The sensor runs what Signalith has.
    t_result=ok t_error='' t_failed=''
    if [ -z "$t_hash" ]; then t_hash=$(cut -c 1-12 "$tdir/etag" 2>/dev/null); fi
    ;;
  2)
    # The tuning in use stays; the status line says why.
    if [ "$t_result" != failed ]; then t_result=unreachable; fi
    ;;
esac
# Your hand edits in /etc count on every run.
merge

if [ "$mode" = tuning ]; then
  if [ "$fetched" != 0 ]; then
    save_tuning
    exit 0
  fi
  stage
  off=''
  if cached; then off=offline; fi
  if update $off; then
    applied
    save_tuning
    updated=$(get RULES_UPDATED "$state")
    [ -n "$off" ] || updated=$now
    save_rules ok "$updated" "$(rules_count)" "$now"
    reload
    exit 0
  fi
  refused
  unstage
  save_tuning
  cat "$tmp/out" >&2
  exit 1
fi

# The daily update: the new tuning, if any, goes in with the new rules;
# when they fail together, the rules are tried again without it.
updated=$(get RULES_UPDATED "$state")
rules=$(get RULES_COUNT "$state")
result=failed
if [ "$fetched" = 0 ]; then stage; fi
if update; then
  result=ok
  if [ "$fetched" = 0 ]; then applied; fi
elif [ "$fetched" = 0 ]; then
  refused
  unstage
  if update; then result=ok; fi
fi
if [ "$result" = ok ]; then
  updated=$now
  rules=$(rules_count)
  reload
else
  cat "$tmp/out" >&2
fi
save_tuning
save_rules "$result" "$updated" "$rules" "$now"
[ "$result" = ok ]
HELPER
      ;;
  esac
}

compose_file() {
  cat <<'COMPOSE'
# Signalith network sensor in containers: Zeek, Suricata and the Fluent Bit
# agent, written by the sensor install script with --docker
# (deploy/sensor/install.sh) to /etc/signalith-sensor/docker/. Run the
# script again rather than editing this file: it is replaced.
#
# The images come from their publishers (Docker Hub), pinned by version and
# digest in .env next to this file; Signalith does not rebuild or ship them.
# Linux hosts only: Docker Desktop cannot listen on a physical port.
#
# The host prepares the capture port and runs three timers: the status
# line every 5 minutes, the daily Suricata rules update, and the rule
# tuning set on Signalith every 10 minutes (both run the suricata-update
# service below, then have Suricata load the new rules).
name: signalith-sensor

x-hardened: &hardened
  network_mode: host
  restart: unless-stopped
  read_only: true
  security_opt:
    - no-new-privileges:true
  tmpfs:
    - /tmp
    - /run

services:
  zeek:
    <<: *hardened
    image: ${SIGNALITH_IMAGE_ZEEK}
    # One Zeek process (no zeekctl): fine up to roughly 200 Mbit/s. Bigger
    # links use the package install, which runs Zeek workers per core.
    working_dir: /logs/zeek/current
    entrypoint: ["zeek"]
    command: ["-C", "-i", "af_packet::${SIGNALITH_INTERFACE}", "local", "/config/signalith.zeek"]
    # Only the right packet capture needs: the host already made the port
    # promiscuous, so Zeek cannot change the network settings. It stays the
    # image's root user, as Docker gives added rights to root alone; that
    # root has no other rights, and the image is read-only.
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    volumes:
      - zeek-logs:/logs/zeek
      - /etc/signalith-sensor/docker/zeek/signalith.zeek:/config/signalith.zeek:ro

  suricata:
    <<: *hardened
    image: ${SIGNALITH_IMAGE_SURICATA}
    # Starts as root to open the capture port, then runs as the image's
    # suricata user (--user), keeping only the capture rights. Until then
    # it needs DAC_OVERRIDE (the image's suricata.yaml and log folder are
    # that user's alone), and CHOWN and SETPCAP to hand over and drop the
    # rest.
    entrypoint: ["suricata"]
    command: ["-c", "/etc/suricata/signalith-sensor.yaml", "--af-packet", "--user", "suricata", "--group", "suricata"]
    cap_drop: [ALL]
    cap_add: [NET_RAW, NET_ADMIN, SETUID, SETGID, SYS_NICE, DAC_OVERRIDE, CHOWN, SETPCAP]
    volumes:
      - suricata-logs:/var/log/suricata
      - suricata-rules:/var/lib/suricata
      - /etc/signalith-sensor/docker/suricata/signalith-sensor.yaml:/etc/suricata/signalith-sensor.yaml:ro
      # Your disable.conf and threshold.config with the rule tuning set on
      # Signalith, which the host's timers fetch and merge.
      - /var/lib/signalith-sensor/tuning:/etc/suricata/signalith-tuning:ro

  # The daily rules update, not started with the others: the host's timer
  # runs it, and Suricata loads the new rules once they passed its test.
  suricata-update:
    image: ${SIGNALITH_IMAGE_SURICATA}
    profiles: [update]
    # As the suricata user, who owns the rules folder.
    user: suricata
    network_mode: host
    read_only: true
    security_opt:
      - no-new-privileges:true
    # Suricata's test of the new rules opens its logs: they go nowhere.
    tmpfs:
      - /tmp
      - /var/log/suricata
    entrypoint: ["suricata-update"]
    # The host's rules-update.sh gives these arguments itself.
    command: ["--etopen", "--suricata-conf", "/etc/suricata/signalith-sensor.yaml", "--disable-conf", "/etc/suricata/signalith-tuning/disable.conf",
      "--local", "/etc/suricata/local.rules", "--local", "/etc/suricata/signalith-tuning/server.local.rules", "--no-reload", "--fail"]
    cap_drop: [ALL]
    volumes:
      - suricata-rules:/var/lib/suricata
      - /etc/signalith-sensor/docker/suricata/signalith-sensor.yaml:/etc/suricata/signalith-sensor.yaml:ro
      - /var/lib/signalith-sensor/tuning:/etc/suricata/signalith-tuning:ro
      - /etc/signalith-sensor/docker/suricata/local.rules:/etc/suricata/local.rules:ro

  fluent-bit:
    <<: *hardened
    image: ${SIGNALITH_IMAGE_FLUENTBIT}
    command: ["/fluent-bit/bin/fluent-bit", "-c", "/config/fluent-bit.conf"]
    # The token (SIGNALITH_TOKEN) and the sensor's name (HOSTNAME). The
    # image has no shell to read a Docker secret into a variable, so the
    # token comes from this file, which only root reads.
    env_file: /etc/signalith-sensor/token.env
    cap_drop: [ALL]
    volumes:
      - zeek-logs:/logs/zeek:ro
      - suricata-logs:/logs/suricata:ro
      - /var/log/signalith-sensor:/logs/status:ro
      - buffer:/buffer
      - /etc/signalith-sensor/docker/fluent-bit.conf:/config/fluent-bit.conf:ro
      - /etc/signalith-sensor/ca.pem:/config/ca.pem:ro

volumes:
  zeek-logs:
  suricata-logs:
  suricata-rules:
  buffer:
COMPOSE
}

# The units the sensor runs, with the group of files each restarts on.
units=''
sensor_units() {
  units='signalith-sensor-capture.service:capture signalith-sensor-status.timer:status'
  if [ "$layout" = packages ]; then
    [ "$zeek" = no ] || units="$units signalith-zeek.service:zeek signalith-zeekctl-cron.timer:zeek"
    [ "$suricata" = no ] || units="$units signalith-suricata.service:suricata"
    units="$units signalith-fluent-bit.service:agent"
  fi
  [ "$suricata" = no ] || units="$units signalith-suricata-update.timer:rules signalith-sensor-tuning.timer:rules"
  # The capture port's name as systemd writes its device unit.
  if [ -n "$dryrun" ] || ! command -v systemd-escape >/dev/null 2>&1; then
    dev=sys-subsystem-net-devices-$(printf '%s' "$iface" | sed 's/-/\\x2d/g').device
  else
    dev=sys-subsystem-net-devices-$(systemd-escape "$iface").device
  fi
  # write_unit puts it in with sed, which would read \x2d as "-".
  dev=$(printf '%s' "$dev" | sed 's/\\/\\\\/g')
  # A new capture port: the service stops as written for the old one,
  # which puts that port back as it was, before the units name the new.
  if [ -n "$old_iface" ] && [ "$old_iface" != "$iface" ]; then
    run systemctl stop signalith-sensor-capture.service || true
  fi
  for u in $units; do
    u=${u%:*}
    write_unit "$u"
    case "$u" in
      *.timer) write_unit "${u%.timer}.service" ;;
    esac
  done
  sensor_helper capture-up.sh | put /usr/lib/signalith-sensor/capture-up.sh 0755 root:root capture
  for h in status.sh rules-update.sh; do
    sensor_helper "$h" | put "/usr/lib/signalith-sensor/$h" 0755 root:root helpers
  done
  # A copy of this script, for --uninstall (and to run it again).
  if [ -f "$0" ]; then
    put_file /usr/lib/signalith-sensor/install.sh 0755 root:root "$0" script
  fi
  if is_changed units; then run systemctl daemon-reload; fi
  ok "systemd units and helpers in /etc/systemd/system and /usr/lib/signalith-sensor"
}
write_unit() {
  sensor_unit "$1" | sed -e "s|@IFACE_UNIT@|$dev|g" -e "s|@IFACE@|$iface|g" >"$tmp/unit"
  before=$changed
  put_file "/etc/systemd/system/$1" 0644 root:root "$tmp/unit" units
  if [ "$changed" != "$before" ]; then
    # The unit's own group restarts too.
    for e in $units; do
      [ "${e%:*}" = "$1" ] || [ "${e%:*}" = "${1%.service}.timer" ] || continue
      case " $changed " in *" ${e#*:} "*) ;; *) changed="$changed ${e#*:}" ;; esac
    done
  fi
  manifest_add "unit $1"
}

# --- Sensor: Docker ----------------------------------------------------

sensor_docker_checks() {
  if [ -n "$dryrun" ]; then
    info "dry run: Docker not checked"
    return 0
  fi
  command -v docker >/dev/null 2>&1 || fail "--docker needs Docker Engine, which this machine does not have." "Install Docker Engine 24 or newer (https://docs.docker.com/engine/install/), or leave out --docker to install packages."
  v=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || fail "Docker does not answer." "sudo systemctl start docker, then run the line again."
  major=${v%%.*}
  case "$major" in '' | *[!0-9]*) major=0 ;; esac
  [ "$major" -ge 24 ] || fail "Docker $v is too old: the sensor needs Docker Engine 24 or newer." "Upgrade Docker Engine."
  case "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" in
    *"Docker Desktop"*) fail "Docker Desktop cannot capture a physical network port." "Use Docker Engine on Linux, or leave out --docker to install packages." ;;
  esac
  docker compose version >/dev/null 2>&1 || fail "--docker needs Docker Compose v2 (docker compose)." "Install the docker-compose-plugin package."
  ok "Docker $v with Compose"
}

dc() {
  run docker compose -f /etc/signalith-sensor/docker/docker-compose.yml "$@"
}

sensor_docker_files() {
  folder /etc/signalith-sensor/docker 0755 root:root
  compose_file | put /etc/signalith-sensor/docker/docker-compose.yml 0644 root:root docker
  put /etc/signalith-sensor/docker/.env 0644 root:root docker <<EOF
# Written by the Signalith sensor install script: the capture port and the
# publishers' images, pinned by digest.
SIGNALITH_INTERFACE=$iface
SIGNALITH_SENSOR_NAME=$name
SIGNALITH_IMAGE_ZEEK=$IMAGE_ZEEK
SIGNALITH_IMAGE_SURICATA=$IMAGE_SURICATA
SIGNALITH_IMAGE_FLUENTBIT=$IMAGE_FLUENTBIT
EOF
  if [ "$zeek" = yes ]; then
    zeek_script | put /etc/signalith-sensor/docker/zeek/signalith.zeek 0644 root:root zeek
  fi
}

sensor_docker_start() {
  services='fluent-bit'
  [ "$zeek" = no ] || services="zeek $services"
  [ "$suricata" = no ] || services="suricata $services"
  dc pull --quiet
  if [ "$suricata" = yes ]; then
    if ! manifest_has "rules first"; then
      say "  downloading the Suricata rules (Emerging Threats Open)..."
      if ! run /usr/lib/signalith-sensor/rules-update.sh >"$tmp/out" 2>&1; then
        warn "The first rules download failed: Suricata starts with no rules, and the daily update tries again." "sudo systemctl start signalith-suricata-update.service, then see: journalctl -u signalith-suricata-update"
        why
        dc --profile update run --rm --entrypoint sh suricata-update -c 'mkdir -p /var/lib/suricata/rules && touch /var/lib/suricata/rules/suricata.rules'
      fi
      manifest_add "rules first"
    elif is_changed rules; then
      # Your own rules (--local-rules) changed: in use now, not tomorrow.
      rules_again
    fi
  fi
  first=yes
  if manifest_has "docker /etc/signalith-sensor/docker/docker-compose.yml"; then first=no; fi
  # shellcheck disable=SC2086 # a list of service names
  dc up -d --remove-orphans $services
  manifest_add "docker /etc/signalith-sensor/docker/docker-compose.yml"
  # Their files are mounted: a container whose files changed restarts.
  for e in zeek:zeek suricata:suricata agent:fluent-bit; do
    case " $services " in *" ${e#*:} "*) ;; *) continue ;; esac
    if [ "$first" = no ] && is_changed "${e%:*}"; then dc restart "${e#*:}"; fi
  done
  ok "containers started: $services"
}

# --- Sensor: start and confirm -----------------------------------------

# sensor_tuning_files writes the files Suricata reads its tuning from:
# disable.conf and threshold.config as written above, with the tuning
# fetched from Signalith (none yet on the first run).
sensor_tuning_files() {
  [ "$suricata" = yes ] || return 0
  if ! SIGNALITH_SENSOR_ROOT=$R sh "$R/usr/lib/signalith-sensor/rules-update.sh" merge >"$tmp/out" 2>&1; then
    why
    fail "The rule tuning files could not be written in /var/lib/signalith-sensor/tuning (see above)."
  fi
}

sensor_test_configs() {
  if [ "$layout" = docker ]; then return 0; fi
  if [ "$suricata" = yes ] && is_changed suricata; then
    if [ ! -f "$R/var/lib/signalith-sensor/suricata/rules/suricata.rules" ]; then
      # Suricata's test needs a rule file; the first update fills it.
      : | put /var/lib/signalith-sensor/suricata/rules/suricata.rules 0644 root:root rules
    fi
    if ! quiet suricata -T -c /etc/suricata/signalith-sensor.yaml; then
      restore /etc/suricata/signalith-sensor.yaml
      fail "Suricata refused its new configuration (see above); the one before was put back." "Check /etc/suricata/suricata.yaml, the package's file this configuration builds on."
    fi
    ok "Suricata's configuration passed its test"
  fi
  if [ "$zeek" = yes ] && is_changed zeek; then
    if ! quiet runuser -u zeek -- /opt/zeek/bin/zeekctl check; then
      for f in node.cfg networks.cfg zeekctl.cfg; do restore "/opt/zeek/etc/$f"; done
      restore /opt/zeek/share/zeek/site/signalith.zeek
      fail "zeekctl check refused Zeek's new configuration (see above); the files before were put back."
    fi
    ok "Zeek's configuration passed zeekctl check"
  fi
}

# is_changed says whether group $1 changed in this run.
is_changed() {
  case " $changed " in *" $1 "*) return 0 ;; esac
  return 1
}

# rules_again updates the rules on a run after the first, when they
# changed (your own rules, --local-rules); Suricata loads them once they
# pass its test.
rules_again() {
  say "  updating the Suricata rules with your own..."
  if run /usr/lib/signalith-sensor/rules-update.sh >"$tmp/out" 2>&1; then
    ok "the Suricata rules, with your own"
  else
    warn "The rules update failed: Suricata keeps the rules it had." "See why with: sudo journalctl -u signalith-suricata-update -n 50 (or run sudo /usr/lib/signalith-sensor/rules-update.sh), fix your rules file, and run the line again."
    why
  fi
}

sensor_start() {
  if [ "$suricata" = yes ] && [ "$layout" = packages ]; then
    if ! manifest_has "rules first"; then
      say "  downloading the Suricata rules (Emerging Threats Open)..."
      if run /usr/lib/signalith-sensor/rules-update.sh >"$tmp/out" 2>&1; then
        ok "the Suricata rules"
      else
        warn "The first rules download failed: Suricata starts with no rules, and the daily update tries again." "sudo systemctl start signalith-suricata-update.service, then see: journalctl -u signalith-suricata-update"
        why
      fi
      manifest_add "rules first"
    elif is_changed rules; then
      rules_again
    fi
  fi
  for e in $units; do
    u=${e%:*}
    group=${e#*:}
    run systemctl enable --quiet "$u"
    if is_changed "$group"; then
      case "$u" in
        *.timer) run systemctl restart "$u" ;;
        *) quiet systemctl restart "$u" || fail "$u did not start (see above)." "See why with: sudo journalctl -u $u -n 50" ;;
      esac
    else
      run systemctl start "$u"
    fi
  done
  if [ "$layout" = docker ]; then sensor_docker_start; fi
  run systemctl start signalith-sensor-status.service
  ok "services and timers started"
}

# seen prints when Signalith last heard from this sensor's token.
seen() {
  code=$(sig_get /api/sensor/seen "$tmp/seen" 2>/dev/null) || code=000
  [ "$code" = 200 ] || return 0
  sed -n 's/.*"last_seen":"\([^"]*\)".*/\1/p' "$tmp/seen"
}

common_confirm() {
  if [ -n "$dryrun" ]; then
    say "    would wait until Signalith has heard from the sensor (GET /api/sensor/seen)"
    warnings_note
    return 0
  fi
  say "  waiting for Signalith to hear from the sensor..."
  i=0
  while [ "$i" -lt 18 ]; do
    now=$(seen)
    if [ -n "$now" ] && [ "$now" != "$seen_before" ]; then
      say ""
      say "Sensor sends to Signalith. Open Endpoints: $name should show Network sensor, sending."
      warnings_note
      return 0
    fi
    sleep 5
    i=$((i + 1))
  done
  say "" >&2
  if [ "$layout" = docker ]; then
    docker compose -f /etc/signalith-sensor/docker/docker-compose.yml logs --tail 20 fluent-bit >&2 || true
  else
    journalctl -u signalith-fluent-bit -n 20 --no-pager >&2 || true
  fi
  fail "Signalith has not heard from the sensor after 90 seconds (the agent's log is above)." "Check that this machine reaches $from, and that the token was not revoked (Settings > Agent tokens); the agent keeps trying."
}

# warnings_note repeats, at the end, that warnings scrolled past.
warnings_note() {
  if [ "$warned" -gt 0 ]; then
    say "$warned warning(s) above: the sensor runs, but see the Fix line under each."
  fi
}

# --- Uninstall ---------------------------------------------------------

common_uninstall() {
  if [ -z "$dryrun" ]; then
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: it removes packages and services."
  fi
  [ -f "$manifest" ] || fail "This machine has no sensor the script installed (no $manifest)."
  say "Signalith sensor: removing what the install script added"
  # Containers first.
  if grep -q '^docker ' "$manifest"; then
    if [ "$purge" = yes ]; then
      dc down --volumes --remove-orphans || true
    else
      dc down --remove-orphans || true
    fi
  fi
  # shellcheck disable=SC2013 # names, one a line
  for u in $(sed -n 's/^unit //p' "$manifest"); do
    quiet systemctl disable --now "$u" || true
  done
  # shellcheck disable=SC2013 # names, one a line
  for u in $(sed -n 's/^mask //p' "$manifest"); do
    quiet systemctl unmask "$u" || true
  done
  # The package's own services that were running before the sensor.
  # shellcheck disable=SC2013 # names, one a line
  for u in $(sed -n 's/^was running //p' "$manifest"); do
    quiet systemctl start "$u" || warn "Could not start $u again, which ran before the sensor (see above)." "sudo systemctl start $u"
  done
  sed -n 's/^orig //p' "$manifest" | while IFS= read -r f; do
    if [ -f "$R$f.signalith-orig" ]; then mv -f "$R$f.signalith-orig" "$R$f"; fi
  done
  sed -n 's/^file //p' "$manifest" | while IFS= read -r f; do
    rm -f "$R$f"
  done
  ok "removed the files it wrote, and put back the ones it replaced"
  # Packages the script installed, newest first; the ones that were here
  # before stay.
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
  # shellcheck disable=SC2013 # names, one a line
  for a in $(sed -n 's/^account //p' "$manifest"); do
    quiet userdel "$a" || true
  done
  # shellcheck disable=SC2013 # names, one a line
  for g in $(sed -n 's/^group //p' "$manifest"); do
    if getent group "$g" >/dev/null 2>&1 || [ -n "$dryrun" ]; then
      quiet groupdel "$g" || true
    fi
  done
  rm -rf "$R/etc/signalith-sensor" "$R/usr/lib/signalith-sensor" "$R/var/lib/signalith-sensor"
  if [ "$purge" = yes ]; then
    rm -rf "$R/var/log/signalith-sensor" "$R/var/log/suricata/signalith" "$R/opt/zeek/logs" "$R/opt/zeek/spool"
    ok "removed the logs"
  else
    info "the logs stay (/var/log/suricata/signalith, /opt/zeek/logs, /var/log/signalith-sensor): --purge removes them"
  fi
  run systemctl daemon-reload || true
  say ""
  say "The sensor is removed. Revoke its token in Signalith: Settings > Agent tokens."
}

# --- Main --------------------------------------------------------------

if [ "$uninstall" = yes ]; then
  common_uninstall
  exit 0
fi

common_args
say "Signalith sensor: checking this machine"
common_machine
sensor_sources
sensor_resources
if [ "$docker" = yes ]; then sensor_docker_checks; fi
say ""
say "Signalith"
common_ca
common_config
say ""
say "Capture port"
sensor_pick_port
sensor_port_checks
say ""
if [ "$check_only" = yes ]; then
  if [ "$warned" -gt 0 ]; then
    say "Checked: $warned warning(s) above; nothing was changed (--check-only)."
  else
    say "Checked: this machine is ready; nothing was changed (--check-only)."
  fi
  exit 0
fi

seen_before=''
if [ -z "$dryrun" ]; then seen_before=$(seen); fi
# Left by a run that was stopped halfway (by a power cut, say).
rm -f "$R"/etc/signalith-sensor/*.signalith-new
say "Installing"
if [ "$docker" = yes ]; then
  layout=docker
else
  sensor_packages
fi
sensor_accounts
if [ "$zeek" = yes ] && [ "$layout" = packages ]; then sensor_zeek_config; fi
if [ "$suricata" = yes ]; then sensor_suricata_config; fi
if [ "$layout" = docker ]; then sensor_docker_files; fi
sensor_conf
common_agent_config
sensor_units
sensor_tuning_files
sensor_test_configs
say ""
if [ -z "$changed" ] && [ -z "$installed" ] && [ -z "$upgraded" ]; then
  say "Nothing to change: the sensor is set up as the line says."
  if [ -z "$dryrun" ]; then
    last=$(seen)
    if [ -n "$last" ]; then say "Signalith last heard from $name at $last."; fi
  fi
  warnings_note
  exit 0
fi
say "Starting"
sensor_start
common_confirm
