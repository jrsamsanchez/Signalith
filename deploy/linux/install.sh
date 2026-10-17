#!/bin/sh
# Installs Signalith on Linux as a systemd service, and joins it to the
# servers of an existing Signalith (a cluster) or sets it up as a first
# server.
#
# The Servers page's "Add a server" dialog gives one line that downloads
# this script from a server of the cluster, checks it, and runs it:
#
#   echo 'SJ1....' | sudo sh install.sh --from https://siem-a:9000 \
#     --version 1.5.0 --sha256 <program's SHA-256> --join -
#
# "--join -" reads the token from the standard input, so it is never on a
# command line other users of the machine could see in the process list.
#
# A first server, with no cluster to join:
#
#   sudo sh install.sh --binary ./signalith-linux-amd64
#
# What it does, in order, stopping at the first problem with a plain
# message and nothing half done:
#   1. Checks the machine: root, systemd, a known processor type, and the
#      tools it uses.
#   2. Finds the program. When the signalith .deb or .rpm package is
#      installed, it uses the package's /usr/bin/signalith, which must be
#      the version the cluster runs (it never installs a second copy).
#      Otherwise it installs /usr/local/bin/signalith: the file --binary
#      names, or the program downloaded from the --from server, checked
#      against --sha256 either way when it is given (always when
#      downloaded).
#   3. Without the package: the signalith system account, /etc/signalith
#      and /var/lib/signalith, and the systemd unit (the same unit as
#      deploy/systemd/signalith.service).
#   4. With --join: "signalith join", which checks the token against the
#      cluster, checks OpenSearch from this machine before writing
#      anything, writes this server's settings and keys, and starts the
#      service. Without --join: "signalith init" and the service, as the
#      package does.
set -eu

config=/etc/signalith/signalith.yaml
from=''
version=''
sha256=''
binary=''
token=''
name=''
listen=''
node_url=''

say() { printf '%s\n' "$*"; }
ok() { printf '  \342\234\223 %s\n' "$*"; }
fail() {
  printf '\n%s\n' "$*" >&2
  exit 1
}
usage() {
  cat <<'USAGE'
Usage: sudo sh install.sh [--join - --from https://<server>:9000]
                          [--version <v>] [--sha256 <hex>] [--binary <file>]
                          [--name <server name>] [--listen <addr:port>]
                          [--node-url https://<this server>:9000]

  --join      The token from Servers > Add a server, or - to read it from
              the standard input. Without it this machine becomes a first
              server of its own.
  --from      The server the token came from: the program is downloaded from
              it when this machine has none of the same version.
  --version   The version the cluster runs; this machine must run the same.
  --sha256    The SHA-256 the program must have.
  --binary    Use this file as the program instead of downloading it.
  --name      This server's name on the Servers page (default: the host name).
  --listen    Address and port for the web page and API (agents send to port 7779 on its host).
  --node-url  The address the other servers reach this one at.
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
    --version) need "$1" $#; version=$2; shift 2 ;;
    --version=*) version=${1#*=}; shift ;;
    --sha256) need "$1" $#; sha256=$2; shift 2 ;;
    --sha256=*) sha256=${1#*=}; shift ;;
    --binary) need "$1" $#; binary=$2; shift 2 ;;
    --binary=*) binary=${1#*=}; shift ;;
    --join) need "$1" $#; token=$2; shift 2 ;;
    --join=*) token=${1#*=}; shift ;;
    --name) need "$1" $#; name=$2; shift 2 ;;
    --name=*) name=${1#*=}; shift ;;
    --listen) need "$1" $#; listen=$2; shift 2 ;;
    --listen=*) listen=${1#*=}; shift ;;
    --node-url) need "$1" $#; node_url=$2; shift 2 ;;
    --node-url=*) node_url=${1#*=}; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; fail "Unknown option: $1" ;;
  esac
done

say "Signalith: checking this machine"

[ "$(id -u)" = 0 ] || fail "Run this with sudo: it installs a service and makes a system account."
ok "running as root"

if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
  fail "This machine does not run systemd, which Signalith's service needs. Use a systemd Linux (Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, SUSE), or Docker (Servers > Add a server > Docker)."
fi
ok "systemd"

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "Signalith runs on 64-bit x86 (amd64) and 64-bit ARM (arm64), not $(uname -m)." ;;
esac
ok "processor: $arch"

for tool in sha256sum install id; do
  command -v "$tool" >/dev/null 2>&1 || fail "This script needs $tool, which this machine does not have (it is part of coreutils)."
done

case "$sha256" in
  '') ;;
  *[!0-9a-fA-F]*) fail "--sha256 must be 64 hexadecimal characters." ;;
  *) [ ${#sha256} -eq 64 ] || fail "--sha256 must be 64 hexadecimal characters." ;;
esac
if [ "$token" = - ]; then
  IFS= read -r token || [ -n "$token" ] || fail "No join token on the standard input. Copy the whole line from Servers > Add a server again."
  token=$(printf '%s' "$token" | tr -d '[:space:]')
fi
if [ -n "$token" ]; then
  case "$token" in
    SJ1.*) ;;
    *) fail "The --join value is not a Signalith join token (they start with SJ1.). Copy the whole line from Servers > Add a server again." ;;
  esac
fi
case "$from" in
  '' | https://*) ;;
  *) fail "--from must be an https:// address." ;;
esac

# The program's version, from "signalith version" ("signalith 1.5.0").
version_of() {
  "$1" version 2>/dev/null | awk '{print $2; exit}'
}

# checksum fails unless file $1 has the SHA-256 --sha256 names.
checksum() {
  [ -n "$sha256" ] || return 0
  got=$(sha256sum "$1" | awk '{print $1}')
  want=$(printf '%s' "$sha256" | tr 'A-F' 'a-f')
  [ "$got" = "$want" ] || fail "$2 does not have the SHA-256 the line names, so it was not installed. Copy the line from Servers > Add a server again; if it happens again, the download was changed on its way here."
}

package=no
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' signalith 2>/dev/null | grep -q 'install ok installed'; then
  package=deb
elif command -v rpm >/dev/null 2>&1 && rpm -q signalith >/dev/null 2>&1; then
  package=rpm
fi

if [ "$package" != no ]; then
  # The package's program and unit stay the ones in use: a second copy in
  # /usr/local/bin would be left behind by the package's next upgrade.
  bin=/usr/bin/signalith
  have=$(version_of "$bin")
  if [ -n "$version" ] && [ "$have" != "$version" ]; then
    if [ "$package" = deb ]; then
      how="sudo apt-get install signalith=$version-1"
    else
      how="sudo dnf install signalith-$version"
    fi
    fail "This machine has the Signalith package $have, but the cluster runs $version, and every server must run the same version. Upgrade the package first ($how), then run the same line again: the token is used only when the join succeeds."
  fi
  ok "the signalith package ($have) is installed; it is used as it is"
else
  bin=/usr/local/bin/signalith
  tmp=''
  trap 'if [ -n "$tmp" ]; then rm -f "$tmp"; fi' EXIT
  if [ -n "$binary" ]; then
    [ -f "$binary" ] || fail "--binary $binary: there is no such file."
    checksum "$binary" "$binary"
    src=$binary
  elif [ -x "$bin" ] && [ -n "$version" ] && [ "$(version_of "$bin")" = "$version" ]; then
    src=''
  else
    [ -n "$from" ] || fail "There is no Signalith program on this machine. Give one with --binary, or the server to download it from with --from."
    [ -n "$sha256" ] || fail "--sha256 is needed to check the program downloaded from $from."
    command -v curl >/dev/null 2>&1 || fail "This script needs curl to download the program (sudo apt-get install curl, or sudo dnf install curl)."
    tmp=$(mktemp)
    # The certificate is not checked here: the SHA-256 in the line is,
    # which is stronger. Nothing is followed elsewhere.
    code=$(curl -sSk --proto '=https' -o "$tmp" -w '%{http_code}' "$from/api/cluster/join/binary?os=linux&arch=$arch") ||
      fail "Could not reach $from to download the program. Check that this machine can reach it (the web port), then run the same line again."
    if [ "$code" = 404 ]; then
      v=${version:-<version>}
      fail "$from cannot hand out the program for Linux $arch (it runs on another kind of machine). Install the Signalith $v package (https://signalith.io/docs/install-packages/), or download signalith-linux-$arch from https://github.com/jrsamsanchez/Signalith/releases/tag/v$v and run this again with --binary <that file> in place of --sha256."
    fi
    [ "$code" = 200 ] || fail "$from answered $code to the download of the program. Run the same line again; if it keeps failing, see the server's log."
    checksum "$tmp" "The program downloaded from $from"
    src=$tmp
  fi
  if [ -n "$src" ]; then
    if systemctl is-active --quiet signalith 2>/dev/null; then
      say "Stopping the Signalith service to replace its program..."
      systemctl stop signalith
    fi
    install -m 0755 -o root -g root "$src" "$bin"
    ok "installed the program: $bin ($(version_of "$bin"))"
  else
    ok "the program is installed already: $bin ($(version_of "$bin"))"
  fi

  # The account and folders the package's scripts make.
  if ! getent group signalith >/dev/null 2>&1; then
    groupadd --system signalith
  fi
  if ! getent passwd signalith >/dev/null 2>&1; then
    shell=/bin/false
    for s in /usr/sbin/nologin /sbin/nologin; do
      if [ -x "$s" ]; then shell=$s; break; fi
    done
    useradd --system --gid signalith --no-create-home --home-dir /var/lib/signalith \
      --shell "$shell" --comment "Signalith SIEM" signalith
  fi
  install -d -m 0750 -o root -g signalith /etc/signalith
  install -d -m 0750 -o signalith -g signalith /var/lib/signalith
  ok "the signalith account, /etc/signalith and /var/lib/signalith"

  unit=/etc/systemd/system/signalith.service
  cat >"$unit.new" <<'UNIT'
[Unit]
Description=Signalith SIEM server
Documentation=https://github.com/jrsamsanchez/Signalith
After=network-online.target opensearch.service
Wants=network-online.target

[Service]
Type=simple
User=signalith
Group=signalith
# Run as root ("+"), and never stopping the start ("-"): notes next to the
# config file that the built-in admin still has the first password, which
# only root can read, so the server asks for a new one at the next sign-in.
ExecStartPre=-+/usr/local/bin/signalith initial-password -c /etc/signalith/signalith.yaml -note
ExecStart=/usr/local/bin/signalith serve -c /etc/signalith/signalith.yaml
Restart=on-failure
RestartSec=5
# A stop gives the background jobs up to a minute to finish before another
# server takes them over.
TimeoutStopSec=100
# Secrets can live here instead of the config file:
# EnvironmentFile=-/etc/signalith/signalith.env

# The master key that encrypts the passwords and keys Signalith stores is
# /var/lib/signalith/keys/master.key, made by "signalith init" or by the
# server. systemd can hand it to the service instead from a file only root
# can read, away from the service's own folder and from /etc/signalith:
# move the key to /etc/credstore/signalith-master.key and uncomment the next
# line, as docs/encryption.md ("Keeping the key elsewhere") shows step by
# step. It is off by default because the service does not start while that
# file is missing. "signalith secrets" commands run by hand use the same file.
# LoadCredential=master.key:/etc/credstore/signalith-master.key

# Lets the signalith user open the syslog port 514 (ports below 1024 are
# privileged on Linux) and nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Keeps passwords and keys in memory off the disk: new files private by
# default, no core dumps, no swap.
UMask=0077
LimitCORE=0
MemorySwapMax=0

# What the service can see and change: the system and its config
# read-only, its state folder writable, no home folders, its own /tmp, no
# devices, and nothing of the kernel's settings.
ProtectSystem=strict
ReadOnlyPaths=/etc/signalith
ReadWritePaths=/var/lib/signalith
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
# Other users' processes are hidden. (ProcSubset=pid is left out: it hides
# /proc/sys too, and Go then gives each listener a backlog of 128 instead
# of the kernel's somaxconn, which would slow agents reconnecting at once.)
ProtectProc=invisible

# Only the kinds of network it uses (AF_NETLINK lists this computer's
# addresses for the Add data page), and only the system calls of an
# ordinary service.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Custom detections, asset and identity lists, dashboards, retention
# settings, archived days, a master key Signalith makes (keys/) and the
# HTTPS certificate it makes for itself (tls/) are saved here.
StateDirectory=signalith
StateDirectoryMode=0750
# This server's identity (node.id) and its lock (cluster/) are kept here
# too, next to the master key and the HTTPS certificate.
Environment=SIGNALITH_STATE_DIR=/var/lib/signalith
Environment=SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections
Environment=SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups
Environment=SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards
Environment=SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive
# To archive to another disk, point SIGNALITH_ARCHIVE_DIR there and allow it:
# ReadWritePaths=/mnt/archive/signalith
# The archive CLI does not see these variables; give it the folder:
#   sudo -u signalith signalith archive list -c /etc/signalith/signalith.yaml -dir /var/lib/signalith/archive
# The settings, validate and secrets commands read the *_DIR, *_FILE and
# master key settings above, and StateDirectory, from this unit (systemctl
# show signalith) when the service runs with the same config file. Where systemctl cannot be
# asked, give settings and validate the Settings page's file, for example
# to undo a change that locks people out:
#   sudo signalith settings reset -c /etc/signalith/signalith.yaml -file /var/lib/signalith/lookups/settings.yaml server.listen

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$unit.new"
  mv -f "$unit.new" "$unit"
  systemctl daemon-reload
  ok "the systemd unit: $unit"
fi

# The folders the unit gives the service, for the commands run here.
export SIGNALITH_STATE_DIR=/var/lib/signalith
export SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections
export SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups
export SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards
export SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive

if [ -n "$token" ]; then
  # A package install has started the service with its own first
  # settings: it is stopped, and join starts it again as a member.
  if systemctl is-active --quiet signalith 2>/dev/null; then
    systemctl stop signalith
  fi
  say ""
  say "Joining the cluster"
  # The token goes to join on its standard input, never as an argument.
  set -- join - --yes -c "$config"
  [ -z "$name" ] || set -- "$@" --name "$name"
  [ -z "$listen" ] || set -- "$@" --listen "$listen"
  [ -z "$node_url" ] || set -- "$@" --node-url "$node_url"
  status=0
  printf '%s\n' "$token" | "$bin" "$@" || status=$?
  token=''
  case "$status" in
    0) exit 0 ;;
    2 | 3) fail "The join was refused (see above). Nothing was changed on this machine." ;;
    4) fail "This machine is not ready to join (see above). Nothing was changed on it. The token is used up: make a new one on Servers > Add a server once the problem is fixed." ;;
    5) fail "The join could not save its files, so it undid what it wrote (see above)." ;;
    6) fail "The join worked, but the service did not start. See why with: sudo journalctl -u signalith -n 50" ;;
    *) fail "signalith join failed (exit code $status, see above)." ;;
  esac
fi

say ""
if [ -e "$config" ]; then
  systemctl enable --now signalith >/dev/null 2>&1 || fail "The service did not start. See why with: sudo journalctl -u signalith -n 50"
  say "Signalith was set up on this machine before; its service is running."
  exit 0
fi
"$bin" init -c "$config" -save-password >/dev/null
chown -R signalith:signalith /var/lib/signalith
chown root:signalith "$config"
chmod 0640 "$config"
chown root:root /etc/signalith/initial-admin-password
chmod 0600 /etc/signalith/initial-admin-password
systemctl enable --now signalith >/dev/null 2>&1 || fail "Signalith is installed, but its service did not start. See why with: sudo journalctl -u signalith -n 50"
say "Signalith is installed and its service is running."
cat <<'MSG'

  Sign in:   https://<this server>:9000 as admin
  Password:  sudo signalith initial-password
  Agents:    send to port 7779 (Add data sets them up). Open 9000 and 7779
             in this server's firewall for other machines.
  OpenSearch: Signalith expects it at http://127.0.0.1:9200. To use another
             one, change it on the Settings page (OpenSearch > Address).

The browser warns about the certificate until you trust Signalith's own CA:
https://signalith.io/docs/https/
Back up the master key in /var/lib/signalith/keys: https://signalith.io/docs/encryption/
Secure OpenSearch and give Signalith a certificate to sign in with:
https://signalith.io/docs/opensearch-security/

MSG
