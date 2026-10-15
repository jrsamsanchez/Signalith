#!/bin/bash
# Builds the Signalith test lab. Terraform puts this script on signalith-1,
# and lab-setup.service runs it once after the first boot, writing to
# /var/log/lab-setup.log. From signalith-1 it reaches every other machine
# over the private network with the lab's own SSH key.
#
# Each step leaves a mark in /root/lab/done when it finishes, so running
# "sudo lab-setup" again carries on from the step that failed.
#
# What it sets up (docs/cloud-lab.md):
#   1. builds Signalith from the repository at the branch Terraform names;
#   2. OpenSearch on opensearch-1..3 with certificates of its own CA;
#   3. signalith-1, pointed at OpenSearch, and the CA handed to the cluster;
#   4. signalith-2 and the scanner, joined with join tokens;
#   5. OpenVAS on the scanner;
#   6. Fluent Bit on the Linux endpoints;
#   7. the network sensor, fed by a copy of the endpoints' traffic.
set -euo pipefail
umask 077
export HOME=/root
export DEBIAN_FRONTEND=noninteractive

LAB=/root/lab
DONE=$LAB/done
mkdir -p "$DONE"

conf() { jq -r "$1" "$LAB/lab.json"; }
SIZE=$(conf .size)
REF=$(conf .ref)
OPENVAS=$(conf .openvas)
DOMAIN=$(conf .domain)
SIEM=$(conf .siem)
LB_IP=$(conf .lb_ip)
SIEM_URL="https://$SIEM:8080"
OPENSEARCH_VERSION=2.17.1
BIN=/usr/local/bin/signalith

ip_of() { conf ".machines[] | select(.name == \"$1\") | .ip"; }
names() { conf ".machines[] | select(.role == \"$1\") | .name"; }
have() { [ -n "$(ip_of "$1")" ]; }

say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() {
  say "FAILED: $*"
  say "Fix the cause, then run: sudo lab-setup"
  exit 1
}
trap 'say "FAILED at line $LINENO. Run sudo lab-setup again to carry on."' ERR

# step runs a step once: a step that finished before is skipped.
step() {
  local name=$1
  shift
  if [ -e "$DONE/$name" ]; then
    say "  done before: $name"
    return
  fi
  say "Starting: $name"
  "$@"
  touch "$DONE/$name"
  say "Done: $name"
}

SSH=(ssh -i "$LAB/id_lab" -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$LAB/known_hosts" -o LogLevel=ERROR)

# on runs a command on another machine of the lab, as root.
on() {
  local host=$1
  shift
  "${SSH[@]}" "root@$(ip_of "$host")" "$@"
}

# script runs the standard input as a bash script on another machine, with
# the NAME=value arguments set first.
script() {
  local host=$1
  shift
  local vars=''
  for v in "$@"; do vars+="$(printf '%q ' "$v")"; done
  on "$host" "env $vars bash -s"
}

# sg runs signalith as the account its service runs as, with the
# service's folders (as deploy/linux/install.sh does).
sg() {
  sudo -u signalith env SIGNALITH_STATE_DIR=/var/lib/signalith \
    SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \
    SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups \
    SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards \
    SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive \
    "$BIN" "$@"
}

# retry runs a command until it succeeds, every 10 seconds, at most $1
# times.
retry() {
  local tries=$1
  shift
  local i
  for ((i = 1; i <= tries; i++)); do
    if "$@"; then return 0; fi
    sleep 10
  done
  return 1
}

# api calls Signalith's API on signalith-1, signed in as the built-in
# admin (as the Add data page would).
api() {
  local ca=/var/lib/signalith/tls/ca.pem jar=$LAB/cookies
  curl -fsS -c "$jar" --cacert "$ca" -H 'Content-Type: application/json' -H 'Origin: https://localhost:8080' \
    -d "$(jq -n --rawfile p /etc/signalith/initial-admin-password '{username: "admin", password: ($p | rtrimstr("\n"))}')" \
    https://localhost:8080/api/login >/dev/null
  curl -fsS -b "$jar" --cacert "$ca" -H 'Origin: https://localhost:8080' "https://localhost:8080$1"
  rm -f "$jar"
}

others() { conf '.machines[] | select(.name != "signalith-1") | .name'; }

# ---- 0. the other machines ----

ready() { on "$1" 'cloud-init status --wait >/dev/null 2>&1; [ $? -le 2 ]'; }

wait_machines() {
  for m in $(others); do
    retry 90 ready "$m" || fail "$m did not finish starting (cloud-init). Check it in the Hetzner Console."
    say "  $m is up"
  done
}

# ---- 1. build Signalith ----

build() {
  mkdir -p "$LAB/src"
  cd "$LAB/src"
  [ -d .git ] || git init -q
  git fetch -q --depth 1 https://github.com/jrsamsanchez/Signalith.git "$REF"
  git checkout -q --force FETCH_HEAD
  local gov arch sha
  gov=$(awk '$1 == "go" { print $2 }' go.mod)
  arch=$(dpkg --print-architecture)
  if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$gov "; then
    rm -rf /usr/local/go
    curl -fsSL "https://go.dev/dl/go$gov.linux-$arch.tar.gz" | tar -C /usr/local -xz
  fi
  sha=$(git rev-parse --short=7 HEAD)
  CGO_ENABLED=0 /usr/local/go/bin/go build -trimpath -ldflags "-s -w -X main.version=0.0.0-lab-$sha" \
    -o "$LAB/signalith" ./cmd/signalith
  say "  built Signalith 0.0.0-lab-$sha from $REF"
}

# ---- 2. OpenSearch ----

opensearch_certs() {
  cd "$LAB"
  rm -rf pki
  local nodes=() n peers
  mapfile -t nodes < <(names opensearch)
  for n in "${nodes[@]}"; do
    peers=()
    for p in "${nodes[@]}"; do [ "$p" = "$n" ] || peers+=(-peer "$p"); done
    if [ "$n" = opensearch-1 ]; then
      "$LAB/signalith" opensearch-certs -out "pki/$n" -node "$n" -san "$n.$DOMAIN" -san "$(ip_of "$n")" "${peers[@]}" >/dev/null
    else
      "$LAB/signalith" opensearch-certs -ca-dir pki/opensearch-1/ca -out "pki/$n" -node "$n" -san "$n.$DOMAIN" -san "$(ip_of "$n")" "${peers[@]}" >/dev/null
    fi
  done
}

opensearch_install() {
  local nodes=() n seeds managers discovery
  mapfile -t nodes < <(names opensearch)
  if [ "${#nodes[@]}" -gt 1 ]; then
    seeds=$(printf '"%s", ' "${nodes[@]}")
    managers=$seeds
    discovery="discovery.seed_hosts: [${seeds%, }]
cluster.initial_cluster_manager_nodes: [${managers%, }]"
  else
    discovery="discovery.type: single-node"
  fi
  for n in "${nodes[@]}"; do
    say "  $n"
    tar -C "$LAB/pki/$n/opensearch" -cz . | on "$n" 'rm -rf /root/opensearch-pki && mkdir -p /root/opensearch-pki && tar -C /root/opensearch-pki -xz'
    script "$n" NAME="$n" IP="$(ip_of "$n")" VERSION="$OPENSEARCH_VERSION" DISCOVERY="$discovery" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! dpkg -s opensearch >/dev/null 2>&1; then
  curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp | gpg --dearmor --batch --yes -o /usr/share/keyrings/opensearch-keyring
  echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" >/etc/apt/sources.list.d/opensearch-2.x.list
  apt-get update -q
  # No demo security settings: the lab's own are put in place below. The
  # package still asks for a demo admin password, which is never used.
  DISABLE_INSTALL_DEMO_CONFIG=true OPENSEARCH_INITIAL_ADMIN_PASSWORD="Lab-$(openssl rand -hex 16)" \
    apt-get install -y -q "opensearch=$VERSION"
fi
systemctl stop opensearch 2>/dev/null || true
rm -rf /etc/opensearch/certs
cp -r /root/opensearch-pki/certs /etc/opensearch/certs
chown -R opensearch:opensearch /etc/opensearch/certs
chmod 700 /etc/opensearch/certs
chmod 600 /etc/opensearch/certs/*
install -d -o opensearch -g opensearch /etc/opensearch/opensearch-security
install -m 600 -o opensearch -g opensearch /root/opensearch-pki/opensearch-security/*.yml /etc/opensearch/opensearch-security/
cat >/etc/opensearch/opensearch.yml <<YML
cluster.name: signalith-lab
node.name: $NAME
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
network.host: ["_local_", "$IP"]
$DISCOVERY

YML
cat /root/opensearch-pki/add-to-opensearch.yml >>/etc/opensearch/opensearch.yml
# Half the memory for the heap.
heap=$(awk '/MemTotal/ { print int($2 / 1024 / 2) }' /proc/meminfo)
[ "$heap" -ge 512 ] || heap=512
mkdir -p /etc/opensearch/jvm.options.d
printf -- '-Xms%sm\n-Xmx%sm\n' "$heap" "$heap" >/etc/opensearch/jvm.options.d/lab-heap.options
sysctl -q -w vm.max_map_count=262144
echo vm.max_map_count=262144 >/etc/sysctl.d/90-opensearch.conf
rm -rf /root/opensearch-pki
systemctl enable -q opensearch
systemctl restart opensearch
EOF
  done
}

# os_admin asks OpenSearch with the admin certificate, which stays on
# signalith-1.
os_admin() {
  local c=$LAB/pki/opensearch-1/opensearch/certs
  curl -fsS --cacert "$c/root-ca.pem" --cert "$c/admin.pem" --key "$c/admin-key.pem" \
    --resolve "opensearch-1:9200:$(ip_of opensearch-1)" "https://opensearch-1:9200$1"
}

cluster_formed() {
  local want
  want=$(names opensearch | wc -l)
  os_admin '/_cluster/health' 2>/dev/null | jq -e --argjson n "$want" '.number_of_nodes == $n and .status != "red"' >/dev/null
}

opensearch_security() {
  retry 60 cluster_formed || fail "OpenSearch did not form a cluster. On each opensearch machine: journalctl -u opensearch -n 50"
  # A new OpenSearch loads the security settings by itself on its first
  # start; loading them again does no harm, and covers a slow first start.
  on opensearch-1 'OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk bash /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/opensearch/opensearch-security/ -cacert /etc/opensearch/certs/root-ca.pem -cert /etc/opensearch/certs/admin.pem -key /etc/opensearch/certs/admin-key.pem -h localhost -icl -nhnv' >/dev/null
  # The admin certificate is only needed for that: keep it off OpenSearch.
  on opensearch-1 'rm -f /etc/opensearch/certs/admin.pem /etc/opensearch/certs/admin-key.pem'
  say "  $(os_admin '/_cluster/health' | jq -r '"cluster \(.cluster_name): \(.status), \(.number_of_nodes) nodes"')"
}

# ---- 3. signalith-1 ----

# edit_config changes signalith.yaml with the lab's settings, in Python
# (cloud images have PyYAML) so the YAML stays valid.
edit_config() {
  local urls=() n
  for n in $(names opensearch); do [ "$n" = opensearch-1 ] || urls+=("https://$n:9200"); done
  python3 - /etc/signalith/signalith.yaml "$SIEM_URL" "https://signalith-1.$DOMAIN:8080" "$SIEM" "$LB_IP" "${urls[@]}" <<'EOF'
import sys, yaml
path, public, node, siem, lb, *urls = sys.argv[1:]
with open(path) as f:
    c = yaml.safe_load(f)
s = c.setdefault("server", {})
s["public_url"] = public
s["node_url"] = node
tls = s.setdefault("tls", {})
tls["names"] = sorted(set(tls.get("names") or []) | {siem, node.split("//")[1].split(":")[0]})
if lb:
    s["trusted_proxies"] = [lb]
    s["proxy_protocol"] = True
o = c.setdefault("opensearch", {})
o["url"] = "https://opensearch-1:9200"
if urls:
    o["urls"] = urls
o["ca_file"] = "/etc/signalith/opensearch-ca.pem"
o["cert_file"] = "/etc/signalith/opensearch-client.pem"
o["key_file"] = "/etc/signalith/opensearch-client-key.pem"
o.pop("username", None)
o.pop("password", None)
with open(path, "w") as f:
    f.write("# Written by the lab setup (deploy/lab/lab-setup.sh).\n")
    yaml.safe_dump(c, f, sort_keys=False, default_flow_style=False)
EOF
}

readyz() { curl -fsSk -o /dev/null https://127.0.0.1:8080/readyz; }

signalith_first() {
  sh "$LAB/src/deploy/linux/install.sh" --binary "$LAB/signalith"
  systemctl stop signalith
  install -m 400 -o signalith -g signalith "$LAB"/pki/opensearch-1/signalith/opensearch-*.pem /etc/signalith/
  edit_config
  # The first start made a certificate before the lab's names were set:
  # make it again with them.
  rm -rf /var/lib/signalith/tls
  systemctl start signalith
  retry 60 readyz || fail "Signalith did not get ready. See: journalctl -u signalith -n 50"
  sg validate >/dev/null || fail "signalith validate found a problem (run it to see)."
}

cluster_ready() { sg cluster status -json 2>/dev/null | jq -e '(.shared.cluster_id // "") != ""' >/dev/null; }

opensearch_ca() {
  retry 60 cluster_ready || fail "signalith-1 did not make its cluster. See: sudo -u signalith signalith cluster status"
  local d=/var/lib/signalith/lab-ca
  install -d -m 700 -o signalith -g signalith "$d"
  install -m 600 -o signalith -g signalith "$LAB"/pki/opensearch-1/ca/root-ca.pem "$LAB"/pki/opensearch-1/ca/root-ca-key.pem "$d/"
  sg cluster opensearch-ca import "$d/root-ca-key.pem"
  rm -rf "$d"
}

# ---- 4. joined servers ----

join() {
  local name=$1 role=${2:-} out line
  local args=(cluster token -json -platform linux -note "lab" -url "https://signalith-1.$DOMAIN:8080"
    -node-url "https://$name.$DOMAIN:8080")
  [ -z "$role" ] || args+=(-role "$role")
  out=$(sg "${args[@]}")
  line="$(jq -r .commands.linux <<<"$out") --name $name --node-url https://$name.$DOMAIN:8080"
  on "$name" "bash -c $(printf '%q' "$line")"
  if [ "$role" = scanner ]; then
    on "$name" 'DEBIAN_FRONTEND=noninteractive apt-get install -y -q nmap >/dev/null && systemctl restart signalith'
  fi
  if [ -n "$LB_IP" ] && [ "$role" != scanner ]; then
    # Read the PROXY protocol header the load balancer sends.
    on "$name" 'mkdir -p /etc/systemd/system/signalith.service.d && printf "[Service]\nEnvironment=SIGNALITH_PROXY_PROTOCOL=true\n" >/etc/systemd/system/signalith.service.d/lab.conf && systemctl daemon-reload && systemctl restart signalith'
  fi
}

# ---- 5. OpenVAS ----

openvas() {
  local pw
  pw=$(openssl rand -hex 24)
  script scanner PW="$pw" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q docker.io docker-compose-v2 acl nmap >/dev/null
mkdir -p /opt/greenbone /srv/gvmd-socket
cd /opt/greenbone
curl -fsSL https://greenbone.github.io/docs/latest/_static/docker-compose.yml -o docker-compose.yml
# gvmd's socket in a folder of this machine, where Signalith can reach it.
cat >docker-compose.override.yml <<'YML'
volumes:
  gvmd_socket_vol:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /srv/gvmd-socket
YML
docker compose -p greenbone-community-edition up -d --quiet-pull
for i in $(seq 1 90); do
  docker compose -p greenbone-community-edition exec -T -u gvmd gvmd gvmd --get-users >/dev/null 2>&1 && break
  sleep 10
done
if ! docker compose -p greenbone-community-edition exec -T -u gvmd gvmd gvmd --get-users | grep -qx signalith; then
  docker compose -p greenbone-community-edition exec -T -u gvmd gvmd gvmd --create-user=signalith --password="$PW" >/dev/null
fi
# Signalith's account may use the socket, now and when gvmd makes it again.
setfacl -m u:signalith:rwx /srv/gvmd-socket
setfacl -d -m u:signalith:rwx /srv/gvmd-socket
[ ! -S /srv/gvmd-socket/gvmd.sock ] || setfacl -m u:signalith:rw /srv/gvmd-socket/gvmd.sock
install -m 400 -o signalith -g signalith /dev/null /etc/signalith/openvas-password
printf '%s' "$PW" >/etc/signalith/openvas-password
mkdir -p /etc/systemd/system/signalith.service.d
cat >/etc/systemd/system/signalith.service.d/openvas.conf <<'UNIT'
[Service]
Environment=SIGNALITH_OPENVAS_ADDRESS=/srv/gvmd-socket/gvmd.sock
Environment=SIGNALITH_OPENVAS_USERNAME=signalith
Environment=SIGNALITH_OPENVAS_PASSWORD_FILE=/etc/signalith/openvas-password
UNIT
systemctl daemon-reload
systemctl restart signalith
EOF
}

# ---- 6. Linux endpoints ----

endpoints() {
  local token cfg
  token=$(sg tokens create -purpose linux "Lab Linux endpoints")
  cfg=$(api "/api/agents/config?os=linux&server=$SIEM_URL")
  for m in $(names linux); do
    say "  $m"
    jq -r .config <<<"$cfg" | sed "s/$(jq -r .token_placeholder <<<"$cfg")/$token/g" |
      on "$m" 'mkdir -p /etc/fluent-bit && cat >/root/fluent-bit.conf'
    jq -r .ca <<<"$cfg" | on "$m" 'cat >/root/signalith-ca.pem'
    script "$m" CONFIG="$(jq -r .config_path <<<"$cfg")" CA="$(jq -r .ca_path <<<"$cfg")" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
curl -fsSL https://packages.fluentbit.io/fluentbit.key | gpg --dearmor --batch --yes -o /usr/share/keyrings/fluentbit-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/ubuntu/$VERSION_CODENAME $VERSION_CODENAME main" >/etc/apt/sources.list.d/fluent-bit.list
apt-get update -q >/dev/null
apt-get install -y -q fluent-bit auditd >/dev/null
install -D -m 600 /root/fluent-bit.conf "$CONFIG"
install -D -m 644 /root/signalith-ca.pem "$CA"
rm -f /root/fluent-bit.conf /root/signalith-ca.pem
# The audit log rules of the detection packs read the programs that run.
echo '-a always,exit -F arch=b64 -S execve -k exec' >/etc/audit/rules.d/signalith.rules
augenrules --load >/dev/null 2>&1 || true
systemctl enable -q --now fluent-bit
systemctl restart fluent-bit
EOF
  done
}

# ---- 7. network sensor ----

# A cloud network has no mirror port, so each endpoint sends a copy of the
# traffic on its public port to the sensor in VXLAN, and the sensor
# captures it on capture0, a port with no address, as it would a mirror
# port.
mirror() {
  local sensor_ip
  sensor_ip=$(ip_of sensor)
  script sensor IP="$sensor_ip" <<'EOF'
set -euo pipefail
cat >/usr/local/sbin/lab-capture <<SH
#!/bin/sh
ip link show capture0 >/dev/null 2>&1 || ip link add capture0 type vxlan id 42 dstport 4789 local $IP nolearning
ip link set capture0 mtu 1500 up promisc on
SH
chmod 755 /usr/local/sbin/lab-capture
cat >/etc/systemd/system/lab-capture.service <<'UNIT'
[Unit]
Description=Signalith lab: capture port for the endpoints' mirrored traffic
After=network-online.target
Wants=network-online.target
Before=zeek.service suricata.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/lab-capture

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable -q --now lab-capture
EOF
  for m in $(names linux); do
    script "$m" IP="$(ip_of "$m")" SENSOR="$sensor_ip" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q ethtool >/dev/null
cat >/usr/local/sbin/lab-mirror <<SH
#!/bin/sh
# Copies every packet in and out of eth0 to the sensor.
ip link show mirror0 >/dev/null 2>&1 || ip link add mirror0 type vxlan id 42 dstport 4789 remote $SENSOR local $IP
ip link set mirror0 mtu 1500 up
ethtool -K eth0 gro off gso off tso off >/dev/null 2>&1 || true
tc qdisc replace dev eth0 clsact
tc filter replace dev eth0 ingress pref 1 matchall action mirred egress mirror dev mirror0
tc filter replace dev eth0 egress pref 1 matchall action mirred egress mirror dev mirror0
SH
chmod 755 /usr/local/sbin/lab-mirror
cat >/etc/systemd/system/lab-mirror.service <<'UNIT'
[Unit]
Description=Signalith lab: copy this machine's traffic to the network sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/lab-mirror

[Install]
WantedBy=multi-user.target
UNIT
# Some traffic for the sensor to see: web requests, look-ups, and the
# test page that Suricata's rules flag (testmynids.org).
cat >/usr/local/sbin/lab-traffic <<'SH'
#!/bin/sh
curl -s -o /dev/null http://testmynids.org/uid/index.html
curl -s -o /dev/null https://example.com/
curl -s -o /dev/null http://neverssl.com/
getent hosts signalith.io >/dev/null
SH
chmod 755 /usr/local/sbin/lab-traffic
cat >/etc/systemd/system/lab-traffic.service <<'UNIT'
[Unit]
Description=Signalith lab: some web traffic for the network sensor

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lab-traffic
UNIT
cat >/etc/systemd/system/lab-traffic.timer <<'UNIT'
[Unit]
Description=Signalith lab: some web traffic for the network sensor every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable -q --now lab-mirror lab-traffic.timer
EOF
  done
}

sensor() {
  local token out line
  token=$(sg tokens create -purpose sensor "Lab sensor")
  out=$(api "/api/sensor/install?server=$SIEM_URL&interface=capture0")
  line=$(jq -r .linux <<<"$out")
  line=${line//"$(jq -r .token_placeholder <<<"$out")"/$token}
  on sensor "bash -c $(printf '%q' "$line --name sensor")"
}

# ---- run ----

say "Signalith lab setup: $SIZE lab, Signalith $REF"
step machines wait_machines
step build build
step opensearch-certs opensearch_certs
step opensearch-install opensearch_install
step opensearch-security opensearch_security
step signalith-1 signalith_first
step opensearch-ca opensearch_ca
if have signalith-2; then step signalith-2 join signalith-2; fi
if have scanner; then step scanner join scanner scanner; fi
if have scanner && [ "$OPENVAS" = true ]; then step openvas openvas; fi
step endpoints endpoints
if have sensor; then
  step mirror mirror
  step sensor sensor
fi

public=$(curl -fsS -4 --max-time 5 https://ipv4.icanhazip.com 2>/dev/null || echo '<signalith-1 address>')
say "Lab ready."
cat <<MSG

  Signalith:  https://$public:8080
  User:       admin
  Password:   sudo cat /etc/signalith/initial-admin-password  (on signalith-1)

  Agents and the sensor send to $SIEM_URL$([ -n "$LB_IP" ] && echo " (the load balancer)").
  The rest is by hand: see "After the setup" in docs/cloud-lab.md
  (Windows, the scan networks, single sign-on).

MSG
