#!/bin/sh
# Runs deploy/linux/install.sh in a fresh Linux container, as root, with
# the program built from this commit (bin/signalith), and checks what it
# made. systemd does not run in the container, so systemctl is a stand-in
# that notes each call. Run from the repository's folder:
#   docker run --rm -v "$PWD:/work" -w /work debian:13 sh .github/scripts/test-install-sh.sh
set -eu
script=deploy/linux/install.sh
program=bin/signalith

mkdir -p /run/systemd/system
cat >/usr/local/sbin/systemctl <<'STUB'
#!/bin/sh
echo "$*" >>/tmp/systemctl.log
case "$1" in is-active) exit 3 ;; esac
exit 0
STUB
chmod 0755 /usr/local/sbin/systemctl
: >/tmp/systemctl.log

fail() { echo "FAIL: $*" >&2; exit 1; }

# A program that is not the one the line names is refused, and nothing
# is installed.
if out=$(sh "$script" --binary "$program" --sha256 "$(printf '0%.0s' $(seq 64))" 2>&1); then
  fail "a wrong --sha256 was accepted: $out"
fi
echo "$out" | grep -q "does not have the SHA-256" || fail "wrong --sha256: $out"
[ ! -e /usr/local/bin/signalith ] || fail "the program was installed after a wrong --sha256"

# A token that isn't one is refused before anything is done.
if out=$(sh "$script" --binary "$program" --join 'not-a-token' 2>&1); then
  fail "a bad token was accepted"
fi
echo "$out" | grep -q "not a Signalith join token" || fail "bad token: $out"

# A first server: the program, the account, the folders, the unit, the
# config, and the service turned on.
sum=$(sha256sum "$program" | awk '{print $1}')
sh "$script" --binary "$program" --sha256 "$sum" || fail "install failed"
cmp -s "$program" /usr/local/bin/signalith || fail "the program in /usr/local/bin differs"
id signalith >/dev/null || fail "no signalith account"
[ "$(stat -c '%U:%G %a' /etc/signalith)" = "root:signalith 750" ] || fail "/etc/signalith is $(stat -c '%U:%G %a' /etc/signalith)"
[ "$(stat -c '%U:%G %a' /var/lib/signalith)" = "signalith:signalith 750" ] || fail "/var/lib/signalith is $(stat -c '%U:%G %a' /var/lib/signalith)"
[ "$(stat -c '%U:%G %a' /etc/signalith/signalith.yaml)" = "root:signalith 640" ] || fail "signalith.yaml is $(stat -c '%U:%G %a' /etc/signalith/signalith.yaml)"
[ "$(stat -c '%U %a' /etc/signalith/initial-admin-password)" = "root 600" ] || fail "the first password file is $(stat -c '%U %a' /etc/signalith/initial-admin-password)"
cmp -s deploy/systemd/signalith.service /etc/systemd/system/signalith.service || fail "the unit differs from deploy/systemd/signalith.service"
grep -qx "enable --now signalith" /tmp/systemctl.log || fail "the service was not turned on: $(cat /tmp/systemctl.log)"
/usr/local/bin/signalith validate -c /etc/signalith/signalith.yaml >/dev/null || fail "the config does not validate"

# Run again: nothing is made twice.
out=$(sh "$script" --binary "$program" --sha256 "$sum" 2>&1) || fail "second run failed: $out"
echo "$out" | grep -q "set up on this machine before" || fail "second run: $out"

echo "install.sh works on $(. /etc/os-release && echo "$PRETTY_NAME")"
