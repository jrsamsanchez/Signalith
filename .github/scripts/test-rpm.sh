#!/bin/sh
# Installs, upgrades and removes Signalith's .rpm in Rocky Linux 9 and
# Fedora containers (no systemd there, so the service is not started).
#   test-rpm.sh PREVIOUS.rpm NEW.rpm NEW_VERSION
set -eu
dir=$(cd "$(dirname "$1")" && pwd)
prev=$(basename "$1"); new=$(basename "$2"); want=$3
[ "$(cd "$(dirname "$2")" && pwd)" = "$dir" ] || { echo "both packages must be in one folder"; exit 1; }
for image in rockylinux:9 fedora:42; do
  echo "== $image"
  docker run --rm -v "$dir:/p:ro" "$image" sh -euc "
    rpm -i /p/$prev > /tmp/install.txt
    grep -q 'sudo signalith initial-password' /tmp/install.txt
    id signalith
    password=\$(signalith initial-password)
    test -n \"\$password\"
    if grep -qF \"\$password\" /tmp/install.txt; then echo 'the password was printed'; exit 1; fi
    test \"\$(stat -c %U /var/lib/signalith/keys/master.key)\" = signalith
    test \"\$(stat -c %U:%a /etc/signalith/initial-admin-password)\" = root:600
    signalith validate -c /etc/signalith/signalith.yaml
    rpm -U /p/$new
    signalith version | grep -F '$want'
    test \"\$(signalith initial-password)\" = \"\$password\"
    rpm -e signalith
    test ! -e /usr/bin/signalith
    test -f /etc/signalith/signalith.yaml
    test -f /var/lib/signalith/.package-removed
    rpm -i /p/$new
    test ! -e /var/lib/signalith/.package-removed
    test \"\$(signalith initial-password)\" = \"\$password\"
  "
done
echo "The .rpm installs, upgrades and removes cleanly."
