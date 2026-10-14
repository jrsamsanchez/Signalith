#!/bin/sh
# Builds the apt and dnf repositories from PKGDIR with a throwaway signing
# key, serves them on this machine, and installs Signalith from them in
# Ubuntu, Debian, Rocky Linux and Fedora containers, with every signature
# checked.
#   test-repos.sh PKGDIR VERSION
set -eu
pkgs=$(cd "$1" && pwd); want=$2
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
port=8765
url=http://127.0.0.1:$port
cleanup() { [ -z "${server:-}" ] || kill "$server" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

# A key with a passphrase, to test that path too.
export GNUPGHOME=$tmp/gnupg SIGNALITH_GPG_PASSPHRASE=test-passphrase
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase "$SIGNALITH_GPG_PASSPHRASE" \
  --quick-gen-key 'Signalith test <test@signalith.invalid>' rsa3072 sign 1d
"$root/deploy/repos/build.sh" "$pkgs" "$tmp/site" "$url"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$tmp/site" >/dev/null 2>&1 &
server=$!
for i in $(seq 1 20); do curl -sf -o /dev/null "$url/apt/signalith.asc" && break; sleep 0.5; done

# The commands docs/install-packages.md gives, with the test address.
for image in ubuntu:24.04 debian:12; do
  echo "== apt on $image"
  docker run --rm --network host "$image" sh -euc "
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates > /dev/null
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL -o /etc/apt/keyrings/signalith.asc $url/apt/signalith.asc
    echo 'deb [signed-by=/etc/apt/keyrings/signalith.asc] $url/apt stable main' > /etc/apt/sources.list.d/signalith.list
    apt-get update 2>&1 | tee /tmp/update.txt
    if grep -E '^(W|E):' /tmp/update.txt | grep -qF '$url'; then echo 'apt warned about the repository'; exit 1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y signalith
    signalith version | grep -F '$want'
  "
done
for image in rockylinux:9 fedora:42; do
  echo "== dnf on $image"
  docker run --rm --network host "$image" sh -euc "
    curl -fsSL -o /etc/yum.repos.d/signalith.repo $url/rpm/signalith.repo
    grep -qx 'gpgcheck=1' /etc/yum.repos.d/signalith.repo
    grep -qx 'repo_gpgcheck=1' /etc/yum.repos.d/signalith.repo
    dnf install -y --disablerepo='*' --enablerepo=signalith signalith
    signalith version | grep -F '$want'
  "
done
echo "Signalith installs from the signed apt and dnf repositories."
