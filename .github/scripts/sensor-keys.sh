#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Checks the repository signing keys the sensor install script pins
# (KEY_FPR_* in deploy/sensor/install.sh) against what each publisher
# serves today, so a key a vendor rotates, or a pin left empty, fails CI.
# It prints every fingerprint it fetched; a new or empty pin must still be
# checked against the publisher's own page before it goes into the script
# (docs/network-sensor.md, Signing keys).
set -eu
script=deploy/sensor/install.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0

pin() {
  sed -n "s/^$1=//p" "$script" | tr -d "'\""
}

# fpr prints the primary key fingerprints of the keys in file $1.
fpr() {
  gpg --batch --with-colons --show-keys "$1" 2>/dev/null | awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; p = 0 }'
}

check() {
  name=$1 var=$2 got=$3
  want=$(pin "$var")
  printf '%s (%s)\n  pinned:    %s\n  published: %s\n' "$name" "$var" "${want:-<empty>}" "${got:-<none>}"
  if [ -z "$got" ]; then
    echo "  ✗ could not download the publisher's key"
    failed=1
  elif [ -z "$want" ]; then
    echo "  ✗ not pinned yet"
    failed=1
  elif printf '%s\n' "$got" | grep -qx "$want"; then
    echo "  ✓ matches"
  else
    echo "  ✗ does not match: the publisher changed its key"
    failed=1
  fi
}

key() {
  curl -fsSL --retry 3 -o "$tmp/$1" "$2"
  fpr "$tmp/$1"
}

check "Fluent Bit (packages.fluentbit.io)" KEY_FPR_FLUENTBIT "$(key fluentbit https://packages.fluentbit.io/fluentbit.key)"
check "Zeek (openSUSE Build Service, security:zeek)" KEY_FPR_ZEEK_OBS \
  "$(key zeek 'https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key')"
# Launchpad says which key signs the PPA, independently of a key server.
check "Suricata (OISF PPA)" KEY_FPR_OISF_PPA \
  "$(curl -fsSL --retry 3 https://api.launchpad.net/1.0/~oisf/+archive/ubuntu/suricata-stable | jq -r .signing_key_fingerprint)"
check "Suricata (OISF COPR)" KEY_FPR_OISF_COPR \
  "$(key copr 'https://download.copr.fedorainfracloud.org/results/@oisf/suricata-8.0/pubkey.gpg')"
exit "$failed"
