#!/bin/sh
# Installs Signalith from the apt and dnf repositories at URL in Ubuntu,
# Debian, Rocky Linux and Fedora containers, with every signature checked,
# and checks the installed version.
#   install-from-repos.sh URL VERSION
set -eu
url=${1%/}; want=$2

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
