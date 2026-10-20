#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
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
