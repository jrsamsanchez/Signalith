#!/bin/sh
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Prepares the capture port named on the command line, for
# signalith-sensor-capture.service: up and listening to every packet
# (promiscuous), never answering (no ARP, no IPv6), and without the
# network card offloads that merge packets before Zeek and Suricata see
# them. Offloads a card does not have are skipped.
set -u
iface=${1:-}
case "$iface" in
  '' | *[!A-Za-z0-9_.:-]*)
    echo "capture-up: no capture port named (or a name with odd characters)" >&2
    exit 1
    ;;
esac
ip link set dev "$iface" up promisc on arp off
if [ -w "/proc/sys/net/ipv6/conf/$iface/disable_ipv6" ]; then
  echo 1 >"/proc/sys/net/ipv6/conf/$iface/disable_ipv6"
fi
if command -v ethtool >/dev/null 2>&1; then
  for feature in gro lro gso tso rx-gro-hw; do
    ethtool -K "$iface" "$feature" off >/dev/null 2>&1 || true
  done
fi
exit 0
