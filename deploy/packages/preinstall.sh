#!/bin/sh
# Signalith runs as its own system account, signalith, which owns its
# config and state folders. Made once; an upgrade keeps it.
set -e
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
exit 0
