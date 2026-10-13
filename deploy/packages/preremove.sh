#!/bin/sh
# Stops and disables the service when the package is removed, not when it
# is upgraded (dpkg: "remove"; rpm: 0 packages left).
set -e
case "$1" in
  remove|0)
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now signalith >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
