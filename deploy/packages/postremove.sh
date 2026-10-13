#!/bin/sh
# The config (/etc/signalith) and the state folder with the master key,
# certificates and settings (/var/lib/signalith) are kept, so reinstalling
# picks up where it left off. Delete them by hand to remove everything;
# events stay in OpenSearch.
set -e
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
case "$1" in
  remove|purge|0)
    # Tells postinstall.sh, if the package is installed again, to start
    # the service the removal stopped.
    if [ -d /var/lib/signalith ]; then : > /var/lib/signalith/.package-removed; fi
    echo "Signalith was removed. Its config (/etc/signalith) and data (/var/lib/signalith) were kept." ;;
esac
exit 0
