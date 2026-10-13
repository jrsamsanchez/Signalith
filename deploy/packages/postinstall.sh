#!/bin/sh
# After the files are in place. A first install writes a starter config
# (HTTPS on, a generated admin password kept for "signalith
# initial-password", syslog on 514 and 6514) and starts the service; an
# upgrade encrypts passwords an older version kept as plain text and
# restarts the service if it was running.
#
# dpkg calls this with "configure <old version>" (empty on a first install);
# rpm with 1 for a first install and 2 for an upgrade.
set -e
config=/etc/signalith/signalith.yaml
upgrade=no
case "$1" in
  configure) [ -n "$2" ] && upgrade=yes ;;
  2) upgrade=yes ;;
esac

systemd=no
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemd=yes
  systemctl daemon-reload || true
fi

# The same folders the unit gives the service, for commands run here.
export SIGNALITH_STATE_DIR=/var/lib/signalith
export SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections
export SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups
export SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards
export SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive

if [ ! -e "$config" ]; then
  install -d -m 0750 -o root -g signalith /etc/signalith
  install -d -m 0750 -o signalith -g signalith /var/lib/signalith
  /usr/bin/signalith init -c "$config" -save-password > /dev/null
  # The service reads its config and may change only what is in
  # /var/lib/signalith; the first password stays root's.
  chown -R signalith:signalith /var/lib/signalith
  chown root:signalith "$config"
  chmod 0640 "$config"
  chown root:root /etc/signalith/initial-admin-password
  chmod 0600 /etc/signalith/initial-admin-password
  started="Signalith is installed. Start it with: sudo systemctl enable --now signalith"
  if [ "$systemd" = yes ]; then
    systemctl enable signalith >/dev/null 2>&1 || true
    if systemctl start signalith; then
      started="Signalith is installed and its service is running."
    fi
  fi
  printf '\n%s\n' "$started"
  cat <<'MSG'

  Sign in:   https://<this server>:8080 as admin
  Password:  sudo signalith initial-password
  OpenSearch: Signalith expects it at http://127.0.0.1:9200. To use another
             one, change it on the Settings page (OpenSearch > Address).

The browser warns about the certificate until you trust Signalith's own CA:
https://signalith.io/docs/https/
Back up the master key in /var/lib/signalith/keys: https://signalith.io/docs/encryption/
Secure OpenSearch and give Signalith a certificate to sign in with:
https://signalith.io/docs/opensearch-security/

MSG
elif [ "$upgrade" = yes ]; then
  /usr/bin/signalith secrets encrypt -c "$config" || echo "Some passwords or keys could not be encrypted; check with: sudo signalith secrets status" >&2
  if [ "$systemd" = yes ]; then
    systemctl try-restart signalith || true
  fi
fi
exit 0
