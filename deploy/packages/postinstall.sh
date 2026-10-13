#!/bin/sh
# After the files are in place. A first install writes a starter config
# (HTTPS on, a generated admin password kept for "signalith
# initial-password", syslog on 514 and 6514) and starts the service.
# With a config already there (an upgrade, or installing again after a
# removal), passwords an older version kept as plain text are encrypted
# and the service is restarted if it was running, or started again if the
# removal had stopped it.
set -e
config=/etc/signalith/signalith.yaml
# Left by postremove.sh when the package was removed.
removed=/var/lib/signalith/.package-removed

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
  rm -f "$removed"
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
else
  /usr/bin/signalith secrets encrypt -c "$config" || echo "Some passwords or keys could not be encrypted; check with: sudo signalith secrets status" >&2
  if [ -e "$removed" ]; then
    # Installed again after being removed: the removal stopped and
    # disabled the service, so it is turned back on with the kept config.
    rm -f "$removed"
    if [ "$systemd" = yes ]; then
      systemctl enable signalith >/dev/null 2>&1 || true
      systemctl start signalith || true
    fi
  elif [ "$systemd" = yes ]; then
    systemctl try-restart signalith || true
  fi
fi
exit 0
