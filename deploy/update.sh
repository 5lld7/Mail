#!/usr/bin/env bash
# Update application files; keep server settings, mailbox data and retention state.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run using sudo bash /tmp/mail-panel-update.sh' >&2
  exit 1
fi
test -f /etc/mail-panel.env
test -x /opt/mail-panel/.venv/bin/python
if systemctl cat mail-panel-expiry.timer >/dev/null 2>&1; then
  systemctl disable --now mail-panel-expiry.timer
fi
if systemctl cat mail-panel-expiry.service >/dev/null 2>&1; then
  systemctl stop mail-panel-expiry.service
fi
umask 077
stage=$(mktemp -d /tmp/mail-panel-update.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
curl --fail --location --show-error --proto '=https' --tlsv1.2 https://github.com/5lld7/Mail/archive/refs/heads/main.tar.gz -o "$stage/source.tar.gz"
mkdir "$stage/source"
tar -xzf "$stage/source.tar.gz" -C "$stage/source" --strip-components=1
/opt/mail-panel/.venv/bin/python -m pip install --no-cache-dir -r "$stage/source/requirements.txt"
/opt/mail-panel/.venv/bin/python -m pip check
(
  cd "$stage/source"
  /opt/mail-panel/.venv/bin/python -m unittest discover -s tests -v
)
mkdir -p /var/backups/mail-panel
backup="/var/backups/mail-panel/source-$(date +%Y%m%d-%H%M%S)-$$.tar.gz"
tar --exclude=.venv --exclude=.git --exclude=instance --exclude=.env --exclude=__pycache__ -czf "$backup" -C /opt/mail-panel .
systemctl stop mail-panel
cp -a "$stage/source/." /opt/mail-panel/
chown -R root:root /opt/mail-panel
chmod -R go-w /opt/mail-panel
chmod 755 /opt/mail-panel /opt/mail-panel/record_login.py
chmod 644 /opt/mail-panel/retention.py
systemctl start mail-panel
systemctl is-active --quiet mail-panel
curl --fail --silent --show-error --retry 5 --retry-connrefused --retry-delay 1 http://127.0.0.1:8095/ -o /dev/null
echo 'Update complete. Refresh the panel. Settings preserved; automatic 24-hour expiry disabled.'
echo "Previous application source: $backup"
