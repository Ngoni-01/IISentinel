#!/bin/bash
# IISentinel — one-shot VPS deployment (Ubuntu 22.04/24.04)
# Works on Vultr, Hetzner, DigitalOcean, Oracle Cloud, any Ubuntu VPS.
# Usage:  sudo bash vps_setup.sh yourdomain.com     (or an IP for HTTP-only)
set -e
DOMAIN=${1:-}
APP_DIR=/opt/iisentinel
DATA_DIR=/var/lib/iisentinel

echo "══ IISentinel VPS setup ══"
apt-get update -qq
apt-get install -y -qq python3-venv python3-pip iputils-ping debian-keyring debian-archive-keyring apt-transport-https curl

# ── app user + dirs ──
id -u iis &>/dev/null || useradd -r -m -d $APP_DIR -s /usr/sbin/nologin iis
mkdir -p $APP_DIR $DATA_DIR
cp -r "$(dirname "$0")/../backend/." $APP_DIR/
chown -R iis:iis $APP_DIR $DATA_DIR

# ── python env ──
sudo -u iis python3 -m venv $APP_DIR/venv
sudo -u iis $APP_DIR/venv/bin/pip install -q -r $APP_DIR/requirements.txt

# ── systemd service ──
cp "$(dirname "$0")/iisentinel.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now iisentinel
sleep 3 && systemctl --no-pager -l status iisentinel | head -6

# ── Caddy: HTTPS + HTTP/2 + compression, zero config pain ──
if [ -n "$DOMAIN" ]; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy.list >/dev/null
  apt-get update -qq && apt-get install -y -qq caddy
  sed "s/DOMAIN/$DOMAIN/" "$(dirname "$0")/Caddyfile" > /etc/caddy/Caddyfile
  systemctl reload caddy
  echo "→ Live at https://$DOMAIN (SSL automatic)"
else
  echo "→ No domain given: app on http://SERVER_IP:8000 (add a domain later for HTTPS)"
fi

# ── nightly DB backup (7-day rotation) ──
cat > /etc/cron.daily/iisentinel-backup << 'B'
#!/bin/bash
sqlite3 /var/lib/iisentinel/iisentinel.db ".backup /var/lib/iisentinel/backup-$(date +%u).db" 2>/dev/null || \
cp /var/lib/iisentinel/iisentinel.db /var/lib/iisentinel/backup-$(date +%u).db
B
chmod +x /etc/cron.daily/iisentinel-backup

# ── firewall ──
command -v ufw >/dev/null && { ufw allow 22; ufw allow 80; ufw allow 443; ufw allow 8000; ufw --force enable; }

echo "══ DONE ══  service: systemctl status iisentinel   logs: journalctl -u iisentinel -f"
