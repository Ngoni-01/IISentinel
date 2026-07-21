# Permanent hosting — 10 minutes, ~$6/month, zero cold starts

## Why this instead of Render free
Render free = 0.1 CPU shared, sleeps after 15 min (30-60s wake), wipes your
SQLite on every restart, and sits in Europe/US (~160ms+ from Harare).
A Johannesburg VPS = full CPU, always on, persistent disk, ~30ms from Harare.
Your code already runs in milliseconds — the host was the bottleneck.

## Steps
1. Create the server
   - Vultr → Deploy → Cloud Compute → **Johannesburg** → Ubuntu 24.04 → $6/mo
   - (Hetzner ~€4 EU-only, DigitalOcean $6, Oracle Always-Free also work)
2. Upload this project
   scp -r IIS_PROD root@YOUR_IP:/root/iisentinel
3. Run the installer
   ssh root@YOUR_IP
   cd /root/iisentinel/deploy
   bash vps_setup.sh                # HTTP on port 8000, or:
   bash vps_setup.sh yourdomain.com # automatic HTTPS via Caddy
4. Done. Database lives at /var/lib/iisentinel (survives deploys),
   nightly backups rotate 7 days, service auto-restarts on crash/reboot.

## Updating later
   scp backend/* root@YOUR_IP:/opt/iisentinel/ && ssh root@YOUR_IP systemctl restart iisentinel

## If you stay on Render meanwhile
- CHECK YOUR START COMMAND — must be exactly:
  gunicorn app:app --workers 1 --threads 32 --worker-tmp-dir /dev/shm --keep-alive 5 --timeout 120 --bind 0.0.0.0:$PORT
  (multiple sync workers silently deadlock SSE = "everything slow")
- $7/mo Starter removes sleep; attach a disk and set DB_PATH=/var/data/iisentinel.db
- Free tier: keep UptimeRobot pinging /api/ping every 10 min
