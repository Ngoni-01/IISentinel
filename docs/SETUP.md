# Setup — from clone to first finding in five minutes

## 1. Run the server (local or a $7 instance)

    pip install -r requirements.txt
    python3 run.py

First boot prints a one-time admin password:

    ==============================================================
      FIRST BOOT — admin credentials (shown once)
        username: admin
        password: amber-mesa-7419-quill
    ==============================================================

Open http://localhost:5000, sign in, and set a real password when prompted.

For a real deployment, use the included `render.yaml` (Render) or run
gunicorn behind any reverse proxy:

    gunicorn sentinel.api.app:app --workers 1 --threads 16 --bind 0.0.0.0:$PORT

Set `DB_PATH` to a persistent disk so findings survive restarts.

## 1b. Configuration (optional)

Everything runs on sensible defaults. To change any of them:

    cp .env.example .env      # then edit

`.env.example` documents every variable the code reads and nothing it
doesn't — port, database path, and the two rate limits. It contains no
credentials: the admin password is generated on first boot and printed once,
and collector keys are issued through enrolment codes in the UI.

The one setting that matters for a hosted deployment is **`DB_PATH`**. Point
it at a persistent disk. If you leave it on ephemeral storage, every restart
wipes your findings and your admin account, and first boot mints a new
password. `render.yaml` already mounts a disk and sets this correctly.

## 2. Add a sensor (in the UI)

Click **Add sensor**, name the segment (e.g. `floor-3`), and Sentinel gives
you a one-time command with the enrolment code already in it:

    python3 net_sensor.py --server https://your-sentinel \
        --enrol 3F2A-9C11-B0D4 --segment "floor-3" \
        --expected 192.168.3.1 --arp --lldp

## 3. Run the sensor on the segment

On any machine on that network — a Raspberry Pi, a spare laptop, anything
Linux with Python:

    pip install requests          # scapy optional, improves accuracy
    # paste the command from step 2

`--expected` is the sanctioned gateway/DHCP IP; if you omit it the sensor
uses its own default gateway. `--lldp` needs `lldpd` (`sudo apt install
lldpd`) or falls back to a brief CDP listen. Raw DHCP needs `sudo`.

The sensor enrols once, caches its key in `~/.sentinel-key`, and from then on
runs with no code needed.

## 4. Watch the finding appear

The dashboard updates on its own. If anything on that segment is handing out
DHCP leases it should not be, it appears with the vendor, the switch port,
the affected hosts, and a blast-radius timeline.

## The 90-second demo

1. Sign in. Empty dashboard, guided setup.
2. Add sensor → get the command → run it on the venue network.
3. A real finding appears: the device nobody declared.
4. Open **Blast radius**: what depends on it, and when each dependency bites.

Every number on screen is labelled observed / derived / assumed. Nothing is
simulated.
