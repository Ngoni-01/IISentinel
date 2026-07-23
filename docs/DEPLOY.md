# Deploying

The application lives at the **repository root**. There is no `backend`
directory — that was the previous layout. The Flask app is imported as
`sentinel.api.app:app`.

## Render

If you are creating a new service, the included `render.yaml` sets
everything. If you are updating a service that already existed against the
old layout, change these four settings by hand:

| Setting          | Value                                                            |
|------------------|------------------------------------------------------------------|
| Root Directory   | **leave blank** (was `backend` — this is the cause of "Root directory 'backend' does not exist") |
| Build Command    | `pip install -r requirements.txt`                                 |
| Start Command    | `gunicorn sentinel.api.app:app --workers 1 --threads 16 --worker-tmp-dir /dev/shm --timeout 120 --bind 0.0.0.0:$PORT` |
| Environment var  | `DB_PATH` = `/var/data/sentinel.db`                               |

Add a **persistent disk** mounted at `/var/data`. Without it, every restart
wipes the database, which also means a new admin password is generated and
your previous one stops working.

## Getting your admin password

The password is generated once, on first boot, and printed to the log. On
Render: open the service, click **Logs**, and look for:

    ==============================================================
      FIRST BOOT - admin credentials (shown once)
        username: admin
        password: harbor-ionic-8028-nexus
      You will be required to change this at first sign-in.
    ==============================================================

It appears only on the boot where the database was created. If you missed
it, delete the database file on the disk and restart — a new one is issued.

## Any other host

    pip install -r requirements.txt
    export DB_PATH=/var/lib/sentinel/sentinel.db
    gunicorn sentinel.api.app:app --workers 1 --threads 16 --bind 0.0.0.0:8000

The `Procfile` carries the same command for Heroku-style platforms.

## Why one worker

SQLite serialises writes. A single worker with threads avoids cross-process
write contention while still handling concurrent sensors. See ADR-003 in
ARCHITECTURE.md for when to revisit this.
