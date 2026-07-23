"""
Development entry point.

Production runs `gunicorn sentinel.api.app:app` (see Procfile). The database
schema and the first-boot admin account are created when sentinel.api.app is
imported, so both entry points behave identically.
"""
import os

from sentinel.api.app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), threaded=True)
