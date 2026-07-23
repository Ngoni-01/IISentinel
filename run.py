"""Development entry point. Production uses gunicorn against sentinel.api.app:app"""
import os

from sentinel.storage import db
from sentinel.api.app import app

if __name__ == "__main__":
    boot = db.init_db()
    if boot["first_boot"]:
        print("\n" + "=" * 62)
        print("  FIRST BOOT — admin credentials (shown once)")
        print("    username: admin")
        print(f"    password: {boot['password']}")
        print("  You will be required to change this on first sign-in.")
        print("=" * 62 + "\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), threaded=True)
