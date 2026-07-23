web: gunicorn sentinel.api.app:app --workers 1 --threads 16 --worker-tmp-dir /dev/shm --timeout 120 --bind 0.0.0.0:$PORT
