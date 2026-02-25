import os

def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return int(default)

# Recommended production profile (documentation only; not applied automatically):
# - Use async workers: gevent (WSGI) or uvicorn workers (ASGI migration).
# - workers = CPU cores * 2
# - keepalive = 30-75
# - max_requests = 4000
# - max_requests_jitter = 400
# - graceful_timeout = 30
# Example:
#   worker_class = "gevent"
#   workers = max(2, (os.cpu_count() or 1) * 2)
#   keepalive = 45
#   max_requests = 4000
#   max_requests_jitter = 400

# Important: app state is process-local (in-memory bus cache + SSE subscribers),
# so multiple workers will split live state and cause inconsistent realtime behavior.
workers = 1
worker_class = os.environ.get("GUNICORN_WORKER_CLASS", "gevent")
if worker_class == "gthread":
    threads = max(1, _env_int("GUNICORN_THREADS", 4))
if worker_class in ("gevent", "eventlet"):
    worker_connections = max(100, _env_int("GUNICORN_WORKER_CONNECTIONS", 1000))
timeout = max(1, _env_int("GUNICORN_TIMEOUT", 120))
graceful_timeout = max(1, _env_int("GUNICORN_GRACEFUL_TIMEOUT", 30))
keepalive = max(1, _env_int("GUNICORN_KEEPALIVE", 65))
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

port = _env_int("PORT", 8080)
bind = f"0.0.0.0:{port}"
