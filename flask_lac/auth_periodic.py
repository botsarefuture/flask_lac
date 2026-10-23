"""
Periodic auth maintenance. Run this as its OWN process, never inside gunicorn:

    python auth_periodic.py

(systemd service, a docker-compose service, supervisor, ... - one instance.)

What it does every AUTH_PERIODIC_INTERVAL seconds (default 60):
  * walks every cached session in Redis,
  * re-verifies the token with the auth service,
  * deletes revoked/expired sessions (workers see the logout on their next
    request) and refreshes still-valid ones without extending their Redis TTL,
    so idle sessions fall out on their own.

Because it keeps entries fresh, gunicorn workers almost never have to call the
auth service themselves. If this process dies nothing breaks: workers simply
fall back to lazy re-verification after AUTH_CACHE_TTL.

Requires REDIS_URL (the same one the workers use).
"""

import logging
import os
import signal
import sys
import threading
import time

from flask_lac.user import (
    INVALID,
    OK,
    _cache,
    _RedisCache,
    fetch_auth_state,
)

INTERVAL = int(os.getenv("AUTH_PERIODIC_INTERVAL", "60"))

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("auth_periodic")


def run_once(cache):
    checked = removed = refreshed = skipped = 0
    for key in cache.scan_keys():
        entry = cache.get(key)
        if not entry or "token" not in entry:
            continue
        checked += 1
        state, info = fetch_auth_state(entry["token"])  # has hard timeouts
        if state == INVALID:
            cache.delete(key)
            removed += 1
        elif state == OK:
            entry["info"] = info
            entry["checked_at"] = time.time()
            cache.refresh_in_place(key, entry)  # keeps the remaining TTL
            refreshed += 1
        else:  # auth service down: leave entry alone
            skipped += 1
    log.info(
        "checked=%d refreshed=%d removed=%d skipped=%d",
        checked, refreshed, removed, skipped,
    )


def main():
    cache = _cache()
    if not isinstance(cache, _RedisCache):
        log.error("REDIS_URL is not set or Redis is unreachable; nothing to do.")
        return 1

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    log.info("Started; interval=%ss", INTERVAL)
    while not stop.is_set():
        started = time.monotonic()
        try:
            run_once(cache)
        except Exception:
            log.exception("Periodic run failed; will retry next interval")
        stop.wait(max(1.0, INTERVAL - (time.monotonic() - started)))
    log.info("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
