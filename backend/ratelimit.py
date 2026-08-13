"""
Simple in-memory sliding-window rate limiter.

Protects sensitive endpoints (login, OTP request) from automated abuse and
brute-force at the network layer, in addition to per-account lockout. Keyed by
(endpoint-kind, client IP). In-memory is sufficient for this single-process
demo; a production deployment would back this with Redis.
"""

import time
from collections import defaultdict
from functools import wraps

from flask import current_app, jsonify, request

# { key: [timestamps...] }
_HITS = defaultdict(list)


def reset():
    """Clear all counters (used by the test-suite between tests)."""
    _HITS.clear()


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else request.remote_addr


def rate_limited(kind):
    """Decorator: allow at most RATE_LIMIT_MAX requests per window per IP."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            cfg = current_app.config
            max_hits = cfg.get("RATE_LIMIT_MAX", 30)
            window = cfg.get("RATE_LIMIT_WINDOW_SECONDS", 60)

            key = f"{kind}:{_client_ip()}"
            now = time.time()
            hits = [t for t in _HITS[key] if now - t < window]
            if len(hits) >= max_hits:
                retry = int(window - (now - hits[0])) + 1
                _HITS[key] = hits
                return (
                    jsonify({
                        "error": "Too many requests. Please slow down.",
                        "retry_after_seconds": retry,
                    }),
                    429,
                )
            hits.append(now)
            _HITS[key] = hits
            return fn(*args, **kwargs)

        return wrapper

    return decorator
