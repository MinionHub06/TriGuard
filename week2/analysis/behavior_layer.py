import hashlib
import logging
import os
import time

log = logging.getLogger(__name__)

# ── In-process fallback ────────────────────────────────────────────────────────

_fallback: dict = {}


def _fb_incr(key: str, ttl: int) -> int:
    now = time.time()
    val, exp = _fallback.get(key, (0, now + ttl))
    if now > exp:
        val, exp = 0, now + ttl
    val += 1
    _fallback[key] = (val, exp)
    return val


def _fb_get(key: str):
    now = time.time()
    if key not in _fallback:
        return None
    val, exp = _fallback[key]
    if now > exp:
        del _fallback[key]
        return None
    return val


def _fb_setex(key: str, ttl: int, value) -> None:
    _fallback[key] = (value, time.time() + ttl)


# ── Thresholds ────────────────────────────────────────────────────────────────

REQUEST_WINDOW_SECS   = int(os.getenv("TG_RATE_WINDOW",    60))
HIGH_VOLUME_THRESHOLD = int(os.getenv("TG_RATE_THRESHOLD", 30))
BURST_THRESHOLD       = int(os.getenv("TG_BURST_THRESHOLD", 10))
PATTERN_MEMORY_TTL    = int(os.getenv("TG_PATTERN_TTL",   3600))
BLOCK_TTL             = int(os.getenv("TG_BLOCK_TTL",      300))


# ── BehavioralLayer ───────────────────────────────────────────────────────────

class BehavioralLayer:
    """
    Usage:
        beh_layer = BehavioralLayer(app.config['REDIS_URL'])
        result    = beh_layer.score(ip, payload, ml_score)

    redis_url accepts any of:
        "redis://localhost:6379/0"   standard URL
        "redis://:password@host:port/db"
        None / ""                   skips Redis, uses in-process fallback
    """

    def __init__(self, redis_url: str = None):
        self._client = None
        self._available = False
        if redis_url:
            self._connect(redis_url)

    def _connect(self, redis_url: str) -> None:
        try:
            import redis as _redis
            client = _redis.Redis.from_url(
                redis_url,
                socket_connect_timeout=1,
                socket_timeout=1,
                decode_responses=True,
            )
            client.ping()
            self._client    = client
            self._available = True
            log.info("BehavioralLayer: Redis connected — %s", redis_url)
        except Exception as exc:
            self._client    = None
            self._available = False
            log.warning(
                "BehavioralLayer: Redis unavailable (%s) — using in-process fallback.", exc
            )

    # ── internal Redis helpers ────────────────────────────────────────────────

    def _incr_with_ttl(self, key: str, ttl: int) -> int:
        if self._available:
            try:
                pipe = self._client.pipeline()
                pipe.incr(key)
                pipe.expire(key, ttl)
                return pipe.execute()[0]
            except Exception as exc:
                log.warning("BehavioralLayer Redis write error: %s", exc)
        return _fb_incr(key, ttl)

    def _get(self, key: str):
        if self._available:
            try:
                return self._client.get(key)
            except Exception as exc:
                log.warning("BehavioralLayer Redis read error: %s", exc)
        return _fb_get(key)

    def _setex(self, key: str, ttl: int, value) -> None:
        if self._available:
            try:
                self._client.setex(key, ttl, value)
                return
            except Exception as exc:
                log.warning("BehavioralLayer Redis setex error: %s", exc)
        _fb_setex(key, ttl, value)

    # ── public API ────────────────────────────────────────────────────────────

    def score(self, ip: str, payload: str, ml_score: float) -> dict:
        """
        Compute behavioral risk score [0.0–1.0] for this (ip, payload) pair.

        Returns dict:
            behavioral_score  float
            rate_flag         bool
            burst_flag        bool
            repeat_flag       bool
            block_flag        bool
            request_count     int
        """
        now_ts = int(time.time())

        # 1. Active block list
        block_key  = f"tg:block:{ip}"
        block_flag = self._get(block_key) is not None

        # 2. Sliding-window rate counter
        rate_key      = f"tg:rate:{ip}"
        request_count = self._incr_with_ttl(rate_key, REQUEST_WINDOW_SECS)
        rate_flag     = request_count >= HIGH_VOLUME_THRESHOLD

        # 3. Burst detection — 5-second slot bucket
        burst_key   = f"tg:burst:{ip}:{now_ts // 5}"
        burst_count = self._incr_with_ttl(burst_key, 10)
        burst_flag  = burst_count >= BURST_THRESHOLD

        # 4. Payload pattern memory
        payload_hash = hashlib.sha1(payload.encode()).hexdigest()[:16]
        pattern_key  = f"tg:pattern:{ip}:{payload_hash}"
        repeat_flag  = self._get(pattern_key) is not None
        if ml_score >= 0.5:
            self._setex(pattern_key, PATTERN_MEMORY_TTL, "1")

        # 5. Auto-block on high-confidence attack
        if ml_score >= 0.85 and not block_flag:
            self._setex(block_key, BLOCK_TTL, "1")
            log.warning(
                "BehavioralLayer: auto-blocked %s (ml_score=%.3f)", ip, ml_score
            )
            block_flag = True

        # 6. Composite score
        composite = 0.0
        if block_flag:   composite += 0.60
        if repeat_flag:  composite += 0.20
        if rate_flag:    composite += 0.12
        if burst_flag:   composite += 0.08
        composite = min(composite, 1.0)

        return {
            "behavioral_score": round(composite, 4),
            "rate_flag":        rate_flag,
            "burst_flag":       burst_flag,
            "repeat_flag":      repeat_flag,
            "block_flag":       block_flag,
            "request_count":    request_count,
        }

    # Alias
    behavioral_score = score

    def reset_ip(self, ip: str) -> None:
        """Clear all behavioral state for an IP — useful in tests."""
        keys = [f"tg:block:{ip}", f"tg:rate:{ip}"]
        if self._available:
            try:
                self._client.delete(*keys)
            except Exception:
                pass
        for k in keys:
            _fallback.pop(k, None)

    def redis_status(self) -> dict:
        """Return Redis connection state — consumed by GET /health."""
        return {
            "connected": self._available,
            "fallback":  not self._available,
        }