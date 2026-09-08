"""Per-account login backoff for the local provider — step 053, blocker B2 of plan 049.

Step 051 bounded how much memory a login flood can burn; this bounds how fast a guesser
may try one account. A small in-process map keyed by the normalized email holds a
consecutive-failure count and, past a threshold, a growing block. The block is checked
*before* the password is verified, so a blocked attempt costs neither a scrypt nor a
database read — and the check keys on the address whether or not it names a real account,
so it is not an oracle for which addresses exist.

Per process and per deployment: `--local` is one process, and a replicated provider is a
deferral the door's Postgres budget already made for its own reason (see plan 053).
"""

import threading
import time
from dataclasses import dataclass

# Consecutive failures before a block begins. Below this, a mistyped password costs
# nothing — the common case is a person, not a guesser.
_THRESHOLD = 5
# The block after the threshold, doubling each further failure: 1s, 2s, 4s, … The cap
# keeps an account-lockout nuisance (a guesser failing a known address on purpose) from
# becoming an indefinite lockout — it clears after this at most.
_BASE_SECONDS = 1.0
_CAP_SECONDS = 900.0  # 15 minutes
# A record whose last attempt is older than this starts over, so yesterday's two typos
# do not count against today, and idle records are evicted so the map cannot grow without
# bound.
_RESET_WINDOW_SECONDS = 900.0


def _normalize(email: str) -> str:
    return (email or "").strip().lower()


@dataclass
class _Record:
    failures: int = 0
    last_attempt: float = 0.0
    blocked_until: float = 0.0


class LoginThrottle:
    """Thread-safe per-email login backoff. One instance per running edge."""

    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._records: dict[str, _Record] = {}

    def blocked_for(self, email: str) -> float:
        """Seconds the caller must wait before this account may try again; 0 if free.

        Also the point where a stale record is reset or evicted, so the map stays small
        without a sweeper thread.
        """
        key = _normalize(email)
        now = self._clock()
        with self._lock:
            record = self._records.get(key)
            if record is None:
                return 0.0
            if now - record.last_attempt > _RESET_WINDOW_SECONDS:
                # Idle long enough to forgive and to forget — free the slot.
                del self._records[key]
                return 0.0
            remaining = record.blocked_until - now
            return remaining if remaining > 0 else 0.0

    def failed(self, email: str) -> None:
        """Record a failed attempt and extend the block past the threshold."""
        key = _normalize(email)
        now = self._clock()
        with self._lock:
            record = self._records.get(key)
            if record is None or now - record.last_attempt > _RESET_WINDOW_SECONDS:
                record = _Record()
                self._records[key] = record
            record.failures += 1
            record.last_attempt = now
            if record.failures > _THRESHOLD:
                delay = min(
                    _CAP_SECONDS, _BASE_SECONDS * 2 ** (record.failures - _THRESHOLD - 1)
                )
                record.blocked_until = now + delay

    def succeeded(self, email: str) -> None:
        """Clear the record — a right password ends the penalty for that account."""
        key = _normalize(email)
        with self._lock:
            self._records.pop(key, None)
