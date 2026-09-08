"""In-process operational counters, read by `GET /metrics`. Step 057.

A lock-guarded map and two functions — deliberately not a metrics library. The product's
unit of work is a brokered tool call, `core/broker.call` is the one path every one of
them takes, and counting there is counting everything, once. The
gauges beside these counters (session pool, database pool) are read live at scrape time
by the route and never stored here.

Counters are per process and reset on restart, which is what a Prometheus counter is:
rates survive restarts, absolute values do not pretend to. This module lives at the
package root like `config` because every layer may bump a counter, and it imports
nothing of ours so it can never be the top of a cycle.
"""

import threading

_LOCK = threading.Lock()
# (name, ((label, value), ...)) -> number. Labels are a sorted tuple so the same call
# site can pass them in any order and land on one series.
_COUNTERS: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}


def bump(name: str, amount: float = 1, **labels: str) -> None:
    """Add to one series. Never raises: a metric must not be able to fail a call."""
    key = (name, tuple(sorted(labels.items())))
    with _LOCK:
        _COUNTERS[key] = _COUNTERS.get(key, 0) + amount


def snapshot() -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """A copy, for rendering. The lock is held for the copy and nothing else."""
    with _LOCK:
        return dict(_COUNTERS)


def reset() -> None:
    """Tests only, like `storage.reset`: suites must not inherit each other's counts."""
    with _LOCK:
        _COUNTERS.clear()
