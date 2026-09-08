"""Keeping the log tables writable and the retention window enforced. One sweep.

Extracted from the worker in step 060 because the worker had quietly become the only
process running it, and moved here in step 078 when the worker left the tree. Two
things happen in one pass: the log partitions are extended past the horizon so the
audit append never meets `missing_partition` months from now (migration 030), and
records older than `CARNET_RETENTION_DAYS` are pruned. Each caller keeps its own
throttle — the API's `LogMaintainer` runs this hourly, `carnet --prune-logs` runs it
now — because the interval is the caller's property, not the sweep's.

At the package root like `metrics`, because it is an operational concern that belongs
to no layer: it imports storage and config, and nothing imports it but entry points.
"""

import logging
from datetime import datetime, timedelta, timezone

from . import storage
from .config import RETENTION_DAYS
from .storage.base import prune_floor

log = logging.getLogger(__name__)


def sweep_log_tables() -> dict:
    """Extend the log partitions and enforce retention — one sweep, unthrottled.

    **Partition maintenance runs whether or not retention is configured**:
    `ensure_log_partitions` is what keeps the log tables writable months from now,
    and a deployment with retention off needs that exactly as much as one with it on.
    Returns the per-table prune counts, empty when retention is off or nothing was due.
    """
    try:
        created = storage.active().ensure_log_partitions()
        if created:
            log.info(
                "retention: created %d log partition(s): %s",
                len(created), ", ".join(created),
            )
    except Exception:  # noqa: BLE001 - the same rule the prune below follows
        log.exception("partition maintenance failed")

    if RETENTION_DAYS is None:
        return {}

    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    try:
        counts = storage.active().prune_log_records(cutoff)
    except Exception:  # noqa: BLE001 - a failed prune must not kill the caller's thread
        log.exception("retention sweep failed")
        return {}

    total = sum(counts.values())
    if total:
        # Loudly, because this is the one operation in the product that destroys
        # records somebody may later be asked to produce. `prune_floor` rather than
        # `cutoff`, because the month boundary is what was actually applied and a log
        # line naming the requested cutoff would overstate the precision by up to a month.
        log.info(
            "retention: removed %d record(s) older than %s — %s",
            total, prune_floor(cutoff).isoformat(), counts,
        )
    return counts


__all__ = ["sweep_log_tables"]
