from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Iterable


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def summarize(events: Iterable[dict]) -> dict:
    rows = list(events)
    types = Counter(row.get("type", "unknown") for row in rows)
    sources = Counter(row.get("source", "unknown") for row in rows)
    roles = Counter(row.get("role", "unknown") for row in rows)

    timestamps = [parsed for row in rows if (parsed := _parse_time(row.get("timestamp")))]
    started_at = min(timestamps).isoformat() if timestamps else None
    ended_at = max(timestamps).isoformat() if timestamps else None
    duration_s = None
    if len(timestamps) >= 2:
        duration_s = round((max(timestamps) - min(timestamps)).total_seconds(), 3)

    return {
        "event_count": len(rows),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_s": duration_s,
        "event_types": dict(sorted(types.items())),
        "sources": dict(sorted(sources.items())),
        "roles": dict(sorted(roles.items())),
    }
