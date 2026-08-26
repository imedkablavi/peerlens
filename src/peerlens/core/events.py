from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
import uuid

SCHEMA_VERSION = 1
VALID_ROLES = frozenset({"self", "peer", "relay", "unknown"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Event:
    type: str
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    role: str = "unknown"
    timestamp: str = field(default_factory=utc_now)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.type or not self.type.strip():
            raise ValueError("event type must not be empty")
        if not self.source or not self.source.strip():
            raise ValueError("event source must not be empty")
        if self.role not in VALID_ROLES:
            raise ValueError(f"invalid event role: {self.role}")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema version: {self.schema_version}; expected {SCHEMA_VERSION}"
            )
        if not isinstance(self.data, dict):
            raise TypeError("event data must be a dictionary")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Event":
        required = {"type", "source"}
        missing = required.difference(value)
        if missing:
            raise ValueError(f"missing event fields: {', '.join(sorted(missing))}")
        return cls(
            type=str(value["type"]),
            source=str(value["source"]),
            data=dict(value.get("data") or {}),
            role=str(value.get("role", "unknown")),
            timestamp=str(value.get("timestamp") or utc_now()),
            id=str(value.get("id") or uuid.uuid4()),
            schema_version=int(value.get("schema_version", SCHEMA_VERSION)),
        )
