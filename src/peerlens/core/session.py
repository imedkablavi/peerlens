from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
from typing import Iterable

from .events import Event, SCHEMA_VERSION


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


@dataclass(slots=True)
class CaptureSession:
    root: Path
    session_id: str
    events_path: Path
    metadata_path: Path
    event_count: int = 0

    @classmethod
    def create(cls, base: Path, adapter: str) -> "CaptureSession":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        sid = f"{stamp}-{secrets.token_hex(3)}"
        root = (base / sid).resolve()
        root.mkdir(parents=True, exist_ok=False)
        session = cls(root, sid, root / "events.jsonl", root / "session.json")
        _write_json(
            session.metadata_path,
            {
                "session_id": sid,
                "adapter": adapter,
                "created_at": _utc_now(),
                "completed_at": None,
                "status": "running",
                "event_count": 0,
                "schema_version": SCHEMA_VERSION,
            },
        )
        return session

    def append(self, event: Event) -> None:
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        self.event_count += 1

    def finalize(self, status: str = "completed", error: str | None = None) -> None:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError(f"invalid session status: {status}")
        metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        metadata.update(
            {
                "completed_at": _utc_now(),
                "status": status,
                "event_count": self.event_count,
            }
        )
        if error:
            metadata["error"] = error
        _write_json(self.metadata_path, metadata)


def read_events(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_no}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"invalid event object at line {line_no}")
            Event.from_dict(row)
            yield row
