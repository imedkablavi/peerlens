import json

import pytest

from peerlens.core.events import Event
from peerlens.core.session import CaptureSession, read_events


def test_session_tracks_status_and_event_count(tmp_path):
    session = CaptureSession.create(tmp_path, "lab")
    session.append(Event(type="session.started", source="lab", role="self"))
    session.append(Event(type="session.ended", source="lab", role="self"))
    session.finalize()

    metadata = json.loads(session.metadata_path.read_text(encoding="utf-8"))
    assert metadata["status"] == "completed"
    assert metadata["event_count"] == 2
    assert metadata["completed_at"]
    assert len(list(read_events(session.events_path))) == 2


def test_read_events_rejects_invalid_jsonl(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"type": "ok", "source": "lab"}\nnot-json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSONL at line 2"):
        list(read_events(path))
