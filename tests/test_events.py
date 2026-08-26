import pytest

from peerlens.core.events import Event


def test_event_schema_is_stable():
    row = Event(type="test.event", source="lab", data={"x": 1}).to_dict()
    assert row["schema_version"] == 1
    assert row["type"] == "test.event"
    assert row["source"] == "lab"
    assert row["data"] == {"x": 1}


def test_event_rejects_unknown_role():
    with pytest.raises(ValueError, match="invalid event role"):
        Event(type="test.event", source="lab", role="target")


def test_event_round_trip():
    original = Event(type="test.event", source="lab", role="peer", data={"x": 1})
    restored = Event.from_dict(original.to_dict())
    assert restored.to_dict() == original.to_dict()
