from peerlens.reporting.json_report import summarize


def test_summary_counts_types_sources_and_roles():
    result = summarize(
        [
            {"type": "a", "source": "lab", "role": "peer"},
            {"type": "a", "source": "lab", "role": "peer"},
            {"type": "b", "source": "lab", "role": "self"},
        ]
    )
    assert result["event_count"] == 3
    assert result["event_types"] == {"a": 2, "b": 1}
    assert result["roles"] == {"peer": 2, "self": 1}
    assert result["duration_s"] is None


def test_summary_reports_duration():
    result = summarize(
        [
            {
                "type": "a",
                "source": "lab",
                "role": "peer",
                "timestamp": "2026-08-27T00:00:00+00:00",
            },
            {
                "type": "b",
                "source": "lab",
                "role": "peer",
                "timestamp": "2026-08-27T00:00:01.500000+00:00",
            },
        ]
    )
    assert result["duration_s"] == 1.5
