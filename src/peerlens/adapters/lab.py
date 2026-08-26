from __future__ import annotations

import time

from peerlens.core.events import Event
from .base import Adapter, AdapterInfo, Emit


class LabAdapter(Adapter):
    info = AdapterInfo(
        name="lab",
        summary="Synthetic events for local development and report testing",
        live_capture=True,
    )

    def doctor(self) -> list[tuple[str, bool, str]]:
        return [("lab adapter", True, "ready")]

    def capture(self, seconds: float, emit: Emit) -> None:
        duration = max(0.2, seconds)
        started = time.monotonic()
        emit(Event(type="session.started", source=self.info.name, role="self"))
        sequence = 0
        while time.monotonic() - started < duration:
            sequence += 1
            emit(
                Event(
                    type="media.activity",
                    source=self.info.name,
                    role="peer",
                    data={"level": (sequence * 17) % 64, "sequence": sequence},
                )
            )
            time.sleep(min(0.25, duration))
        emit(Event(type="session.ended", source=self.info.name, role="self"))
