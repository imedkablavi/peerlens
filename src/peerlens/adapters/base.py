from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from peerlens.core.events import Event

Emit = Callable[[Event], None]


class AdapterError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AdapterInfo:
    name: str
    summary: str
    live_capture: bool


class Adapter(ABC):
    info: AdapterInfo

    @abstractmethod
    def doctor(self) -> list[tuple[str, bool, str]]:
        raise NotImplementedError

    @abstractmethod
    def capture(self, seconds: float, emit: Emit) -> None:
        raise NotImplementedError
