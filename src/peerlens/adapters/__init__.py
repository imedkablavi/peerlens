from .base import Adapter
from .lab import LabAdapter
from .whatsapp_desktop import WhatsAppDesktopAdapter


def registry() -> dict[str, Adapter]:
    adapters: list[Adapter] = [LabAdapter(), WhatsAppDesktopAdapter()]
    return {adapter.info.name: adapter for adapter in adapters}
