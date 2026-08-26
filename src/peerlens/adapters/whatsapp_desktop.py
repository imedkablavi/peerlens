from __future__ import annotations

import platform
import subprocess
from typing import Iterable

from .base import Adapter, AdapterInfo, Emit


PROCESS_NAMES = ("WhatsApp.Root.exe", "WhatsApp.exe")


def _running_process_names() -> Iterable[str]:
    system = platform.system().lower()
    try:
        if system == "windows":
            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            for line in output.splitlines():
                if not line:
                    continue
                yield line.split(",", 1)[0].strip('"')
        else:
            output = subprocess.check_output(
                ["ps", "-eo", "comm="],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            yield from (line.strip() for line in output.splitlines() if line.strip())
    except (OSError, subprocess.SubprocessError):
        return


class WhatsAppDesktopAdapter(Adapter):
    info = AdapterInfo(
        name="whatsapp-desktop",
        summary="WhatsApp Desktop environment discovery for authorized research",
        live_capture=False,
    )

    def doctor(self) -> list[tuple[str, bool, str]]:
        system = platform.system()
        process_set = {name.lower() for name in _running_process_names()}
        detected = next((p for p in PROCESS_NAMES if p.lower() in process_set), None)

        try:
            import frida  # noqa: F401
            frida_ok = True
            frida_detail = "installed"
        except ImportError:
            frida_ok = False
            frida_detail = "not installed; install peerlens[frida] when needed"

        return [
            ("operating system", system == "Windows", system),
            ("WhatsApp process", detected is not None, detected or "not detected"),
            ("Frida", frida_ok, frida_detail),
            ("external network use", True, "disabled by default"),
            ("capture scope", True, "environment discovery only in v0.1"),
        ]

    def capture(self, seconds: float, emit: Emit) -> None:
        raise RuntimeError(
            "live peer capture is not enabled in the v0.1 WhatsApp Desktop adapter"
        )
