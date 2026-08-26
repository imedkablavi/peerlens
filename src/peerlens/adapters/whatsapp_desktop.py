from __future__ import annotations

import csv
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
            for row in csv.reader(output.splitlines()):
                if row:
                    yield row[0].strip()
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


def detect_process() -> str | None:
    process_set = {name.lower() for name in _running_process_names()}
    return next((name for name in PROCESS_NAMES if name.lower() in process_set), None)


def frida_status() -> tuple[bool, str]:
    try:
        import frida
    except ImportError:
        return False, "not installed; install peerlens[frida] when needed"
    version = getattr(frida, "__version__", None)
    return True, f"installed{f' ({version})' if version else ''}"


class WhatsAppDesktopAdapter(Adapter):
    info = AdapterInfo(
        name="whatsapp-desktop",
        summary="WhatsApp Desktop environment discovery for authorized research",
        live_capture=False,
    )

    def doctor(self) -> list[tuple[str, bool, str]]:
        system = platform.system()
        detected = detect_process()
        frida_ok, frida_detail = frida_status()

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
