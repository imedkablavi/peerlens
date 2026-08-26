from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import platform
import subprocess
from typing import Iterable, Mapping

from peerlens.core.binary import fingerprint_binary

VOIP_MODULE = "WhatsAppNative.Voip.dll"
PROCESS_NAMES = ("WhatsApp.Root.exe", "WhatsApp.exe")
MAX_SCAN_DEPTH = 6


@dataclass(frozen=True, slots=True)
class WhatsAppLocation:
    executable: str | None
    module: str
    source: str

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


def _powershell_process_paths() -> list[Path]:
    if platform.system() != "Windows":
        return []

    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-Process | Where-Object { $_.ProcessName -like 'WhatsApp*' } | "
        "ForEach-Object { $_.Path }"
    )
    try:
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    paths: list[Path] = []
    for line in output.splitlines():
        value = line.strip()
        if value:
            paths.append(Path(value))
    return paths


def _known_roots(env: Mapping[str, str]) -> list[Path]:
    roots: list[Path] = []

    local = env.get("LOCALAPPDATA")
    if local:
        base = Path(local)
        roots.extend(
            [
                base / "WhatsApp",
                base / "Programs" / "WhatsApp",
            ]
        )
        packages = base / "Packages"
        if packages.is_dir():
            try:
                roots.extend(
                    entry
                    for entry in packages.iterdir()
                    if entry.is_dir() and "whatsapp" in entry.name.lower()
                )
            except OSError:
                pass

    for key in ("ProgramFiles", "ProgramFiles(x86)"):
        value = env.get(key)
        if value:
            roots.append(Path(value) / "WhatsApp")

    return roots


def _walk_for_module(root: Path, max_depth: int = MAX_SCAN_DEPTH) -> Iterable[Path]:
    if not root.is_dir():
        return

    root_depth = len(root.parts)
    stack = [root]
    seen: set[Path] = set()

    while stack:
        current = stack.pop()
        try:
            resolved = current.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)

        if len(current.parts) - root_depth > max_depth:
            continue

        candidate = current / VOIP_MODULE
        if candidate.is_file():
            yield candidate

        try:
            children = [child for child in current.iterdir() if child.is_dir()]
        except (OSError, PermissionError):
            continue
        stack.extend(children)


def locate_whatsapp(
    *,
    env: Mapping[str, str] | None = None,
    process_paths: Iterable[Path] | None = None,
) -> list[WhatsAppLocation]:
    environment = os.environ if env is None else env
    running = list(_powershell_process_paths() if process_paths is None else process_paths)

    locations: list[WhatsAppLocation] = []
    module_paths: list[tuple[Path, str, Path | None]] = []

    for executable in running:
        root = executable.parent
        direct = root / VOIP_MODULE
        if direct.is_file():
            module_paths.append((direct, "running-process", executable))
        else:
            for module in _walk_for_module(root, max_depth=3):
                module_paths.append((module, "running-process", executable))

    for root in _known_roots(environment):
        for module in _walk_for_module(root):
            module_paths.append((module, "known-install-root", None))

    dedupe: set[str] = set()
    for module, source, executable in module_paths:
        try:
            key = str(module.resolve()).casefold()
        except OSError:
            key = str(module.absolute()).casefold()
        if key in dedupe:
            continue
        dedupe.add(key)
        locations.append(
            WhatsAppLocation(
                executable=str(executable.resolve()) if executable else None,
                module=str(module.resolve()),
                source=source,
            )
        )

    locations.sort(key=lambda item: (item.source != "running-process", item.module.casefold()))
    return locations


def inspect_locations(locations: Iterable[WhatsAppLocation]) -> list[dict]:
    inspected: list[dict] = []
    for location in locations:
        row = location.to_dict()
        try:
            row["fingerprint"] = fingerprint_binary(Path(location.module)).to_dict()
            row["error"] = None
        except (OSError, ValueError) as exc:
            row["fingerprint"] = None
            row["error"] = str(exc)
        inspected.append(row)
    return inspected
