from __future__ import annotations

from pathlib import Path
from typing import Iterable

from peerlens.adapters.whatsapp_locator import WhatsAppLocation
from peerlens.core.binary import fingerprint_binary
from peerlens.core.profiles import ProfileStore


def evaluate_preflight(
    *,
    locations: Iterable[WhatsAppLocation],
    profiles: ProfileStore,
    system: str,
    process: str | None,
    frida_ok: bool,
) -> dict:
    candidates: list[dict] = []
    exact_matches = 0
    verified_matches = 0

    for location in locations:
        row = location.to_dict()
        try:
            fingerprint = fingerprint_binary(Path(location.module))
            profile = profiles.match(fingerprint)
        except (OSError, ValueError, TypeError) as exc:
            row.update(
                {
                    "fingerprint": None,
                    "profile": None,
                    "exact_match": False,
                    "verified": False,
                    "error": str(exc),
                }
            )
        else:
            matched = profile is not None
            verified = bool(profile and profile.verified)
            exact_matches += int(matched)
            verified_matches += int(verified)
            row.update(
                {
                    "fingerprint": fingerprint.to_dict(),
                    "profile": profile.to_dict() if profile else None,
                    "exact_match": matched,
                    "verified": verified,
                    "error": None,
                }
            )
        candidates.append(row)

    checks = {
        "windows": system == "Windows",
        "process_running": process is not None,
        "frida_available": frida_ok,
        "module_found": bool(candidates),
        "exact_profile_match": exact_matches == 1,
        "verified_profile": verified_matches == 1,
    }

    reasons: list[str] = []
    if not checks["windows"]:
        reasons.append("WhatsApp Desktop instrumentation requires Windows")
    if not checks["process_running"]:
        reasons.append("WhatsApp Desktop process is not running")
    if not checks["frida_available"]:
        reasons.append("Frida is not available")
    if not checks["module_found"]:
        reasons.append("WhatsAppNative.Voip.dll was not located")
    elif exact_matches == 0:
        reasons.append("no exact SHA-256 build profile matched the located module")
    elif exact_matches > 1:
        reasons.append("more than one located module matched a build profile")
    elif verified_matches == 0:
        reasons.append("the matching build profile is not verified for instrumentation")
    elif verified_matches > 1:
        reasons.append("more than one verified module candidate was found")

    return {
        "ready": all(checks.values()),
        "checks": checks,
        "process": process,
        "candidates": candidates,
        "reasons": reasons,
    }
