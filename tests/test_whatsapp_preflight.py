import hashlib

from peerlens.adapters.whatsapp_locator import WhatsAppLocation
from peerlens.adapters.whatsapp_preflight import evaluate_preflight
from peerlens.core.profiles import BuildProfile, ProfileStore


def _location(tmp_path, content=b"module"):
    module = tmp_path / "WhatsAppNative.Voip.dll"
    module.write_bytes(content)
    return WhatsAppLocation(
        executable=str(tmp_path / "WhatsApp.exe"),
        module=str(module),
        source="running-process",
    )


def test_preflight_requires_verified_exact_profile(tmp_path):
    content = b"known module"
    location = _location(tmp_path, content)
    profile = BuildProfile(
        id="known",
        sha256=hashlib.sha256(content).hexdigest(),
        verified=True,
    )

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((profile,)),
        system="Windows",
        process="WhatsApp.exe",
        frida_ok=True,
    )

    assert result["ready"] is True
    assert result["checks"] == {
        "windows": True,
        "process_running": True,
        "frida_available": True,
        "module_found": True,
        "exact_profile_match": True,
        "verified_profile": True,
    }
    assert result["reasons"] == []


def test_preflight_rejects_unverified_profile(tmp_path):
    content = b"known module"
    location = _location(tmp_path, content)
    profile = BuildProfile(
        id="known",
        sha256=hashlib.sha256(content).hexdigest(),
        verified=False,
    )

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((profile,)),
        system="Windows",
        process="WhatsApp.exe",
        frida_ok=True,
    )

    assert result["ready"] is False
    assert result["checks"]["exact_profile_match"] is True
    assert result["checks"]["verified_profile"] is False
    assert "not verified" in result["reasons"][0]


def test_preflight_rejects_unknown_binary(tmp_path):
    location = _location(tmp_path, b"unknown")
    profile = BuildProfile(id="other", sha256="a" * 64, verified=True)

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((profile,)),
        system="Windows",
        process="WhatsApp.exe",
        frida_ok=True,
    )

    assert result["ready"] is False
    assert result["checks"]["exact_profile_match"] is False
    assert "no exact SHA-256" in result["reasons"][0]


def test_preflight_reports_missing_runtime_requirements():
    result = evaluate_preflight(
        locations=[],
        profiles=ProfileStore(()),
        system="Linux",
        process=None,
        frida_ok=False,
    )

    assert result["ready"] is False
    assert result["reasons"] == [
        "WhatsApp Desktop instrumentation requires Windows",
        "WhatsApp Desktop process is not running",
        "Frida is not available",
        "WhatsAppNative.Voip.dll was not located",
    ]
