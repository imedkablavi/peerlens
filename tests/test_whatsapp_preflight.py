import hashlib
import struct

from peerlens.adapters.whatsapp_locator import WhatsAppLocation
from peerlens.adapters.whatsapp_preflight import evaluate_preflight
from peerlens.core.profiles import BuildProfile, ProfileStore


def _fake_pe(machine=0x8664, image_size=0xC09000):
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<I", data, 0x88, 123456789)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 56, image_size)
    return bytes(data)


def _location(tmp_path, content):
    module = tmp_path / "WhatsAppNative.Voip.dll"
    module.write_bytes(content)
    return WhatsAppLocation(
        executable=str(tmp_path / "WhatsApp.exe"),
        module=str(module),
        source="running-process",
    )


def _profile(content, *, verified=True):
    return BuildProfile(
        id="known",
        sha256=hashlib.sha256(content).hexdigest(),
        verified=verified,
    )


def test_preflight_requires_verified_exact_profile_and_supported_pe(tmp_path):
    content = _fake_pe()
    location = _location(tmp_path, content)

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((_profile(content),)),
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
        "pe_binary": True,
        "supported_architecture": True,
    }
    assert result["reasons"] == []


def test_preflight_rejects_unverified_profile(tmp_path):
    content = _fake_pe()
    location = _location(tmp_path, content)

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((_profile(content, verified=False),)),
        system="Windows",
        process="WhatsApp.exe",
        frida_ok=True,
    )

    assert result["ready"] is False
    assert result["checks"]["exact_profile_match"] is True
    assert result["checks"]["verified_profile"] is False
    assert any("not verified" in reason for reason in result["reasons"])


def test_preflight_rejects_unknown_binary(tmp_path):
    content = _fake_pe()
    location = _location(tmp_path, content)
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
    assert any("no exact SHA-256" in reason for reason in result["reasons"])


def test_preflight_rejects_non_pe_binary(tmp_path):
    content = b"not a pe binary"
    location = _location(tmp_path, content)

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((_profile(content),)),
        system="Windows",
        process="WhatsApp.exe",
        frida_ok=True,
    )

    assert result["ready"] is False
    assert result["checks"]["pe_binary"] is False
    assert any("not a valid PE" in reason for reason in result["reasons"])


def test_preflight_rejects_unsupported_architecture(tmp_path):
    content = _fake_pe(machine=0xAA64)
    location = _location(tmp_path, content)

    result = evaluate_preflight(
        locations=[location],
        profiles=ProfileStore((_profile(content),)),
        system="Windows",
        process="WhatsApp.exe",
        frida_ok=True,
    )

    assert result["ready"] is False
    assert result["checks"]["pe_binary"] is True
    assert result["checks"]["supported_architecture"] is False
    assert any("unsupported module architecture: arm64" in reason for reason in result["reasons"])


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
