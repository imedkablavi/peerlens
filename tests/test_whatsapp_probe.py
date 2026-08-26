import sys
from types import SimpleNamespace

import pytest

from peerlens.adapters.whatsapp_probe import ProbeError, probe_loaded_module, validate_probe


class FakeScript:
    def __init__(self, result):
        self.loaded = False
        self.unloaded = False
        self.exports_sync = SimpleNamespace(inspect=lambda name: result)

    def load(self):
        self.loaded = True

    def unload(self):
        self.unloaded = True


class FakeSession:
    def __init__(self, result):
        self.script = FakeScript(result)
        self.detached = False

    def create_script(self, source):
        assert "rpc.exports" in source
        return self.script

    def detach(self):
        self.detached = True


def test_probe_attaches_reads_module_and_cleans_up(monkeypatch):
    result = {
        "name": "WhatsAppNative.Voip.dll",
        "base": "0x7ff600000000",
        "size": 0xC09000,
        "path": r"C:\Apps\WhatsAppNative.Voip.dll",
    }
    session = FakeSession(result)
    fake_frida = SimpleNamespace(attach=lambda process: session)
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    observed = probe_loaded_module("WhatsApp.exe")

    assert observed == result
    assert session.script.loaded is True
    assert session.script.unloaded is True
    assert session.detached is True


def test_probe_missing_module_fails_closed_and_cleans_up(monkeypatch):
    session = FakeSession(None)
    fake_frida = SimpleNamespace(attach=lambda process: session)
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    with pytest.raises(ProbeError, match="not loaded"):
        probe_loaded_module("WhatsApp.exe")

    assert session.script.unloaded is True
    assert session.detached is True


def test_probe_validation_requires_exact_path_size_and_base():
    remote = {
        "name": "WhatsAppNative.Voip.dll",
        "base": "0x10000000",
        "size": 4096,
        "path": r"C:\Program Files\WhatsApp\WhatsAppNative.Voip.dll",
    }
    result = validate_probe(
        r"c:\program files\whatsapp\WhatsAppNative.Voip.dll",
        4096,
        remote,
    )
    assert result["valid"] is True
    assert all(result["checks"].values())


def test_probe_validation_rejects_stale_loaded_module():
    remote = {
        "name": "WhatsAppNative.Voip.dll",
        "base": "0x10000000",
        "size": 8192,
        "path": r"C:\Old\WhatsAppNative.Voip.dll",
    }
    result = validate_probe(
        r"C:\Current\WhatsAppNative.Voip.dll",
        4096,
        remote,
    )
    assert result["valid"] is False
    assert result["checks"]["module_path"] is False
    assert result["checks"]["module_size"] is False
