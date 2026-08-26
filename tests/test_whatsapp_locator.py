from pathlib import Path

from peerlens.adapters.whatsapp_locator import locate_whatsapp


def test_locator_prefers_running_process_module(tmp_path):
    app = tmp_path / "WhatsApp"
    app.mkdir()
    executable = app / "WhatsApp.exe"
    executable.write_bytes(b"exe")
    module = app / "WhatsAppNative.Voip.dll"
    module.write_bytes(b"dll")

    result = locate_whatsapp(env={}, process_paths=[executable])

    assert len(result) == 1
    assert result[0].source == "running-process"
    assert result[0].executable == str(executable.resolve())
    assert result[0].module == str(module.resolve())


def test_locator_finds_module_under_known_local_root(tmp_path):
    local = tmp_path / "Local"
    module = local / "Programs" / "WhatsApp" / "current" / "WhatsAppNative.Voip.dll"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"dll")

    result = locate_whatsapp(env={"LOCALAPPDATA": str(local)}, process_paths=[])

    assert len(result) == 1
    assert result[0].source == "known-install-root"
    assert result[0].executable is None
    assert result[0].module == str(module.resolve())


def test_locator_deduplicates_running_and_known_root(tmp_path):
    local = tmp_path / "Local"
    app = local / "Programs" / "WhatsApp"
    app.mkdir(parents=True)
    executable = app / "WhatsApp.exe"
    executable.write_bytes(b"exe")
    (app / "WhatsAppNative.Voip.dll").write_bytes(b"dll")

    result = locate_whatsapp(
        env={"LOCALAPPDATA": str(local)},
        process_paths=[executable],
    )

    assert len(result) == 1
    assert result[0].source == "running-process"


def test_locator_returns_empty_when_no_install_is_present(tmp_path):
    result = locate_whatsapp(
        env={"LOCALAPPDATA": str(tmp_path / "missing")},
        process_paths=[],
    )
    assert result == []
