from __future__ import annotations

import ntpath
from typing import Any

from peerlens.adapters.whatsapp_locator import VOIP_MODULE

MODULE_PROBE_AGENT = r"""
'use strict';

function findModule(name) {
  try {
    if (typeof Process.findModuleByName === 'function') {
      var direct = Process.findModuleByName(name);
      if (direct) return direct;
    }
  } catch (e) {}

  var lower = String(name).toLowerCase();
  var modules = Process.enumerateModules();
  for (var i = 0; i < modules.length; i++) {
    if (String(modules[i].name).toLowerCase() === lower) return modules[i];
  }
  return null;
}

rpc.exports = {
  inspect: function(name) {
    var module = findModule(name);
    if (!module) return null;
    return {
      name: module.name,
      base: module.base.toString(),
      size: module.size,
      path: module.path
    };
  }
};
"""


class ProbeError(RuntimeError):
    pass


def probe_loaded_module(process_name: str, module_name: str = VOIP_MODULE) -> dict[str, Any]:
    try:
        import frida
    except ImportError as exc:
        raise ProbeError("Frida is not installed") from exc

    session = None
    script = None
    try:
        session = frida.attach(process_name)
        script = session.create_script(MODULE_PROBE_AGENT)
        script.load()
        result = script.exports_sync.inspect(module_name)
        if not result:
            raise ProbeError(f"{module_name} is not loaded in {process_name}")
        if not isinstance(result, dict):
            raise ProbeError("Frida probe returned an invalid module record")
        return dict(result)
    except ProbeError:
        raise
    except Exception as exc:
        raise ProbeError(f"Frida probe failed: {exc}") from exc
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def _windows_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value))


def validate_probe(expected_module: str, size_of_image: int | None, remote: dict) -> dict:
    remote_name = str(remote.get("name") or "")
    remote_path = str(remote.get("path") or "")
    try:
        remote_size = int(remote.get("size"))
    except (TypeError, ValueError):
        remote_size = None

    checks = {
        "module_name": remote_name.casefold() == VOIP_MODULE.casefold(),
        "module_path": bool(remote_path)
        and _windows_path(remote_path) == _windows_path(expected_module),
        "module_size": size_of_image is not None and remote_size == size_of_image,
        "base_address": bool(remote.get("base")),
    }

    reasons: list[str] = []
    if not checks["module_name"]:
        reasons.append("loaded module name does not match the expected VoIP module")
    if not checks["module_path"]:
        reasons.append("loaded module path does not match the verified on-disk module")
    if not checks["module_size"]:
        reasons.append("loaded module size does not match PE SizeOfImage")
    if not checks["base_address"]:
        reasons.append("loaded module base address was not returned")

    return {
        "valid": all(checks.values()),
        "checks": checks,
        "module": remote,
        "reasons": reasons,
    }
