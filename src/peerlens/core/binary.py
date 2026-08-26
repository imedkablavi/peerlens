from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import struct


MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "arm64",
}


@dataclass(frozen=True, slots=True)
class BinaryFingerprint:
    path: str
    size: int
    sha256: str
    format: str
    architecture: str | None = None
    pe_machine: int | None = None
    pe_timestamp: int | None = None
    size_of_image: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_pe_metadata(path: Path) -> dict:
    with path.open("rb") as handle:
        dos = handle.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            return {"format": "unknown"}

        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        handle.seek(pe_offset)
        header = handle.read(24)
        if len(header) < 24 or header[:4] != b"PE\0\0":
            return {"format": "mz"}

        machine = struct.unpack_from("<H", header, 4)[0]
        timestamp = struct.unpack_from("<I", header, 8)[0]
        optional_size = struct.unpack_from("<H", header, 20)[0]
        optional = handle.read(optional_size)
        size_of_image = None
        if len(optional) >= 60:
            size_of_image = struct.unpack_from("<I", optional, 56)[0]

        return {
            "format": "pe",
            "architecture": MACHINE_NAMES.get(machine, f"machine-0x{machine:04x}"),
            "pe_machine": machine,
            "pe_timestamp": timestamp,
            "size_of_image": size_of_image,
        }


def fingerprint_binary(path: Path) -> BinaryFingerprint:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    metadata = _read_pe_metadata(resolved)
    return BinaryFingerprint(
        path=str(resolved),
        size=resolved.stat().st_size,
        sha256=_sha256(resolved),
        format=metadata["format"],
        architecture=metadata.get("architecture"),
        pe_machine=metadata.get("pe_machine"),
        pe_timestamp=metadata.get("pe_timestamp"),
        size_of_image=metadata.get("size_of_image"),
    )
