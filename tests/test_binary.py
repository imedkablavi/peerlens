import hashlib
import struct

from peerlens.core.binary import fingerprint_binary


def _fake_pe(machine: int = 0x8664, timestamp: int = 123456789, image_size: int = 0xC09000) -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<I", data, 0x88, timestamp)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 56, image_size)
    return bytes(data)


def test_fingerprint_reads_pe_identity(tmp_path):
    path = tmp_path / "WhatsAppNative.Voip.dll"
    content = _fake_pe()
    path.write_bytes(content)

    result = fingerprint_binary(path)

    assert result.format == "pe"
    assert result.architecture == "x86_64"
    assert result.pe_timestamp == 123456789
    assert result.size_of_image == 0xC09000
    assert result.sha256 == hashlib.sha256(content).hexdigest()


def test_fingerprint_handles_non_pe_file(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"not a PE file")
    result = fingerprint_binary(path)
    assert result.format == "unknown"
    assert result.architecture is None
