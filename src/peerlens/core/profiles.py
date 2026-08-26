from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from typing import Any

from peerlens.core.binary import BinaryFingerprint

PROFILE_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True, slots=True)
class BuildProfile:
    id: str
    sha256: str
    application_version: str | None = None
    architecture: str | None = None
    size_of_image: int | None = None
    verified: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("profile id must not be empty")
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError(f"profile {self.id}: invalid sha256")
        if self.size_of_image is not None and self.size_of_image <= 0:
            raise ValueError(f"profile {self.id}: size_of_image must be positive")

    def matches(self, fingerprint: BinaryFingerprint) -> bool:
        if self.sha256.lower() != fingerprint.sha256.lower():
            return False
        if self.architecture and self.architecture != fingerprint.architecture:
            return False
        if self.size_of_image is not None and self.size_of_image != fingerprint.size_of_image:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProfileStore:
    profiles: tuple[BuildProfile, ...]

    @classmethod
    def load(cls, path: Path) -> "ProfileStore":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("profile file must contain a JSON object")
        if payload.get("schema_version") != PROFILE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported profile schema version: {payload.get('schema_version')}"
            )
        rows = payload.get("profiles")
        if not isinstance(rows, list):
            raise ValueError("profiles must be a JSON array")
        profiles = tuple(BuildProfile(**row) for row in rows)
        ids = [profile.id for profile in profiles]
        if len(ids) != len(set(ids)):
            raise ValueError("profile ids must be unique")
        return cls(profiles)

    def match(self, fingerprint: BinaryFingerprint) -> BuildProfile | None:
        matches = [profile for profile in self.profiles if profile.matches(fingerprint)]
        if len(matches) > 1:
            raise ValueError("multiple profiles match the same binary fingerprint")
        return matches[0] if matches else None


def write_profile_file(path: Path, profiles: list[BuildProfile]) -> None:
    payload = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profiles": [profile.to_dict() for profile in profiles],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
