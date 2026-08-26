import json

import pytest

from peerlens.core.binary import BinaryFingerprint
from peerlens.core.profiles import BuildProfile, ProfileStore, write_profile_file


HASH_A = "a" * 64
HASH_B = "b" * 64


def fingerprint(sha256: str = HASH_A) -> BinaryFingerprint:
    return BinaryFingerprint(
        path="sample.dll",
        size=100,
        sha256=sha256,
        format="pe",
        architecture="x86_64",
        pe_machine=0x8664,
        pe_timestamp=1,
        size_of_image=4096,
    )


def test_profile_requires_exact_sha256_match():
    profile = BuildProfile(
        id="wa-test",
        sha256=HASH_A,
        architecture="x86_64",
        size_of_image=4096,
    )
    assert profile.matches(fingerprint(HASH_A)) is True
    assert profile.matches(fingerprint(HASH_B)) is False


def test_profile_store_round_trip(tmp_path):
    path = tmp_path / "profiles.json"
    profile = BuildProfile(id="wa-test", sha256=HASH_A, architecture="x86_64")
    write_profile_file(path, [profile])
    store = ProfileStore.load(path)
    assert store.match(fingerprint()) == profile


def test_profile_store_rejects_duplicate_ids(tmp_path):
    path = tmp_path / "profiles.json"
    payload = {
        "schema_version": 1,
        "profiles": [
            {"id": "same", "sha256": HASH_A},
            {"id": "same", "sha256": HASH_B},
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        ProfileStore.load(path)


def test_profile_rejects_invalid_hash():
    with pytest.raises(ValueError, match="invalid sha256"):
        BuildProfile(id="bad", sha256="1234")
