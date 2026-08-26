from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import sys

from peerlens import __version__
from peerlens.adapters import registry
from peerlens.adapters.base import AdapterError
from peerlens.core.binary import fingerprint_binary
from peerlens.core.session import CaptureSession, read_events
from peerlens.core.profiles import BuildProfile, ProfileStore, write_profile_file
from peerlens.reporting.json_report import summarize
from peerlens.adapters.whatsapp_desktop import WhatsAppDesktopAdapter


def _status(ok: bool) -> str:
    return "OK" if ok else "WARN"


def cmd_doctor(args: argparse.Namespace) -> int:
    print(f"PeerLens {__version__}")
    print(f"Python {platform.python_version()} | {platform.system()} {platform.release()}")
    print()
    failed = False
    for name, adapter in registry().items():
        print(f"[{name}]")
        for check, ok, detail in adapter.doctor():
            print(f"  {_status(ok):4}  {check}: {detail}")
            failed = failed or not ok
        print()
    return 1 if failed and args.strict else 0


def cmd_adapters(_: argparse.Namespace) -> int:
    for adapter in registry().values():
        mode = "capture" if adapter.info.live_capture else "discovery"
        print(f"{adapter.info.name:20} {mode:10} {adapter.info.summary}")
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    if args.seconds <= 0:
        print("--seconds must be greater than zero", file=sys.stderr)
        return 2

    adapters = registry()
    adapter = adapters.get(args.adapter)
    if adapter is None:
        print(f"unknown adapter: {args.adapter}", file=sys.stderr)
        return 2
    if not adapter.info.live_capture:
        print(
            f"adapter '{args.adapter}' does not expose live capture in this release",
            file=sys.stderr,
        )
        return 3

    session = CaptureSession.create(Path(args.out), args.adapter)
    try:
        adapter.capture(args.seconds, session.append)
    except KeyboardInterrupt:
        session.finalize("cancelled")
        print(session.root)
        return 130
    except (AdapterError, RuntimeError, OSError) as exc:
        session.finalize("failed", str(exc))
        print(f"capture failed: {exc}", file=sys.stderr)
        print(session.root, file=sys.stderr)
        return 4
    except Exception as exc:
        session.finalize("failed", f"unexpected error: {exc}")
        raise
    else:
        session.finalize("completed")

    print(session.root)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.events)
    if not path.is_file():
        print(f"events file not found: {path}", file=sys.stderr)
        return 2
    try:
        result = summarize(read_events(path))
    except (OSError, ValueError) as exc:
        print(f"could not read capture: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(args.output)
    else:
        print(text)
    return 0


def cmd_whatsapp_status(_: argparse.Namespace) -> int:
    adapter = WhatsAppDesktopAdapter()
    for check, ok, detail in adapter.doctor():
        print(f"{_status(ok):4}  {check}: {detail}")
    return 0


def cmd_whatsapp_fingerprint(args: argparse.Namespace) -> int:
    try:
        result = fingerprint_binary(Path(args.path)).to_dict()
    except (OSError, ValueError) as exc:
        print(f"could not fingerprint binary: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=None if args.compact else 2, ensure_ascii=False))
    return 0


def cmd_whatsapp_profile_create(args: argparse.Namespace) -> int:
    try:
        fingerprint = fingerprint_binary(Path(args.path))
        profile = BuildProfile(
            id=args.id,
            sha256=fingerprint.sha256,
            application_version=args.version,
            architecture=fingerprint.architecture,
            size_of_image=fingerprint.size_of_image,
            verified=False,
        )
        output = Path(args.output)
        write_profile_file(output, [profile])
    except (OSError, ValueError) as exc:
        print(f"could not create profile: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


def cmd_whatsapp_profile_check(args: argparse.Namespace) -> int:
    try:
        fingerprint = fingerprint_binary(Path(args.path))
        store = ProfileStore.load(Path(args.profiles))
        profile = store.match(fingerprint)
    except (OSError, ValueError, TypeError) as exc:
        print(f"could not check profile: {exc}", file=sys.stderr)
        return 2
    result = {
        "matched": profile is not None,
        "fingerprint": fingerprint.to_dict(),
        "profile": profile.to_dict() if profile else None,
    }
    print(json.dumps(result, indent=None if args.compact else 2, ensure_ascii=False))
    return 0 if profile else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="peerlens")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check local platform and adapters")
    doctor.add_argument("--strict", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    adapters = sub.add_parser("adapters", help="list available adapters")
    adapters.set_defaults(func=cmd_adapters)

    capture = sub.add_parser("capture", help="start a capture session")
    capture.add_argument("--adapter", required=True)
    capture.add_argument("--seconds", type=float, default=5.0)
    capture.add_argument("--out", default="./captures")
    capture.set_defaults(func=cmd_capture)

    report = sub.add_parser("report", help="summarize an events.jsonl capture")
    report.add_argument("events")
    report.add_argument("--output")
    report.set_defaults(func=cmd_report)

    whatsapp = sub.add_parser("whatsapp", help="WhatsApp Desktop discovery tools")
    whatsapp_sub = whatsapp.add_subparsers(dest="whatsapp_command", required=True)

    whatsapp_status = whatsapp_sub.add_parser("status", help="show local WhatsApp Desktop status")
    whatsapp_status.set_defaults(func=cmd_whatsapp_status)

    whatsapp_fingerprint = whatsapp_sub.add_parser(
        "fingerprint", help="fingerprint a WhatsApp PE binary or DLL"
    )
    whatsapp_fingerprint.add_argument("path")
    whatsapp_fingerprint.add_argument("--compact", action="store_true")
    whatsapp_fingerprint.set_defaults(func=cmd_whatsapp_fingerprint)

    whatsapp_profile = whatsapp_sub.add_parser("profile", help="manage exact binary profiles")
    profile_sub = whatsapp_profile.add_subparsers(dest="profile_command", required=True)

    profile_create = profile_sub.add_parser("create", help="create an exact profile from a binary")
    profile_create.add_argument("path")
    profile_create.add_argument("--id", required=True)
    profile_create.add_argument("--version")
    profile_create.add_argument("--output", required=True)
    profile_create.set_defaults(func=cmd_whatsapp_profile_create)

    profile_check = profile_sub.add_parser("check", help="match a binary against a profile file")
    profile_check.add_argument("path")
    profile_check.add_argument("--profiles", required=True)
    profile_check.add_argument("--compact", action="store_true")
    profile_check.set_defaults(func=cmd_whatsapp_profile_check)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
