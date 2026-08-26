from peerlens.cli import build_parser, cmd_capture


def test_parser_accepts_lab_capture():
    parser = build_parser()
    args = parser.parse_args(["capture", "--adapter", "lab", "--seconds", "1"])
    assert args.adapter == "lab"
    assert args.seconds == 1


def test_capture_rejects_non_positive_duration(capsys):
    parser = build_parser()
    args = parser.parse_args(["capture", "--adapter", "lab", "--seconds", "0"])
    assert cmd_capture(args) == 2
    assert "greater than zero" in capsys.readouterr().err


def test_parser_accepts_whatsapp_status():
    parser = build_parser()
    args = parser.parse_args(["whatsapp", "status"])
    assert args.whatsapp_command == "status"


def test_parser_accepts_whatsapp_fingerprint():
    parser = build_parser()
    args = parser.parse_args(["whatsapp", "fingerprint", "sample.dll", "--compact"])
    assert args.path == "sample.dll"
    assert args.compact is True


def test_parser_accepts_whatsapp_profile_create():
    parser = build_parser()
    args = parser.parse_args(
        [
            "whatsapp",
            "profile",
            "create",
            "sample.dll",
            "--id",
            "wa-test",
            "--output",
            "profiles.json",
        ]
    )
    assert args.profile_command == "create"
    assert args.id == "wa-test"


def test_parser_accepts_whatsapp_profile_check():
    parser = build_parser()
    args = parser.parse_args(
        [
            "whatsapp",
            "profile",
            "check",
            "sample.dll",
            "--profiles",
            "profiles.json",
        ]
    )
    assert args.profile_command == "check"


def test_parser_accepts_whatsapp_locate():
    parser = build_parser()
    args = parser.parse_args(["whatsapp", "locate", "--compact"])
    assert args.whatsapp_command == "locate"
    assert args.compact is True


def test_parser_accepts_whatsapp_preflight():
    parser = build_parser()
    args = parser.parse_args(
        ["whatsapp", "preflight", "--profiles", "profiles.json", "--compact"]
    )
    assert args.whatsapp_command == "preflight"
    assert args.profiles == "profiles.json"
    assert args.compact is True


def test_parser_accepts_whatsapp_probe():
    parser = build_parser()
    args = parser.parse_args(
        ["whatsapp", "probe", "--profiles", "profiles.json", "--compact"]
    )
    assert args.whatsapp_command == "probe"
    assert args.profiles == "profiles.json"
    assert args.compact is True
