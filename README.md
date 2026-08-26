<div align="center">

# PeerLens

Command-line framework for authorized chat-call metadata research.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-2f2f2f.svg)](LICENSE)
[![Interface](https://img.shields.io/badge/Interface-CLI-2f2f2f.svg)](#usage)

</div>

## Overview

PeerLens provides a small, adapter-based CLI for collecting, normalizing, and reviewing call-related metadata from supported chat clients in environments you own or are authorized to test.

Capture data is written to local session files. The core does not require a browser, does not send telemetry, and does not perform third-party enrichment by default.

The current WhatsApp Desktop adapter provides environment and process discovery. Live metadata capture is not enabled for that adapter in the current release.

## Requirements

- Python 3.10 or newer
- Git
- Windows for WhatsApp Desktop discovery
- Frida only when using an adapter that requires runtime instrumentation

## Installation

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/imedkablavi/peerlens.git
cd peerlens
python -m venv .venv
```

Activate the environment.

Linux and macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install PeerLens:

```bash
python -m pip install -e .
```

Install optional Frida support when required:

```bash
python -m pip install -e ".[frida]"
```

## Usage

Check the local environment and adapter status:

```bash
peerlens doctor
```

List available adapters:

```bash
peerlens adapters
```

Inspect the local WhatsApp Desktop environment:

```bash
peerlens whatsapp status
```

Locate the installed WhatsApp VoIP module and fingerprint each candidate:

```bash
peerlens whatsapp locate
```

Run the instrumentation preflight against an exact build profile:

```bash
peerlens whatsapp preflight --profiles profiles.json
```

Verify the loaded VoIP module through Frida without installing function hooks:

```bash
peerlens whatsapp probe --profiles profiles.json
```

Fingerprint a WhatsApp executable or DLL before instrumentation work:

```bash
peerlens whatsapp fingerprint path\to\WhatsAppNative.Voip.dll
```

Create an exact build profile from a known binary:

```bash
peerlens whatsapp profile create path\to\WhatsAppNative.Voip.dll --id local-build --output profiles.json
```

Check a binary against that profile before using version-specific instrumentation:

```bash
peerlens whatsapp profile check path\to\WhatsAppNative.Voip.dll --profiles profiles.json
```

Run a local test capture:

```bash
peerlens capture --adapter lab --seconds 3 --out ./captures
```

Generate a JSON summary from a capture:

```bash
peerlens report ./captures/<session>/events.jsonl
```

Write the report to a file:

```bash
peerlens report ./captures/<session>/events.jsonl --output report.json
```

## Capture files

Each capture session has its own directory:

```text
captures/
└── <session>/
    ├── session.json
    └── events.jsonl
```

`session.json` stores capture metadata. `events.jsonl` stores the normalized event stream used by the reporting layer.

## Scope

PeerLens is intended for your own devices and accounts, consent-based research, training environments, and authorized security assessments.

## License

PeerLens is released under the MIT License.
