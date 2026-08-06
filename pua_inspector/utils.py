from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def run_powershell_json(script: str, timeout: int = 45) -> list[dict[str, Any]]:
    script = script.rstrip()
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$ErrorActionPreference='Stop'; "
            f"& {{ {script} }} | ConvertTo-Json -Depth 5 -Compress"
        ),
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell command failed")
    if not completed.stdout.strip():
        return []
    data = json.loads(completed.stdout)
    return data if isinstance(data, list) else [data]


def extract_executable(command_line: str) -> str:
    value = (command_line or "").strip()
    if not value:
        return ""
    if value.startswith('"'):
        closing_quote = value.find('"', 1)
        return value[1:closing_quote] if closing_quote > 0 else value.strip('"')
    lowered = value.casefold()
    marker = lowered.find(".exe")
    return value[: marker + 4] if marker >= 0 else value.split(maxsplit=1)[0]
