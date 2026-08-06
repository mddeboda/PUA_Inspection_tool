from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RecentChange:
    short_hash: str
    date: str
    subject: str


def load_recent_changes(
    repository: Path | None = None,
    limit: int = 5,
    timeout_seconds: int = 5,
) -> list[RecentChange]:
    if not 1 <= limit <= 20:
        raise ValueError("Changelog limit must be between 1 and 20")
    root = repository or Path(__file__).resolve().parent.parent
    command = [
        "git",
        "-C",
        str(root),
        "log",
        "-n",
        str(limit),
        "--date=short",
        "--pretty=format:%h%x1f%ad%x1f%s",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Git is not installed or is not available on PATH") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Git history lookup timed out") from error
    if completed.returncode != 0:
        raise RuntimeError("Git history is unavailable for this installation")

    changes = []
    for line in completed.stdout.splitlines():
        parts = line.split("\x1f", 2)
        if len(parts) == 3:
            changes.append(RecentChange(*parts))
    return changes


def format_recent_changes(changes: list[RecentChange]) -> str:
    if not changes:
        return "No Git changes are available."
    return "\n\n".join(
        f"{change.date}  {change.short_hash}\n{change.subject}" for change in changes
    )
