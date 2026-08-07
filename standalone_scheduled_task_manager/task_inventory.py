from __future__ import annotations

import csv
import io
import locale
import re
import subprocess
from dataclasses import dataclass


_HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


def validate_hostname(hostname: str) -> str:
    target = hostname.strip()
    if target in {".", "localhost"}:
        return target
    if not target or not _HOSTNAME_PATTERN.fullmatch(target):
        raise ValueError("Hostname contains unsupported characters")
    return target


@dataclass(frozen=True)
class ScheduledTaskRecord:
    hostname: str
    task_name: str
    status: str = ""
    action: str = ""
    author: str = ""
    run_as_user: str = ""
    last_run_time: str = ""
    next_run_time: str = ""
    last_result: str = ""
    start_in: str = ""
    comment: str = ""

    @property
    def cache_key(self) -> tuple[str, str]:
        return self.hostname.casefold(), self.task_name.casefold()

    @property
    def is_microsoft_windows_task(self) -> bool:
        return self.task_name.casefold().startswith("\\microsoft\\windows\\")

    @property
    def is_disabled(self) -> bool:
        return self.status.casefold() == "disabled"

    @property
    def is_empty(self) -> bool:
        empty = {"", "n/a", "none", "not available"}
        fields = (
            self.status,
            self.action,
            self.author,
            self.run_as_user,
            self.last_run_time,
            self.next_run_time,
            self.last_result,
            self.start_in,
            self.comment,
        )
        return all(value.strip().casefold() in empty for value in fields)

    def searchable_text(self) -> str:
        return " ".join(
            (
                self.hostname,
                self.task_name,
                self.status,
                self.action,
                self.author,
                self.run_as_user,
                self.comment,
            )
        ).casefold()


def query_task_summaries(hostname: str, *, remote: bool, timeout_seconds: int = 30) -> list[ScheduledTaskRecord]:
    return _run_query(hostname, remote=remote, verbose=False, timeout_seconds=timeout_seconds)


def query_scheduled_tasks(hostname: str, *, remote: bool, verbose: bool = True, timeout_seconds: int = 60) -> list[ScheduledTaskRecord]:
    return _run_query(hostname, remote=remote, verbose=verbose, timeout_seconds=timeout_seconds)


def query_task_details(hostname: str, task_name: str, *, remote: bool, timeout_seconds: int = 30) -> ScheduledTaskRecord:
    name = _validate_task_name(task_name)
    records = _run_query(
        hostname,
        remote=remote,
        verbose=True,
        task_name=name,
        timeout_seconds=timeout_seconds,
    )
    if not records:
        raise RuntimeError(f"Scheduled task is no longer available: {name}")
    return records[0]


def set_task_enabled(hostname: str, task_name: str, *, enabled: bool, remote: bool, timeout_seconds: int = 30) -> str:
    command = _action_command(hostname, "change", task_name, remote=remote)
    command.append("/enable" if enabled else "/disable")
    return _run_action(command, timeout_seconds)


def delete_scheduled_task(hostname: str, task_name: str, *, remote: bool, timeout_seconds: int = 30) -> str:
    command = _action_command(hostname, "delete", task_name, remote=remote)
    command.append("/f")
    return _run_action(command, timeout_seconds)


def _action_command(hostname: str, operation: str, task_name: str, *, remote: bool) -> list[str]:
    target = validate_hostname(hostname)
    name = _validate_task_name(task_name)
    if name.casefold().startswith("\\microsoft\\windows\\"):
        raise ValueError("Microsoft Windows system tasks are protected from changes")
    command = ["schtasks.exe", f"/{operation}"]
    if remote:
        command.extend(("/s", target))
    command.extend(("/tn", name))
    return command


def _run_action(command: list[str], timeout_seconds: int) -> str:
    completed = _run(command, timeout_seconds, "action")
    return completed.stdout.strip() or "Scheduled-task action completed successfully."


def _run_query(hostname: str, *, remote: bool, verbose: bool, timeout_seconds: int, task_name: str = "") -> list[ScheduledTaskRecord]:
    target = validate_hostname(hostname)
    command = ["schtasks.exe", "/query"]
    if remote:
        command.extend(("/s", target))
    if task_name:
        command.extend(("/tn", _validate_task_name(task_name)))
    command.extend(("/fo", "CSV"))
    if verbose:
        command.append("/v")
    completed = _run(command, timeout_seconds, "query")
    return parse_scheduled_tasks_csv(completed.stdout, default_hostname=target)


def _run(command: list[str], timeout_seconds: int, operation: str) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("schtasks.exe is not available; run this application on Windows") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Scheduled-task {operation} timed out after {timeout_seconds} seconds") from error
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(message or f"Scheduled-task {operation} failed")
    return completed


def parse_scheduled_tasks_csv(output: str, *, default_hostname: str = "") -> list[ScheduledTaskRecord]:
    rows = list(csv.reader(io.StringIO(output.lstrip("\ufeff"))))
    header_index = next((index for index, row in enumerate(rows) if len(row) >= 3), None)
    if header_index is None:
        return []
    headers = rows[header_index]
    canonical_headers = [_canonical_header(header) for header in headers]
    has_hostname = "hostname" in canonical_headers
    records: list[ScheduledTaskRecord] = []
    for values in rows[header_index + 1 :]:
        if not values or not any(value.strip() for value in values):
            continue
        padded = values + [""] * max(0, len(headers) - len(values))
        if [_canonical_header(value) for value in padded[: len(headers)]] == canonical_headers:
            continue
        row = dict(zip(canonical_headers, padded, strict=False))
        task_name = _field(row, padded, ("taskname",), 1 if has_hostname else 0)
        if not task_name:
            continue
        records.append(
            ScheduledTaskRecord(
                hostname=(row.get("hostname") or default_hostname).strip(),
                task_name=task_name,
                next_run_time=_field(row, padded, ("nextruntime",), 2 if has_hostname else 1),
                status=_field(row, padded, ("status",), 3 if has_hostname else 2),
                last_run_time=_field(row, padded, ("lastruntime",), 5),
                last_result=_field(row, padded, ("lastresult",), 6),
                author=_field(row, padded, ("author",), 7),
                action=_field(row, padded, ("tasktorun", "action", "actions"), 8),
                start_in=_field(row, padded, ("startin",), 9),
                comment=_field(row, padded, ("comment", "description"), 10),
                run_as_user=_field(row, padded, ("runasuser",), 14),
            )
        )
    return records


def _canonical_header(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _validate_task_name(task_name: str) -> str:
    name = task_name.strip()
    if not name or len(name) > 500 or any(ord(character) < 32 for character in name):
        raise ValueError("Scheduled task name is invalid")
    return name


def _field(row: dict[str, str], values: list[str], names: tuple[str, ...], fallback_index: int) -> str:
    for name in names:
        if value := row.get(name):
            return value.strip()
    return values[fallback_index].strip() if fallback_index < len(values) else ""
