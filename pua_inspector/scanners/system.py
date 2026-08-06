from __future__ import annotations

from pathlib import Path

from pua_inspector.models import Finding
from pua_inspector.scanners.base import (
    ScanContext,
    Scanner,
    find_known_app,
    finding_for_app,
    finding_from_record,
    reject_admin_share_mode,
    review_finding,
)
from pua_inspector.scanners.powershell import run_for_context
from pua_inspector.task_inventory import query_scheduled_tasks


class ScheduledTasksScanner(Scanner):
    name = "Scheduled Tasks"

    def scan(self, context: ScanContext) -> list[Finding]:
        if context.admin_share_mode:
            records = [
                task.to_scan_record()
                for task in query_scheduled_tasks(context.hostname, remote=True)
            ]
            return _match_records(
                context,
                self.name,
                records,
                ("TaskName", "Execute", "Status", "Author", "Comment"),
                "TaskName",
                "Execute",
                "manual",
            )
        script = r"""
Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
  $task = $_
  foreach ($action in $task.Actions) {
    [PSCustomObject]@{
      TaskName=$task.TaskName; TaskPath=$task.TaskPath; State=[string]$task.State
      Execute=$action.Execute; Arguments=$action.Arguments
      Location=($task.TaskPath + $task.TaskName)
    }
  }
}
"""
        return _match_records(
            context,
            self.name,
            run_for_context(context, script),
            ("TaskName", "TaskPath", "Execute", "Arguments"),
            "Location",
            "Execute",
            "scheduled_task",
        )
class ServicesScanner(Scanner):
    name = "Windows Services"

    def scan(self, context: ScanContext) -> list[Finding]:
        reject_admin_share_mode(context, self.name)
        script = r"""
Get-CimInstance Win32_Service -ErrorAction Stop |
  Select-Object Name, DisplayName, State, StartMode, PathName
"""
        return _match_records(
            context,
            self.name,
            run_for_context(context, script),
            ("Name", "DisplayName", "PathName"),
            "Name",
            "PathName",
            "service",
        )


class RunningProcessesScanner(Scanner):
    name = "Running Processes"

    def scan(self, context: ScanContext) -> list[Finding]:
        reject_admin_share_mode(context, self.name)
        script = r"""
Get-CimInstance Win32_Process -ErrorAction Stop |
  Select-Object Name, ProcessId, ExecutablePath, CommandLine
"""
        return _match_records(
            context,
            self.name,
            run_for_context(context, script),
            ("Name", "ExecutablePath", "CommandLine"),
            "ExecutablePath",
            "ExecutablePath",
            "process",
        )


class WmiPersistenceScanner(Scanner):
    name = "WMI Persistence"

    def scan(self, context: ScanContext) -> list[Finding]:
        reject_admin_share_mode(context, self.name)
        script = r"""
$namespace = 'root\subscription'
Get-CimInstance -Namespace $namespace -ClassName CommandLineEventConsumer -ErrorAction Stop |
  Select-Object Name, CommandLineTemplate, ExecutablePath, @{N='Type';E={'CommandLineEventConsumer'}}
Get-CimInstance -Namespace $namespace -ClassName ActiveScriptEventConsumer -ErrorAction Stop |
  Select-Object Name, ScriptingEngine, ScriptText, @{N='Type';E={'ActiveScriptEventConsumer'}}
"""
        records = run_for_context(context, script)
        findings = []
        for record in records:
            searchable = " ".join(str(value or "") for value in record.values())
            app = find_known_app(searchable, context.known_apps)
            if app:
                findings.append(
                    finding_for_app(
                        app,
                        self.name,
                        str(record.get("Name") or record.get("Type") or "WMI consumer"),
                        executable=str(record.get("ExecutablePath") or ""),
                        remediation_type="wmi_consumer",
                        remediation_data=record,
                        details=record,
                    )
                )
        return findings


class HostsFileScanner(Scanner):
    name = "Hosts File"

    def scan(self, context: ScanContext) -> list[Finding]:
        if context.admin_share_mode:
            path = context.admin_root / "Windows" / "System32" / "drivers" / "etc" / "hosts"
            return self._find_records(context, _read_hosts_file(path))
        script = r"""
$path = "$env:SystemRoot\System32\drivers\etc\hosts"
$lineNumber = 0
Get-Content $path -ErrorAction Stop | ForEach-Object {
  $lineNumber++
  $line = $_.Trim()
  if ($line -and -not $line.StartsWith('#')) {
    $parts = $line -split '\s+'
    if ($parts.Count -ge 2 -and $parts[1] -notin @('localhost','localhost.localdomain')) {
      [PSCustomObject]@{Line=$lineNumber; Address=$parts[0]; Hostname=$parts[1]; Path=$path}
    }
  }
}
"""
        return self._find_records(context, run_for_context(context, script))

    def _find_records(self, context: ScanContext, records: list[dict]) -> list[Finding]:
        findings = []
        for record in records:
            searchable = f"{record.get('Hostname', '')} {record.get('Address', '')}"
            app = find_known_app(searchable, context.known_apps)
            if app:
                findings.append(
                    finding_for_app(
                        app,
                        self.name,
                        f"{record.get('Path')}:{record.get('Line')}",
                        details=record,
                    )
                )
            else:
                findings.append(
                    review_finding(
                        str(record.get("Hostname") or "Hosts entry"),
                        self.name,
                        f"{record.get('Path')}:{record.get('Line')}",
                        record,
                    )
                )
        return findings


def _read_hosts_file(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            content = raw_line.split("#", 1)[0].strip()
            if not content:
                continue
            parts = content.split()
            if len(parts) < 2:
                continue
            for hostname in parts[1:]:
                if hostname.casefold() in {"localhost", "localhost.localdomain"}:
                    continue
                records.append(
                    {
                        "Line": line_number,
                        "Address": parts[0],
                        "Hostname": hostname,
                        "Path": str(path),
                    }
                )
    return records


def _match_records(
    context: ScanContext,
    category: str,
    records: list[dict],
    searchable_fields: tuple[str, ...],
    location_field: str,
    command_field: str,
    remediation_type: str,
) -> list[Finding]:
    findings = []
    for record in records:
        finding = finding_from_record(
            record,
            context,
            category,
            searchable_fields,
            location_field,
            command_field,
            remediation_type,
        )
        if finding:
            findings.append(finding)
    return findings
