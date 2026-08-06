from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from pua_inspector.config import AppSettings, expand_windows_path
from pua_inspector.models import Finding, FindingStatus


class RemediationService:
    def __init__(self, settings: AppSettings):
        self.settings = settings

    def remediate(self, finding: Finding) -> tuple[bool, str]:
        handlers = {
            "quarantine_path": self._quarantine_path,
            "registry_value": self._remove_registry_value,
            "scheduled_task": self._remove_scheduled_task,
            "service": self._disable_service,
        }
        handler = handlers.get(finding.remediation_type)
        if not handler:
            finding.status = FindingStatus.FAILED
            return False, "This finding requires manual remediation."
        try:
            message = handler(finding)
            finding.status = FindingStatus.REMEDIATED
            return True, message
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            finding.status = FindingStatus.FAILED
            return False, str(error)

    def _quarantine_path(self, finding: Finding) -> str:
        source = Path(str(finding.remediation_data.get("path") or ""))
        if not source.exists():
            raise RuntimeError(f"Path no longer exists: {source}")
        quarantine = expand_windows_path(self.settings.quarantine_directory)
        quarantine.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        destination = quarantine / f"{stamp}-{source.name}"
        shutil.move(str(source), destination)
        finding.details["quarantine_path"] = str(destination)
        return f"Moved to quarantine: {destination}"

    def _remove_registry_value(self, finding: Finding) -> str:
        data = finding.remediation_data
        path = _ps_quote(str(data.get("RegistryPath") or ""))
        name = _ps_quote(str(data.get("Name") or ""))
        if not path or not name:
            raise RuntimeError("Registry path or value name is missing")
        self._run_powershell(f"Remove-ItemProperty -LiteralPath '{path}' -Name '{name}' -Force")
        return f"Removed registry value {name}"

    def _remove_scheduled_task(self, finding: Finding) -> str:
        data = finding.remediation_data
        task_name = _ps_quote(str(data.get("TaskName") or ""))
        task_path = _ps_quote(str(data.get("TaskPath") or "\\"))
        if not task_name:
            raise RuntimeError("Scheduled task name is missing")
        self._run_powershell(
            f"Unregister-ScheduledTask -TaskName '{task_name}' -TaskPath '{task_path}' -Confirm:$false"
        )
        return f"Removed scheduled task {task_path}{task_name}"

    def _disable_service(self, finding: Finding) -> str:
        name = _ps_quote(str(finding.remediation_data.get("Name") or ""))
        if not name:
            raise RuntimeError("Service name is missing")
        self._run_powershell(
            f"Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue; "
            f"Set-Service -Name '{name}' -StartupType Disabled"
        )
        return f"Stopped and disabled service {name}"

    @staticmethod
    def _run_powershell(script: str) -> None:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                f"$ErrorActionPreference='Stop'; {script}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "Remediation command failed")


def _ps_quote(value: str) -> str:
    return value.replace("'", "''").strip()

