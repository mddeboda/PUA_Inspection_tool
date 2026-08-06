from __future__ import annotations

from pua_inspector.scanners.base import ScanContext
from pua_inspector.utils import run_powershell_json


def run_for_context(context: ScanContext, script: str, timeout: int = 45) -> list[dict]:
    if context.is_local:
        return run_powershell_json(script, timeout=timeout)
    escaped_hostname = context.hostname.replace("'", "''")
    remote_script = (
        f"Invoke-Command -ComputerName '{escaped_hostname}' -ScriptBlock {{ {script} }}"
    )
    return run_powershell_json(remote_script, timeout=timeout)

