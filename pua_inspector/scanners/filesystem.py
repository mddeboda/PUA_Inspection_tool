from __future__ import annotations

import json
import os
from pathlib import Path

from pua_inspector.models import Finding
from pua_inspector.scanners.base import (
    ScanContext,
    Scanner,
    find_known_app,
    finding_for_app,
)
from pua_inspector.scanners.powershell import run_for_context
from pua_inspector.utils import run_powershell_json


def _walk_directories(root: Path, max_depth: int, max_entries: int):
    if not root.exists():
        return
    root_depth = len(root.parts)
    count = 0
    for current, directories, _files in os.walk(root, onerror=lambda _error: None):
        current_path = Path(current)
        depth = len(current_path.parts) - root_depth
        if depth >= max_depth:
            directories.clear()
        for directory in directories:
            yield current_path / directory
            count += 1
            if count >= max_entries:
                return


def _first_executable(directory: Path) -> str:
    try:
        return str(next(directory.glob("*.exe")))
    except (StopIteration, OSError):
        return ""


class KnownDirectoryScanner(Scanner):
    environment_roots: tuple[str, ...] = ()

    def scan(self, context: ScanContext) -> list[Finding]:
        return scan_known_directories(context, self.name, self.roots(context))

    def roots(self, context: ScanContext) -> tuple[Path, ...]:
        if context.admin_share_mode:
            raise RuntimeError(f"{self.name} has no admin-share path mapping")
        if not context.is_local:
            raise RuntimeError(f"{self.name} requires a local scan or Admin Share / SMB mode")
        return tuple(
            Path(value)
            for environment_name in self.environment_roots
            if (value := os.getenv(environment_name))
        )


def scan_known_directories(
    context: ScanContext,
    category: str,
    roots: tuple[Path, ...],
    *,
    remediation_type: str = "quarantine_path",
    details: dict | None = None,
) -> list[Finding]:
    findings = []
    seen: set[str] = set()
    matched_parents: list[str] = []
    for root in roots:
        for directory in _walk_directories(
            root,
            context.settings.scan_path_depth,
            context.settings.max_files_per_location,
        ):
            normalized = str(directory).casefold()
            if any(normalized.startswith(parent + "\\") for parent in matched_parents):
                continue
            app = find_known_app(str(directory), context.known_apps)
            if not app or normalized in seen:
                continue
            seen.add(normalized)
            matched_parents.append(normalized)
            findings.append(
                finding_for_app(
                    app,
                    category,
                    str(directory),
                    executable=_first_executable(directory),
                    remediation_type=remediation_type,
                    remediation_data={"path": str(directory)},
                    details=dict(details or {}),
                )
            )
    return findings


class AppDataScanner(KnownDirectoryScanner):
    name = "AppData (Local, LocalLow, Roaming)"
    environment_roots = ("LOCALAPPDATA", "APPDATA")

    def roots(self, context: ScanContext) -> tuple[Path, ...]:
        if context.admin_share_mode:
            roots = []
            for profile in _remote_user_profiles(context):
                roots.extend(
                    (
                        profile / "AppData" / "Local",
                        profile / "AppData" / "LocalLow",
                        profile / "AppData" / "Roaming",
                    )
                )
            return tuple(roots)
        roots = list(super().roots(context))
        if user_profile := os.getenv("USERPROFILE"):
            roots.append(Path(user_profile) / "AppData" / "LocalLow")
        return tuple(roots)


class ProgramDataScanner(KnownDirectoryScanner):
    name = "ProgramData"
    environment_roots = ("PROGRAMDATA",)

    def roots(self, context: ScanContext) -> tuple[Path, ...]:
        if context.admin_share_mode:
            return (context.admin_root / "ProgramData",)
        return super().roots(context)


class StartupFoldersScanner(Scanner):
    name = "Startup Folders"

    def scan(self, context: ScanContext) -> list[Finding]:
        if context.admin_share_mode:
            roots = [
                profile
                / "AppData"
                / "Roaming"
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "Startup"
                for profile in _remote_user_profiles(context)
            ]
            roots.append(
                context.admin_root
                / "ProgramData"
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "Startup"
            )
            records = _shortcut_records_from_roots(tuple(roots), recursive=False)
            return _find_shortcut_records(context, self.name, records)
        script = r"""
$shell = New-Object -ComObject WScript.Shell
$folders = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
foreach ($folder in $folders) {
  Get-ChildItem $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
    $target = $_.FullName
    $arguments = ''
    if ($_.Extension -eq '.lnk') {
      $shortcut = $shell.CreateShortcut($_.FullName)
      $target = $shortcut.TargetPath
      $arguments = $shortcut.Arguments
    }
    [PSCustomObject]@{Name=$_.Name; Path=$_.FullName; Target=$target; Arguments=$arguments}
  }
}
"""
        return _find_shortcut_records(context, self.name, run_for_context(context, script))


class BrowserShortcutsScanner(Scanner):
    name = "Browser Shortcuts"

    def scan(self, context: ScanContext) -> list[Finding]:
        if context.admin_share_mode:
            roots = []
            for profile in _remote_user_profiles(context):
                roots.extend(
                    (
                        profile / "Desktop",
                        profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu",
                    )
                )
            roots.extend(
                (
                    context.admin_root / "Users" / "Public" / "Desktop",
                    context.admin_root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu",
                )
            )
            records = _shortcut_records_from_roots(
                tuple(roots), recursive=True, browser_only=True
            )
            return _find_shortcut_records(context, self.name, records)
        script = r"""
$shell = New-Object -ComObject WScript.Shell
$roots = @(
  [Environment]::GetFolderPath('Desktop'),
  [Environment]::GetFolderPath('CommonDesktopDirectory'),
  "$env:APPDATA\Microsoft\Windows\Start Menu",
  "$env:PROGRAMDATA\Microsoft\Windows\Start Menu"
)
foreach ($root in $roots) {
  Get-ChildItem $root -Filter *.lnk -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $shortcut = $shell.CreateShortcut($_.FullName)
    if ($shortcut.TargetPath -match '(?i)(chrome|msedge|firefox|opera|browser)') {
      [PSCustomObject]@{Name=$_.Name; Path=$_.FullName; Target=$shortcut.TargetPath; Arguments=$shortcut.Arguments}
    }
  }
}
"""
        return _find_shortcut_records(context, self.name, run_for_context(context, script))


def _find_shortcut_records(
    context: ScanContext, category: str, records: list[dict]
) -> list[Finding]:
    findings = []
    for record in records:
        searchable = " ".join(str(value or "") for value in record.values())
        app = find_known_app(searchable, context.known_apps)
        if app:
            findings.append(
                finding_for_app(
                    app,
                    category,
                    str(record.get("Path") or ""),
                    executable=str(record.get("Target") or ""),
                    remediation_type="quarantine_path",
                    remediation_data={"path": str(record.get("Path") or "")},
                    details=record,
                )
            )
    return findings


class BrowserExtensionsScanner(Scanner):
    name = "Browser Extensions (Chrome/Edge)"

    def scan(self, context: ScanContext) -> list[Finding]:
        roots = self._browser_roots(context)
        findings = []
        for root in roots:
            if not root.exists():
                continue
            for manifest in root.glob("*/Extensions/*/*/manifest.json"):
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
                extension_id = manifest.parents[1].name
                searchable = f"{data.get('name', '')} {data.get('description', '')} {extension_id}"
                app = find_known_app(searchable, context.known_apps)
                if app:
                    extension_root = manifest.parents[1]
                    findings.append(
                        finding_for_app(
                            app,
                            self.name,
                            str(extension_root),
                            remediation_type="quarantine_path",
                            remediation_data={"path": str(extension_root)},
                            details={
                                "extension_id": extension_id,
                                "version": data.get("version", ""),
                                "name": data.get("name", ""),
                            },
                        )
                    )
        return findings

    def _browser_roots(self, context: ScanContext) -> tuple[Path, ...]:
        if context.admin_share_mode:
            local_app_data_roots = [
                profile / "AppData" / "Local" for profile in _remote_user_profiles(context)
            ]
        else:
            if not context.is_local:
                raise RuntimeError(f"{self.name} requires a local scan or Admin Share / SMB mode")
            local_app_data = os.getenv("LOCALAPPDATA")
            local_app_data_roots = [Path(local_app_data)] if local_app_data else []
        roots = []
        for local_app_data_root in local_app_data_roots:
            roots.extend(
                (
                    local_app_data_root / "Google" / "Chrome" / "User Data",
                    local_app_data_root / "Microsoft" / "Edge" / "User Data",
                )
            )
        return tuple(roots)


def _remote_user_profiles(context: ScanContext) -> list[Path]:
    users_root = context.admin_root / "Users"
    try:
        return [path for path in users_root.iterdir() if path.is_dir()]
    except OSError as error:
        raise RuntimeError(f"Cannot enumerate remote user profiles at {users_root}: {error}") from error


def _shortcut_records_from_roots(
    roots: tuple[Path, ...], *, recursive: bool, browser_only: bool = False
) -> list[dict]:
    if not roots:
        return []
    roots_literal = ",\n".join(f"  '{_ps_quote(str(root))}'" for root in roots)
    recurse_switch = " -Recurse" if recursive else ""
    browser_condition = (
        "if ($target -notmatch '(?i)(chrome|msedge|firefox|opera|browser)') { return }"
        if browser_only
        else ""
    )
    script = f"""
$shell = New-Object -ComObject WScript.Shell
$roots = @(
{roots_literal}
)
foreach ($root in $roots) {{
  Get-ChildItem -LiteralPath $root -File{recurse_switch} -ErrorAction SilentlyContinue | ForEach-Object {{
    $target = $_.FullName
    $arguments = ''
    if ($_.Extension -eq '.lnk') {{
      try {{
        $shortcut = $shell.CreateShortcut($_.FullName)
        $target = $shortcut.TargetPath
        $arguments = $shortcut.Arguments
      }} catch {{}}
    }}
    {browser_condition}
    [PSCustomObject]@{{Name=$_.Name; Path=$_.FullName; Target=$target; Arguments=$arguments}}
  }}
}}
"""
    return run_powershell_json(script)


def _ps_quote(value: str) -> str:
    return value.replace("'", "''")
