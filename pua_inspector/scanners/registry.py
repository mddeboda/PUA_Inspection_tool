from __future__ import annotations

from pua_inspector.models import Finding
from pua_inspector.scanners.base import (
    ScanContext,
    Scanner,
    finding_from_record,
    reject_admin_share_mode,
)
from pua_inspector.scanners.filesystem import scan_known_directories
from pua_inspector.scanners.powershell import run_for_context


class InstalledProgramsScanner(Scanner):
    name = "Installed Programs"

    def scan(self, context: ScanContext) -> list[Finding]:
        if context.admin_share_mode:
            roots = (
                context.admin_root / "Program Files",
                context.admin_root / "Program Files (x86)",
            )
            return scan_known_directories(
                context,
                self.name,
                roots,
                remediation_type="manual",
                details={"source": "Admin Share / SMB filesystem approximation"},
            )
        script = r"""
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object DisplayName |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, PSPath
"""
        findings = []
        for record in run_for_context(context, script):
            finding = finding_from_record(
                record,
                context,
                self.name,
                ("DisplayName", "Publisher", "InstallLocation", "UninstallString", "PSPath"),
                "InstallLocation",
                "UninstallString",
                "uninstall_command",
            )
            if finding:
                findings.append(finding)
        return findings


class RegistryRunKeysScanner(Scanner):
    name = "Registry Run/RunOnce Keys"

    def scan(self, context: ScanContext) -> list[Finding]:
        reject_admin_share_mode(context, self.name)
        script = r"""
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($path in $paths) {
  if (Test-Path $path) {
    $item = Get-ItemProperty $path
    foreach ($property in $item.PSObject.Properties) {
      if ($property.Name -notmatch '^PS') {
        [PSCustomObject]@{Name=$property.Name; Command=[string]$property.Value; RegistryPath=$path}
      }
    }
  }
}
"""
        findings = []
        for record in run_for_context(context, script):
            finding = finding_from_record(
                record,
                context,
                self.name,
                ("Name", "Command", "RegistryPath"),
                "RegistryPath",
                "Command",
                "registry_value",
            )
            if finding:
                findings.append(finding)
        return findings
