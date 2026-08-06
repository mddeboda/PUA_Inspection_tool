from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from pua_inspector.config import AppSettings
from pua_inspector.models import Finding, KnownApp, RiskLevel, ScanProgress, ScanReport
from pua_inspector.scanners.base import ScanContext, Scanner, validate_hostname
from pua_inspector.utils import sha256_file
from pua_inspector.virustotal import VirusTotalClient


ProgressCallback = Callable[[ScanProgress], None]


class ScanEngine:
    def __init__(
        self,
        scanners: Iterable[Scanner],
        known_apps: list[KnownApp],
        settings: AppSettings,
        virustotal_client: VirusTotalClient | None = None,
    ):
        self.scanners = {scanner.name: scanner for scanner in scanners}
        self.known_apps = known_apps
        self.settings = settings
        self.virustotal_client = virustotal_client

    @property
    def module_names(self) -> list[str]:
        return list(self.scanners)

    def scan(
        self,
        hostname: str = "",
        enabled_modules: Iterable[str] | None = None,
        progress_callback: ProgressCallback | None = None,
        admin_share_mode: bool = False,
        search_keyword: str = "",
    ) -> ScanReport:
        target = validate_hostname(hostname or socket.gethostname())
        keyword = _validate_search_keyword(search_keyword)
        selected = list(enabled_modules) if enabled_modules is not None else self.module_names
        started = _now()
        findings: list[Finding] = []
        errors: list[str] = []
        scan_indicators = list(self.known_apps)
        if keyword:
            scan_indicators.append(_keyword_indicator(keyword))
        context = ScanContext(target, scan_indicators, self.settings, admin_share_mode)

        if admin_share_mode:
            try:
                share_accessible = context.admin_root.is_dir()
            except OSError as error:
                share_accessible = False
                errors.append(f"Admin Share / SMB: {error}")
            if not share_accessible:
                if not errors:
                    errors.append(
                        f"Admin Share / SMB: cannot access {context.admin_share_display} "
                        "with the current Windows credentials"
                    )
                _notify(progress_callback, "Complete", len(selected), len(selected), "Scan complete")
                return ScanReport(target, findings, errors, started, _now(), keyword)

        for index, module_name in enumerate(selected, start=1):
            scanner = self.scanners.get(module_name)
            if not scanner:
                errors.append(f"{module_name}: module is not available")
                continue
            if admin_share_mode and module_name == "Installed Programs":
                errors.append(
                    "Installed Programs: SMB mode uses a Program Files filesystem approximation; "
                    "registry-only and per-user installs may not appear"
                )
            _notify(progress_callback, module_name, index - 1, len(selected), f"Scanning {module_name}...")
            try:
                module_findings = scanner.scan(context)
                self._enrich_findings(module_findings, errors)
                findings.extend(module_findings)
            except Exception as error:  # A single unavailable source must not end an endpoint scan.
                errors.append(f"{module_name}: {error}")

        _notify(progress_callback, "Complete", len(selected), len(selected), "Scan complete")
        return ScanReport(target, findings, errors, started, _now(), keyword)

    def _enrich_findings(self, findings: list[Finding], errors: list[str]) -> None:
        for finding in findings:
            executable = finding.executable_path()
            if not executable or not executable.is_file():
                continue
            try:
                finding.sha256 = sha256_file(executable)
            except OSError as error:
                errors.append(f"Hashing {executable}: {error}")
                continue
            if self.settings.virustotal_enabled and self.virustotal_client:
                finding.virustotal = self.virustotal_client.lookup_hash(finding.sha256)


def _notify(
    callback: ProgressCallback | None,
    module: str,
    completed: int,
    total: int,
    message: str,
) -> None:
    if callback:
        callback(ScanProgress(module, completed, total, message))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_search_keyword(value: str) -> str:
    keyword = value.strip()
    if len(keyword) > 200:
        raise ValueError("Search keyword must be 200 characters or fewer")
    if any(ord(character) < 32 for character in keyword):
        raise ValueError("Search keyword cannot contain control characters")
    return keyword


def _keyword_indicator(keyword: str) -> KnownApp:
    return KnownApp(
        name=f"Keyword match: {keyword}",
        aliases=(keyword,),
        known_install_paths=(),
        registry_names=(),
        risk_level=RiskLevel.LOW,
        recommended_action=(
            "Review the matched artifact. A custom keyword match is not inherently malicious."
        ),
        remediation_allowed=False,
        remediation_block_reason="Custom keyword matches are review-only and cannot be remediated.",
    )
