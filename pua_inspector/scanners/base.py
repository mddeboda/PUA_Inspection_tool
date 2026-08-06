from __future__ import annotations

import os
import re
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from pua_inspector.config import AppSettings
from pua_inspector.models import Finding, FindingStatus, KnownApp, RiskLevel
from pua_inspector.utils import extract_executable


@dataclass(frozen=True)
class ScanContext:
    hostname: str
    known_apps: list[KnownApp]
    settings: AppSettings
    admin_share_mode: bool = False

    @property
    def is_local(self) -> bool:
        local_names = {"", ".", "localhost", socket.gethostname().casefold()}
        return self.hostname.casefold() in local_names

    @property
    def admin_root(self) -> Path:
        return Path(rf"\\{self.hostname}\C$")

    @property
    def admin_share_display(self) -> str:
        return rf"\\{self.hostname}\C$"


class Scanner(ABC):
    name: str

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        raise NotImplementedError


def reject_admin_share_mode(context: ScanContext, module_name: str) -> None:
    if context.admin_share_mode:
        raise RuntimeError(
            f"{module_name} is not available through the admin share; "
            "use WinRM or another endpoint-management channel"
        )


def find_known_app(text: str, known_apps: list[KnownApp]) -> KnownApp | None:
    haystack = (text or "").casefold()
    for app in known_apps:
        if any(term in haystack for term in app.search_terms):
            return app
        for install_path in app.known_install_paths:
            expanded = os.path.expandvars(install_path).casefold()
            if expanded and expanded in haystack:
                return app
    return None


def finding_for_app(
    app: KnownApp,
    category: str,
    location: str,
    *,
    executable: str = "",
    remediation_type: str = "manual",
    remediation_data: dict | None = None,
    details: dict | None = None,
) -> Finding:
    return Finding(
        finding=app.name,
        category=category,
        location=location,
        risk=app.risk_level,
        status=FindingStatus.DETECTED,
        action=app.recommended_action,
        executable=executable,
        remediation_type=remediation_type,
        remediation_data=remediation_data or {},
        details=details or {},
    )


def finding_from_record(
    record: dict,
    context: ScanContext,
    category: str,
    searchable_fields: tuple[str, ...],
    location_field: str,
    command_field: str = "",
    remediation_type: str = "manual",
) -> Finding | None:
    searchable = " ".join(str(record.get(field) or "") for field in searchable_fields)
    app = find_known_app(searchable, context.known_apps)
    if not app:
        return None
    command = str(record.get(command_field) or "") if command_field else ""
    return finding_for_app(
        app,
        category,
        str(record.get(location_field) or searchable),
        executable=extract_executable(command),
        remediation_type=remediation_type,
        remediation_data=record,
        details=record,
    )


def validate_hostname(hostname: str) -> str:
    value = hostname.strip() or socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", value):
        raise ValueError("Hostname contains unsupported characters")
    return value


def local_directory_candidates(environment_names: tuple[str, ...]) -> list[Path]:
    result: list[Path] = []
    for name in environment_names:
        value = os.getenv(name)
        if value:
            result.append(Path(value))
    return result


def review_finding(name: str, category: str, location: str, details: dict) -> Finding:
    return Finding(
        finding=name,
        category=category,
        location=location,
        risk=RiskLevel.MEDIUM,
        status=FindingStatus.REVIEW,
        action="Review this modification and restore the default if it is unauthorized.",
        details=details,
    )
