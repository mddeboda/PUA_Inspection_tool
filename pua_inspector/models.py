from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FindingStatus(str, Enum):
    DETECTED = "Detected"
    REVIEW = "Review"
    REMOVED = "Removed"
    REMEDIATED = "Remediated"
    FAILED = "Failed"


@dataclass(frozen=True)
class KnownApp:
    name: str
    aliases: tuple[str, ...]
    known_install_paths: tuple[str, ...]
    registry_names: tuple[str, ...]
    risk_level: RiskLevel
    recommended_action: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KnownApp":
        return cls(
            name=data["name"],
            aliases=tuple(data.get("aliases", [])),
            known_install_paths=tuple(data.get("known_install_paths", [])),
            registry_names=tuple(data.get("registry_names", [])),
            risk_level=RiskLevel(data.get("risk_level", "Medium")),
            recommended_action=data.get("recommended_action", "Review and remove if unauthorized."),
        )

    @property
    def search_terms(self) -> tuple[str, ...]:
        values = (self.name, *self.aliases, *self.registry_names)
        return tuple(value.casefold() for value in values if value)


@dataclass
class VirusTotalResult:
    sha256: str
    detection_ratio: str = "Not queried"
    reputation: int | None = None
    last_analysis_date: str = ""
    report_url: str = ""
    error: str = ""


@dataclass
class Finding:
    finding: str
    category: str
    location: str
    risk: RiskLevel
    status: FindingStatus = FindingStatus.DETECTED
    action: str = "Review"
    executable: str = ""
    sha256: str = ""
    virustotal: VirusTotalResult | None = None
    remediation_type: str = "manual"
    remediation_data: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["risk"] = self.risk.value
        result["status"] = self.status.value
        return result

    def executable_path(self) -> Path | None:
        return Path(self.executable) if self.executable else None


@dataclass
class ScanProgress:
    module: str
    completed: int
    total: int
    message: str


@dataclass
class ScanReport:
    hostname: str
    findings: list[Finding]
    errors: list[str]
    started_at: str
    finished_at: str
    search_keyword: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "search_keyword": self.search_keyword,
        }
