from __future__ import annotations

import csv
import json
from pathlib import Path

from pua_inspector.models import ScanReport


def export_report(report: ScanReport, path: Path) -> None:
    if path.suffix.casefold() == ".json":
        path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return
    if path.suffix.casefold() != ".csv":
        raise ValueError("Export filename must end in .csv or .json")
    fieldnames = [
        "finding",
        "category",
        "location",
        "risk",
        "status",
        "action",
        "remediation_allowed",
        "remediation_block_reason",
        "executable",
        "sha256",
        "vt_detection_ratio",
        "vt_reputation",
        "vt_last_analysis_date",
        "vt_report_url",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in report.findings:
            vt = finding.virustotal
            writer.writerow(
                {
                    "finding": finding.finding,
                    "category": finding.category,
                    "location": finding.location,
                    "risk": finding.risk.value,
                    "status": finding.status.value,
                    "action": finding.action,
                    "remediation_allowed": finding.remediation_allowed,
                    "remediation_block_reason": finding.remediation_block_reason,
                    "executable": finding.executable,
                    "sha256": finding.sha256,
                    "vt_detection_ratio": vt.detection_ratio if vt else "",
                    "vt_reputation": vt.reputation if vt else "",
                    "vt_last_analysis_date": vt.last_analysis_date if vt else "",
                    "vt_report_url": vt.report_url if vt else "",
                }
            )
