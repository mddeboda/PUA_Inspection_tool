import csv

from pua_inspector.exporter import export_report
from pua_inspector.models import Finding, RiskLevel, ScanReport, VirusTotalResult


def sample_report():
    finding = Finding("Wave Browser", "Installed Programs", "C:\\Wave", RiskLevel.HIGH)
    finding.sha256 = "a" * 64
    finding.virustotal = VirusTotalResult(
        finding.sha256,
        detection_ratio="8/70",
        reputation=-5,
        last_analysis_date="2026-01-01T00:00:00+00:00",
        report_url="https://www.virustotal.com/gui/file/" + finding.sha256,
    )
    return ScanReport("HOST", [finding], [], "start", "finish")


def test_csv_export_includes_virustotal_fields(tmp_path):
    path = tmp_path / "results.csv"

    export_report(sample_report(), path)

    with path.open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["vt_detection_ratio"] == "8/70"
    assert row["vt_reputation"] == "-5"


def test_json_export_contains_findings(tmp_path):
    path = tmp_path / "results.json"

    export_report(sample_report(), path)

    assert '"Wave Browser"' in path.read_text(encoding="utf-8")

