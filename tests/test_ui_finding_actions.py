import socket

from pua_inspector.models import Finding, RiskLevel, ScanReport, VirusTotalResult
from pua_inspector.task_inventory import ScheduledTaskRecord
from pua_inspector.ui.main_window import MainWindow


def sample_finding(*, remediation_allowed=True):
    finding = Finding(
        finding="Wave Browser",
        category="Scheduled Tasks",
        location=r"\Vendor\WaveUpdater",
        risk=RiskLevel.HIGH,
        action="Review and remove if unauthorized.",
        remediation_allowed=remediation_allowed,
        remediation_block_reason=(
            "Custom keyword matches are review-only." if not remediation_allowed else ""
        ),
        executable=r"C:\Program Files\Wave\wave.exe",
        sha256="a" * 64,
        details={"TaskName": "WaveUpdater"},
    )
    finding.virustotal = VirusTotalResult(
        sha256=finding.sha256,
        detection_ratio="8/70",
        reputation=-5,
        last_analysis_date="2026-01-01T00:00:00+00:00",
        report_url="https://www.virustotal.com/gui/file/" + finding.sha256,
    )
    return finding


def test_full_finding_details_include_evidence_and_policy():
    details = MainWindow._format_finding_details(
        sample_finding(remediation_allowed=False)
    )

    assert "Category: Scheduled Tasks" in details
    assert "Detection ratio: 8/70" in details
    assert "Remediation allowed: No" in details
    assert "Custom keyword matches are review-only." in details
    assert '"TaskName": "WaveUpdater"' in details


def test_context_remediation_state_respects_local_and_policy_safeguards():
    window = MainWindow.__new__(MainWindow)
    window.last_scan_admin_share_mode = False
    window.report = ScanReport(
        socket.gethostname(), [], [], "start", "finish"
    )

    assert window._can_remediate([sample_finding()]) is True
    assert window._can_remediate([sample_finding(remediation_allowed=False)]) is False

    window.last_scan_admin_share_mode = True
    assert window._can_remediate([sample_finding()]) is False


def test_plain_language_task_details_explain_state_and_result():
    record = ScheduledTaskRecord(
        hostname="WORKSTATION-1",
        task_name="\\Vendor\\Updater",
        status="Ready",
        action="C:\\Vendor\\updater.exe --silent",
        author="Vendor Inc.",
        run_as_user="SYSTEM",
        last_run_time="8/6/2026 9:00 AM",
        next_run_time="8/7/2026 9:00 AM",
        last_result="0",
        comment="Checks for application updates.",
    )

    details = MainWindow._format_task_details(record)

    assert "Enabled and waiting for its next trigger." in details
    assert "The most recent run completed successfully." in details
    assert "Program or command: C:\\Vendor\\updater.exe --silent" in details
    assert "Runs as account: SYSTEM" in details
