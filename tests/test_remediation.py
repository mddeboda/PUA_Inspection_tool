from pua_inspector.config import AppSettings
from pua_inspector.models import Finding, FindingStatus, RiskLevel
from pua_inspector.remediation import RemediationService


def test_policy_blocked_finding_cannot_be_quarantined(tmp_path):
    source = tmp_path / "keyword-match"
    source.mkdir()
    finding = Finding(
        finding="Keyword match: test",
        category="AppData",
        location=str(source),
        risk=RiskLevel.LOW,
        remediation_allowed=False,
        remediation_block_reason="Custom keyword matches are review-only.",
        remediation_type="quarantine_path",
        remediation_data={"path": str(source)},
    )
    settings = AppSettings(quarantine_directory=str(tmp_path / "quarantine"))

    success, message = RemediationService(settings).remediate(finding)

    assert success is False
    assert message == "Custom keyword matches are review-only."
    assert source.exists()
    assert finding.status == FindingStatus.DETECTED
    assert not (tmp_path / "quarantine").exists()
