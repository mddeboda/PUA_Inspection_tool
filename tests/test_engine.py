from unittest.mock import patch

from pua_inspector.config import AppSettings
from pua_inspector.engine import ScanEngine
from pua_inspector.models import Finding, RiskLevel
from pua_inspector.scanners.base import (
    ScanContext,
    Scanner,
    find_known_app,
    finding_for_app,
)


class SuccessfulScanner(Scanner):
    name = "Test scanner"

    def __init__(self, executable: str = ""):
        self.executable = executable

    def scan(self, context: ScanContext):
        return [
            Finding(
                finding="Test PUA",
                category=self.name,
                location="test location",
                risk=RiskLevel.MEDIUM,
                executable=self.executable,
            )
        ]


class FailedScanner(Scanner):
    name = "Failed scanner"

    def scan(self, context: ScanContext):
        raise PermissionError("access denied")


class SearchableScanner(Scanner):
    name = "Searchable scanner"

    def scan(self, context: ScanContext):
        app = find_known_app(
            "C:\\ProgramData\\ExampleVendor\\needle-agent.exe --startup",
            context.known_apps,
        )
        return [finding_for_app(app, self.name, "test location")] if app else []


class FakeVirusTotal:
    configured = True

    def lookup_hash(self, sha256):
        return None


def test_engine_continues_after_module_error(tmp_path):
    engine = ScanEngine(
        [FailedScanner(), SuccessfulScanner()],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    report = engine.scan("localhost")

    assert len(report.findings) == 1
    assert report.findings[0].finding == "Test PUA"
    assert report.errors == ["Failed scanner: access denied"]


def test_engine_hashes_detected_executable(tmp_path):
    executable = tmp_path / "sample.exe"
    executable.write_bytes(b"known test content")
    engine = ScanEngine(
        [SuccessfulScanner(str(executable))],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    report = engine.scan("localhost")

    assert len(report.findings[0].sha256) == 64


def test_empty_module_selection_runs_nothing():
    engine = ScanEngine(
        [SuccessfulScanner()],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    report = engine.scan("localhost", enabled_modules=[])

    assert report.findings == []


def test_admin_share_mode_reports_inaccessible_share():
    engine = ScanEngine(
        [SuccessfulScanner()],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    with patch("pathlib.Path.is_dir", return_value=False):
        report = engine.scan("REMOTE-PC", admin_share_mode=True)

    assert report.findings == []
    assert report.errors == [
        "Admin Share / SMB: cannot access \\\\REMOTE-PC\\C$ with the current Windows credentials"
    ]


def test_optional_keyword_is_matched_across_scanner_metadata():
    engine = ScanEngine(
        [SearchableScanner()],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    report = engine.scan("localhost", search_keyword="Needle-Agent")

    assert len(report.findings) == 1
    assert report.findings[0].finding == "Keyword match: Needle-Agent"
    assert report.findings[0].risk == RiskLevel.LOW
    assert report.findings[0].remediation_allowed is False
    assert "review-only" in report.findings[0].remediation_block_reason
    assert report.search_keyword == "Needle-Agent"


def test_blank_keyword_does_not_create_an_indicator():
    engine = ScanEngine(
        [SearchableScanner()],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    report = engine.scan("localhost", search_keyword="   ")

    assert report.findings == []
    assert report.search_keyword == ""


def test_keyword_length_is_limited():
    engine = ScanEngine(
        [SearchableScanner()],
        known_apps=[],
        settings=AppSettings(virustotal_enabled=False),
    )

    try:
        engine.scan("localhost", search_keyword="x" * 201)
    except ValueError as error:
        assert str(error) == "Search keyword must be 200 characters or fewer"
    else:
        raise AssertionError("Expected an overlong keyword to be rejected")
