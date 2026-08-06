from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pua_inspector.config import AppSettings, load_known_apps
from pua_inspector.scanners.base import ScanContext
from pua_inspector.scanners.filesystem import scan_known_directories
from pua_inspector.scanners.registry import RegistryRunKeysScanner
from pua_inspector.scanners.system import (
    ScheduledTasksScanner,
    _parse_schtasks_csv,
    _query_scheduled_tasks,
    _read_hosts_file,
)


def test_admin_share_root_uses_c_drive_share():
    context = ScanContext("REMOTE-PC", [], AppSettings(), admin_share_mode=True)

    assert str(context.admin_root) == "\\\\REMOTE-PC\\C$\\"
    assert context.admin_share_display == r"\\REMOTE-PC\C$"


def test_smb_directory_matching_uses_same_iocs(tmp_path):
    canary = tmp_path / "OneStart.ai"
    canary.mkdir()
    executable = canary / "canary.exe"
    executable.write_bytes(b"benign test")
    context = ScanContext(
        "REMOTE-PC",
        load_known_apps(),
        AppSettings(scan_path_depth=2),
        admin_share_mode=True,
    )

    findings = scan_known_directories(context, "AppData", (tmp_path,))

    assert len(findings) == 1
    assert findings[0].finding == "OneStart.ai"
    assert findings[0].executable == str(executable)


def test_smb_hosts_reader_handles_multiple_hostnames(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "# comment\n127.0.0.1 localhost\n192.0.2.1 first.test second.test # canary\n",
        encoding="utf-8",
    )

    records = _read_hosts_file(hosts)

    assert [record["Hostname"] for record in records] == ["first.test", "second.test"]


def test_registry_module_does_not_fall_back_to_winrm_in_smb_mode():
    context = ScanContext("REMOTE-PC", [], AppSettings(), admin_share_mode=True)

    with pytest.raises(RuntimeError, match="not available through the admin share"):
        RegistryRunKeysScanner().scan(context)


def test_schtasks_csv_parser_extracts_remote_task_action():
    output = (
        '"HostName","TaskName","Next Run Time","Status","Logon Mode",'
        '"Last Run Time","Last Result","Author","Task To Run","Start In","Comment"\n'
        '"REMOTE-PC","\\OneStart Update","N/A","Ready","Interactive only",'
        '"N/A","0","Vendor","C:\\OneStart.ai\\update.exe --silent","","Updater"\n'
    )

    records = _parse_schtasks_csv(output)

    assert records == [
        {
            "HostName": "REMOTE-PC",
            "TaskName": "\\OneStart Update",
            "Status": "Ready",
            "Execute": "C:\\OneStart.ai\\update.exe --silent",
            "Author": "Vendor",
            "Comment": "Updater",
            "Source": "schtasks /query",
        }
    ]


def test_schtasks_query_uses_current_windows_identity():
    completed = SimpleNamespace(
        returncode=0,
        stdout='"HostName","TaskName","Next Run Time","Status","Logon Mode"\n',
        stderr="",
    )

    with patch("pua_inspector.scanners.system.subprocess.run", return_value=completed) as run:
        _query_scheduled_tasks("REMOTE-PC")

    command = run.call_args.args[0]
    assert command == [
        "schtasks.exe",
        "/query",
        "/s",
        "REMOTE-PC",
        "/fo",
        "CSV",
        "/v",
    ]
    assert "/u" not in command
    assert "/p" not in command


def test_smb_scheduled_task_scanner_matches_ioc():
    context = ScanContext(
        "REMOTE-PC",
        load_known_apps(),
        AppSettings(),
        admin_share_mode=True,
    )
    records = [
        {
            "HostName": "REMOTE-PC",
            "TaskName": "\\OneStart.ai Update",
            "Status": "Ready",
            "Execute": "C:\\ProgramData\\OneStart.ai\\update.exe --silent",
            "Author": "Test",
            "Comment": "Benign test record",
            "Source": "schtasks /query",
        }
    ]

    with patch("pua_inspector.scanners.system._query_scheduled_tasks", return_value=records):
        findings = ScheduledTasksScanner().scan(context)

    assert len(findings) == 1
    assert findings[0].finding == "OneStart.ai"
    assert findings[0].location == "\\OneStart.ai Update"
    assert findings[0].remediation_type == "manual"
