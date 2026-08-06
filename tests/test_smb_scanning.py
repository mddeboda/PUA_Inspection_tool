from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pua_inspector.config import AppSettings, load_known_apps
from pua_inspector.scanners.base import ScanContext
from pua_inspector.scanners.filesystem import scan_known_directories
from pua_inspector.scanners.registry import RegistryRunKeysScanner
from pua_inspector.scanners.system import (
    ScheduledTasksScanner,
    _read_hosts_file,
)
from pua_inspector.task_inventory import (
    ScheduledTaskRecord,
    delete_scheduled_task,
    parse_scheduled_tasks_csv,
    query_scheduled_tasks,
    query_task_details,
    query_task_summaries,
    set_task_enabled,
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

    records = parse_scheduled_tasks_csv(output)

    assert records == [
        ScheduledTaskRecord(
            hostname="REMOTE-PC",
            task_name="\\OneStart Update",
            next_run_time="N/A",
            status="Ready",
            last_run_time="N/A",
            last_result="0",
            author="Vendor",
            action="C:\\OneStart.ai\\update.exe --silent",
            comment="Updater",
        )
    ]


def test_schtasks_csv_parser_skips_repeated_verbose_headers():
    header = (
        '"HostName","TaskName","Next Run Time","Status","Logon Mode",'
        '"Last Run Time","Last Result","Author","Task To Run"\n'
    )
    output = (
        header
        + '"HOST","\\First Task","N/A","Ready","Interactive",'
        '"N/A","0","Vendor","first.exe"\n'
        + header
        + header
        + '"HOST","\\Second Task","N/A","Ready","Interactive",'
        '"N/A","0","Vendor","second.exe"\n'
    )

    records = parse_scheduled_tasks_csv(output)

    assert [record.task_name for record in records] == [
        "\\First Task",
        "\\Second Task",
    ]
    assert all(record.hostname == "HOST" for record in records)


def test_schtasks_csv_parser_supports_fast_three_column_output():
    header = '"TaskName","Next Run Time","Status"\n'
    output = (
        header
        + '"\\Vendor\\Updater","8/7/2026 9:00:00 AM","Ready"\n'
        + header
        + '"\\Vendor\\Cleanup","N/A","Disabled"\n'
    )

    records = parse_scheduled_tasks_csv(output, default_hostname="WORKSTATION-1")

    assert records == [
        ScheduledTaskRecord(
            hostname="WORKSTATION-1",
            task_name="\\Vendor\\Updater",
            next_run_time="8/7/2026 9:00:00 AM",
            status="Ready",
        ),
        ScheduledTaskRecord(
            hostname="WORKSTATION-1",
            task_name="\\Vendor\\Cleanup",
            next_run_time="N/A",
            status="Disabled",
        ),
    ]


def test_schtasks_query_uses_current_windows_identity():
    completed = SimpleNamespace(
        returncode=0,
        stdout='"HostName","TaskName","Next Run Time","Status","Logon Mode"\n',
        stderr="",
    )

    with patch("pua_inspector.task_inventory.subprocess.run", return_value=completed) as run:
        query_scheduled_tasks("REMOTE-PC", remote=True)

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


def test_local_task_query_does_not_use_remote_switch():
    completed = SimpleNamespace(
        returncode=0,
        stdout='"HostName","TaskName","Next Run Time","Status","Logon Mode"\n',
        stderr="",
    )

    with patch("pua_inspector.task_inventory.subprocess.run", return_value=completed) as run:
        query_scheduled_tasks("localhost", remote=False)

    assert run.call_args.args[0] == [
        "schtasks.exe",
        "/query",
        "/fo",
        "CSV",
        "/v",
    ]


def test_fast_task_summary_query_omits_verbose_switch():
    completed = SimpleNamespace(
        returncode=0,
        stdout='"HostName","TaskName","Next Run Time","Status","Logon Mode"\n',
        stderr="",
    )

    with patch("pua_inspector.task_inventory.subprocess.run", return_value=completed) as run:
        query_task_summaries("REMOTE-PC", remote=True)

    assert run.call_args.args[0] == [
        "schtasks.exe",
        "/query",
        "/s",
        "REMOTE-PC",
        "/fo",
        "CSV",
    ]


def test_task_detail_query_targets_only_selected_task():
    completed = SimpleNamespace(
        returncode=0,
        stdout=(
            '"HostName","TaskName","Next Run Time","Status","Logon Mode",'
            '"Last Run Time","Last Result","Author","Task To Run"\n'
            '"REMOTE-PC","\\Test Task","N/A","Ready","Interactive",'
            '"N/A","0","Test","test.exe"\n'
        ),
        stderr="",
    )

    with patch("pua_inspector.task_inventory.subprocess.run", return_value=completed) as run:
        task = query_task_details("REMOTE-PC", "\\Test Task", remote=True)

    assert run.call_args.args[0] == [
        "schtasks.exe",
        "/query",
        "/s",
        "REMOTE-PC",
        "/tn",
        "\\Test Task",
        "/fo",
        "CSV",
        "/v",
    ]
    assert task.action == "test.exe"


def test_task_noise_filter_properties():
    microsoft = ScheduledTaskRecord(
        "HOST", "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"
    )
    disabled = ScheduledTaskRecord("HOST", "\\Vendor\\Updater", status="Disabled")
    empty = ScheduledTaskRecord("HOST", "\\Vendor\\Incomplete", next_run_time="N/A")
    active = ScheduledTaskRecord("HOST", "\\Vendor\\Active", status="Ready")

    assert microsoft.is_microsoft_windows_task is True
    assert disabled.is_disabled is True
    assert empty.is_empty is True
    assert active.is_empty is False


@pytest.mark.parametrize(
    ("enabled", "switch"),
    ((True, "/enable"), (False, "/disable")),
)
def test_remote_task_state_change_uses_current_identity(enabled, switch):
    completed = SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    with patch("pua_inspector.task_inventory.subprocess.run", return_value=completed) as run:
        result = set_task_enabled(
            "REMOTE-PC", "\\Vendor\\Updater", enabled=enabled, remote=True
        )

    assert run.call_args.args[0] == [
        "schtasks.exe",
        "/change",
        "/s",
        "REMOTE-PC",
        "/tn",
        "\\Vendor\\Updater",
        switch,
    ]
    assert "/u" not in run.call_args.args[0]
    assert "/p" not in run.call_args.args[0]
    assert result == "SUCCESS"


def test_remote_task_delete_is_forced_after_ui_confirmation():
    completed = SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    with patch("pua_inspector.task_inventory.subprocess.run", return_value=completed) as run:
        delete_scheduled_task(
            "REMOTE-PC", "\\Vendor\\Updater", remote=True
        )

    assert run.call_args.args[0] == [
        "schtasks.exe",
        "/delete",
        "/s",
        "REMOTE-PC",
        "/tn",
        "\\Vendor\\Updater",
        "/f",
    ]


def test_backend_blocks_changes_to_microsoft_system_tasks():
    with pytest.raises(ValueError, match="protected from changes"):
        delete_scheduled_task(
            "localhost",
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            remote=False,
        )


def test_smb_scheduled_task_scanner_matches_ioc():
    context = ScanContext(
        "REMOTE-PC",
        load_known_apps(),
        AppSettings(),
        admin_share_mode=True,
    )
    records = [
        ScheduledTaskRecord(
            hostname="REMOTE-PC",
            task_name="\\OneStart.ai Update",
            status="Ready",
            action="C:\\ProgramData\\OneStart.ai\\update.exe --silent",
            author="Test",
            comment="Benign test record",
        )
    ]

    with patch("pua_inspector.scanners.system.query_scheduled_tasks", return_value=records):
        findings = ScheduledTasksScanner().scan(context)

    assert len(findings) == 1
    assert findings[0].finding == "OneStart.ai"
    assert findings[0].location == "\\OneStart.ai Update"
    assert findings[0].remediation_type == "manual"
