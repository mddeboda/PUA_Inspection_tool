from unittest.mock import patch

import pytest

from pua_inspector.config import AppSettings
from pua_inspector.scanners.base import ScanContext
from pua_inspector.scanners.registry import InstalledProgramsScanner
from pua_inspector.scanners.system import (
    RunningProcessesScanner,
    ScheduledTasksScanner,
    ServicesScanner,
    WmiPersistenceScanner,
)


@pytest.mark.parametrize(
    "scanner",
    [
        ScheduledTasksScanner(),
        ServicesScanner(),
        RunningProcessesScanner(),
        WmiPersistenceScanner(),
    ],
)
def test_privileged_system_queries_do_not_suppress_permission_errors(scanner):
    context = ScanContext("localhost", [], AppSettings())

    with patch("pua_inspector.scanners.system.run_for_context", return_value=[]) as run:
        scanner.scan(context)

    script = run.call_args.args[1]
    assert "-ErrorAction SilentlyContinue" not in script
    assert "-ErrorAction Stop" in script


def test_installed_program_inventory_surfaces_access_errors():
    context = ScanContext("localhost", [], AppSettings())

    with patch("pua_inspector.scanners.registry.run_for_context", return_value=[]) as run:
        InstalledProgramsScanner().scan(context)

    script = run.call_args.args[1]
    assert "Get-ItemProperty $path -ErrorAction Stop" in script
    assert "Get-ItemProperty $paths -ErrorAction SilentlyContinue" not in script
