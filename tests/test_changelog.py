from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pua_inspector.changelog import format_recent_changes, load_recent_changes


def test_load_recent_changes_runs_bounded_git_log(tmp_path):
    completed = SimpleNamespace(
        returncode=0,
        stdout=(
            "abc1234\x1f2026-08-06\x1fAdd safety policy\n"
            "def5678\x1f2026-08-05\x1fBuild scanner"
        ),
        stderr="",
    )

    with patch("pua_inspector.changelog.subprocess.run", return_value=completed) as run:
        changes = load_recent_changes(tmp_path, limit=5)

    command = run.call_args.args[0]
    assert command[:5] == ["git", "-C", str(tmp_path), "log", "-n"]
    assert command[5] == "5"
    assert [change.subject for change in changes] == ["Add safety policy", "Build scanner"]


def test_git_history_failure_has_safe_message(tmp_path):
    completed = SimpleNamespace(returncode=128, stdout="", stderr="sensitive path")

    with patch("pua_inspector.changelog.subprocess.run", return_value=completed):
        with pytest.raises(RuntimeError, match="Git history is unavailable"):
            load_recent_changes(tmp_path)


def test_recent_changes_format_is_readable(tmp_path):
    completed = SimpleNamespace(
        returncode=0,
        stdout="abc1234\x1f2026-08-06\x1fAdd safety policy",
        stderr="",
    )

    with patch("pua_inspector.changelog.subprocess.run", return_value=completed):
        message = format_recent_changes(load_recent_changes(tmp_path))

    assert message == "2026-08-06  abc1234\nAdd safety policy"
