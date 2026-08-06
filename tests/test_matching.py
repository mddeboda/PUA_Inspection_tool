from pua_inspector.config import load_known_apps
from pua_inspector.scanners.base import find_known_app
from pua_inspector.utils import extract_executable


def test_known_app_alias_match_is_case_insensitive():
    match = find_known_app("C:\\Users\\sam\\AppData\\Local\\WAVEBROWSER\\app.exe", load_known_apps())

    assert match is not None
    assert match.name == "Wave Browser"


def test_extract_quoted_executable():
    assert extract_executable('"C:\\Program Files\\App\\app.exe" --background') == (
        "C:\\Program Files\\App\\app.exe"
    )


def test_extract_unquoted_executable_with_spaces():
    assert extract_executable("C:\\Tools Folder\\sample.exe /silent") == (
        "C:\\Tools Folder\\sample.exe"
    )
