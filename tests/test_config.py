import json

from pua_inspector.config import AppSettings, load_known_apps, load_settings, save_settings


def test_default_ioc_file_contains_requested_entries():
    names = {app.name for app in load_known_apps()}

    assert {
        "OneStart.ai",
        "Shift Browser",
        "Wave Browser",
        "WebDiscover Browser",
        "RAV Endpoint Protection",
        "PC App Store",
        "PremierOpinion",
        "RelevantKnowledge",
        "Search Protect",
        "Ask Toolbar",
        "Browser Assistant",
        "Chromium Adware Variant",
    } <= names


def test_settings_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    original = AppSettings(enabled_modules=["Hosts File"], scan_path_depth=5)

    save_settings(original, path)
    loaded = load_settings(path)

    assert loaded.enabled_modules == ["Hosts File"]
    assert loaded.scan_path_depth == 5
    assert json.loads(path.read_text(encoding="utf-8"))["virustotal_enabled"] is True

