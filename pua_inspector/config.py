from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from pua_inspector.models import KnownApp


PACKAGE_DATA = Path(__file__).parent / "data"
DEFAULT_IOC_FILE = PACKAGE_DATA / "known_apps.json"
DEFAULT_SETTINGS_FILE = PACKAGE_DATA / "settings.json"


@dataclass
class AppSettings:
    enabled_modules: list[str] = field(default_factory=list)
    virustotal_enabled: bool = True
    virustotal_timeout_seconds: int = 15
    scan_path_depth: int = 3
    max_files_per_location: int = 5000
    quarantine_directory: str = "%PROGRAMDATA%\\PUAInspector\\Quarantine"

    @classmethod
    def from_dict(cls, data: dict) -> "AppSettings":
        defaults = cls()
        return cls(
            enabled_modules=list(data.get("enabled_modules", defaults.enabled_modules)),
            virustotal_enabled=bool(data.get("virustotal_enabled", True)),
            virustotal_timeout_seconds=int(data.get("virustotal_timeout_seconds", 15)),
            scan_path_depth=max(1, int(data.get("scan_path_depth", 3))),
            max_files_per_location=max(100, int(data.get("max_files_per_location", 5000))),
            quarantine_directory=data.get("quarantine_directory", defaults.quarantine_directory),
        )


def load_known_apps(path: Path = DEFAULT_IOC_FILE) -> list[KnownApp]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return [KnownApp.from_dict(item) for item in payload["known_apps"]]


def load_settings(path: Path = DEFAULT_SETTINGS_FILE) -> AppSettings:
    if not path.exists():
        return AppSettings()
    with path.open("r", encoding="utf-8") as handle:
        return AppSettings.from_dict(json.load(handle))


def user_settings_path() -> Path:
    app_data = os.getenv("APPDATA")
    base = Path(app_data) if app_data else Path.home() / ".pua_inspector"
    return base / "PUAInspector" / "settings.json" if app_data else base / "settings.json"


def load_effective_settings() -> AppSettings:
    user_path = user_settings_path()
    return load_settings(user_path if user_path.exists() else DEFAULT_SETTINGS_FILE)


def save_settings(settings: AppSettings, path: Path | None = None) -> Path:
    destination = path or user_settings_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "enabled_modules": settings.enabled_modules,
        "virustotal_enabled": settings.virustotal_enabled,
        "virustotal_timeout_seconds": settings.virustotal_timeout_seconds,
        "scan_path_depth": settings.scan_path_depth,
        "max_files_per_location": settings.max_files_per_location,
        "quarantine_directory": settings.quarantine_directory,
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination


def load_api_key(env_file: Path | None = None) -> str:
    load_dotenv(dotenv_path=env_file, override=False)
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def expand_windows_path(value: str) -> Path:
    return Path(os.path.expandvars(value)).expanduser()
