from __future__ import annotations

from pua_inspector.config import AppSettings, load_api_key, load_effective_settings, load_known_apps
from pua_inspector.engine import ScanEngine
from pua_inspector.scanners import default_scanners
from pua_inspector.ui.main_window import MainWindow
from pua_inspector.virustotal import VirusTotalClient


def build_engine() -> tuple[ScanEngine, AppSettings]:
    settings = load_effective_settings()
    vt_client = VirusTotalClient(load_api_key(), settings.virustotal_timeout_seconds)
    engine = ScanEngine(default_scanners(), load_known_apps(), settings, vt_client)
    return engine, settings


def main() -> None:
    engine, settings = build_engine()
    window = MainWindow(engine, settings)
    window.mainloop()


if __name__ == "__main__":
    main()
