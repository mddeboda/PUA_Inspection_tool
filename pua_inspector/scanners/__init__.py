from pua_inspector.scanners.filesystem import (
    AppDataScanner,
    BrowserExtensionsScanner,
    BrowserShortcutsScanner,
    ProgramDataScanner,
    StartupFoldersScanner,
)
from pua_inspector.scanners.registry import InstalledProgramsScanner, RegistryRunKeysScanner
from pua_inspector.scanners.system import (
    HostsFileScanner,
    RunningProcessesScanner,
    ScheduledTasksScanner,
    ServicesScanner,
    WmiPersistenceScanner,
)


def default_scanners():
    return [
        InstalledProgramsScanner(),
        ScheduledTasksScanner(),
        RegistryRunKeysScanner(),
        StartupFoldersScanner(),
        ServicesScanner(),
        AppDataScanner(),
        ProgramDataScanner(),
        BrowserShortcutsScanner(),
        BrowserExtensionsScanner(),
        HostsFileScanner(),
        WmiPersistenceScanner(),
        RunningProcessesScanner(),
    ]


__all__ = ["default_scanners"]

