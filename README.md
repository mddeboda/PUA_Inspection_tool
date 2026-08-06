# PUA Inspector

PUA Inspector is a lightweight Windows desktop scanner for endpoint hygiene and potentially unwanted applications. It keeps the scanning engine independent of Tkinter so another presentation layer, including PySide6, can consume the same models and services later.

The initial release checks installed programs, scheduled tasks, Run/RunOnce keys, startup folders, services, AppData, ProgramData, browser shortcuts and extensions, the hosts file, WMI persistence, and running processes. Findings are matched against editable JSON indicators and detected executable files are SHA-256 hashed.

## Quickstart

Use Python 3.10 or newer on Windows. An elevated PowerShell session is recommended for a complete local scan.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

Add a VirusTotal API key to `.env` to enable reputation lookups:

```dotenv
VIRUSTOTAL_API_KEY=replace_with_your_key
```

The `.env` file is ignored by Git. Without a key, scanning and SHA-256 hashing still work and the details panel reports that VirusTotal is not configured.

## Usage notes

- Enter an optional value in **Keyword (optional)** to add a temporary, case-insensitive search term for the current scan. It checks the names, paths, commands, registry/task metadata, hosts entries, shortcuts, and extension metadata already collected by the selected modules; it does not search arbitrary file contents.
- Custom matches appear as `Keyword match: VALUE` with Low risk and a review-only recommendation. The keyword is included in JSON exports but is not saved to `known_apps.json`.
- Leave **Admin Share / SMB scan mode** unchecked for a local scan or a remote WinRM scan.
- For a remote file scan without WinRM, enter the target hostname and select **Admin Share / SMB scan mode**. The app uses `\\HOSTNAME\C$` with the current Windows credentials; it does not request or store an SMB password.
- SMB mode scans AppData, ProgramData, Chrome/Edge extensions, startup folders, browser shortcuts, the hosts file, and known directories under Program Files. Executable hashing and VirusTotal enrichment work across the share.
- Scheduled Tasks uses `schtasks.exe /query /s HOSTNAME /fo CSV /v` in SMB mode. This uses the remote Task Scheduler RPC service and the current Windows identity; no username or password is requested or stored.
- Installed Programs is a filesystem approximation in SMB mode. Run/RunOnce registry values, services, WMI persistence, and running processes require WinRM or another management channel and are logged as unavailable.
- SMB mode is read-only. **Remove Selected** is blocked for all SMB results.
- Double-click the finding details panel to open an available VirusTotal report.
- **Remove Selected** asks for confirmation. Files and directories are moved to `%PROGRAMDATA%\PUAInspector\Quarantine`; startup values and scheduled tasks are removed; detected services are stopped and disabled. Unsupported finding types remain manual actions.
- Treat IOC matches as administrative leads, not proof of malware. Review publisher, business approval, and VirusTotal context before remediation.

To verify admin-share access before scanning:

```powershell
Test-Path '\\TARGET-PC\C$'
Get-ChildItem '\\TARGET-PC\C$\Users' -Force
```

## Configuration

- IOC definitions: `pua_inspector/data/known_apps.json`
- Default settings: `pua_inspector/data/settings.json`
- User settings: `%APPDATA%\PUAInspector\settings.json`
- API key: `.env` as `VIRUSTOTAL_API_KEY`

Each IOC supports a name, aliases, known install paths, registry names, risk level, and recommended action. Expand the JSON file to fit your organization's software policy.

## Development

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
python -m compileall -q pua_inspector tests run.py
```

Backend code lives under `pua_inspector/scanners`, `engine.py`, and the service modules. Tkinter-specific code is isolated under `pua_inspector/ui`.

This application is intended for legitimate endpoint administration with authorization. Remote access and remediation depend on Windows permissions and local security policy.

## License

PUA Inspector is available under the [MIT License](LICENSE).
