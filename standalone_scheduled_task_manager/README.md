# Standalone Scheduled Task Manager

A focused Windows Tkinter application for inventorying and managing scheduled tasks without the rest of PUA Inspector.

## Features

- Automatically queries the local computer at startup.
- Queries remote computers with `schtasks.exe /s HOSTNAME` and the current Windows identity.
- Uses a fast summary query by default and loads verbose details when a task is selected.
- Supports an optional verbose full refresh.
- Filters by task name, action, author, account, status, hostname, and description.
- Hides Microsoft Windows tasks, disabled tasks, and empty tasks by default.
- Sortable task table with a visible action column.
- Plain-language task details and Windows result-code explanations.
- Enables, disables, and permanently deletes authorized tasks.
- Protects all tasks beneath `\Microsoft\Windows` from modification.
- Runs queries and changes in background threads so the interface remains responsive.

## Run

Use Python 3.10 or newer on Windows. An elevated session may be required to view or change all tasks.

```powershell
cd standalone_scheduled_task_manager
python run.py
```

Tkinter and `schtasks.exe` are included with standard Windows Python and Windows, so there are no third-party runtime dependencies.

## Test

```powershell
cd standalone_scheduled_task_manager
python -m unittest discover -s tests -v
python -m compileall -q .
```

Remote access and task changes depend on Windows permissions, firewall policy, and the Remote Scheduled Tasks Management rules. Use only on systems you are authorized to administer.
