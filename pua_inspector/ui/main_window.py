from __future__ import annotations

import json
import os
import queue
import socket
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from pua_inspector.changelog import RecentChange, format_recent_changes, load_recent_changes
from pua_inspector.config import AppSettings, save_settings
from pua_inspector.engine import ScanEngine
from pua_inspector.exporter import export_report
from pua_inspector.models import Finding, ScanProgress, ScanReport
from pua_inspector.remediation import RemediationService
from pua_inspector.task_inventory import (
    ScheduledTaskRecord,
    delete_scheduled_task,
    query_scheduled_tasks,
    query_task_details,
    query_task_summaries,
    set_task_enabled,
)


class MainWindow(tk.Tk):
    def __init__(self, engine: ScanEngine, settings: AppSettings):
        super().__init__()
        self.engine = engine
        self.settings = settings
        self.remediation = RemediationService(settings)
        self.report: ScanReport | None = None
        self.last_scan_admin_share_mode = False
        self.recent_changes: list[RecentChange] = []
        self.changelog_status = "Loading recent changes..."
        self.task_records: list[ScheduledTaskRecord] = []
        self.task_records_by_item: dict[str, ScheduledTaskRecord] = {}
        self.task_detail_cache: dict[tuple[str, str], ScheduledTaskRecord] = {}
        self.task_detail_loading: set[tuple[str, str]] = set()
        self.task_query_target = socket.gethostname()
        self.task_query_remote = False
        self.task_query_verbose = False
        self.task_query_generation = 0
        self.task_inventory_load_started = False
        self.task_action_in_progress = False
        self.task_detail_windows: dict[tuple[str, str], tuple[tk.Toplevel, tk.Text]] = {}
        self.findings_by_item: dict[str, Finding] = {}
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.module_variables: dict[str, tk.BooleanVar] = {}

        self.title("PUA Inspector")
        self.geometry("1280x820")
        self.minsize(980, 680)
        self.configure(background="#f3f5f8")
        self._configure_style()
        self._build_ui()
        self.after(100, self._drain_events)
        threading.Thread(target=self._load_changelog_worker, daemon=True).start()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 20), foreground="#172033")
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground="#5d6678")
        style.configure("Primary.TButton", font=("Segoe UI Semibold", 10), padding=(14, 8))
        style.configure("TButton", font=("Segoe UI", 10), padding=(11, 7))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))
        style.configure("TLabelframe.Label", font=("Segoe UI Semibold", 10))

    def _build_ui(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        scanner_tab = ttk.Frame(self.notebook)
        self.task_inventory_tab = ttk.Frame(self.notebook)
        self.notebook.add(scanner_tab, text="Endpoint Scanner")
        self.notebook.add(self.task_inventory_tab, text="Scheduled Task Inventory")
        self._build_scanner_tab(scanner_tab)
        self._build_task_inventory_tab(self.task_inventory_tab)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_notebook_tab_changed)

    def _build_scanner_tab(self, parent: ttk.Frame) -> None:
        shell = ttk.Frame(parent, padding=18)
        shell.pack(fill=tk.BOTH, expand=True)
        shell.columnconfigure(1, weight=1)
        shell.rowconfigure(2, weight=3)
        shell.rowconfigure(4, weight=1)

        header = ttk.Frame(shell)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        ttk.Label(header, text="PUA Inspector", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Endpoint hygiene, persistence, and potentially unwanted application review",
            style="Subtitle.TLabel",
        ).pack(anchor="w")

        controls = ttk.Frame(shell)
        controls.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        controls.columnconfigure(1, weight=1)
        ttk.Label(controls, text="Hostname").grid(row=0, column=0, padx=(0, 8))
        self.hostname = ttk.Entry(controls)
        self.hostname.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.hostname.insert(0, socket.gethostname())
        self.admin_share_mode = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls,
            text="Admin Share / SMB scan mode",
            variable=self.admin_share_mode,
        ).grid(row=1, column=2, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(controls, text="Keyword (optional)").grid(
            row=1, column=0, padx=(0, 8), pady=(6, 0)
        )
        self.search_keyword = ttk.Entry(controls)
        self.search_keyword.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(6, 0))
        self.scan_button = ttk.Button(
            controls, text="Scan", style="Primary.TButton", command=self._start_scan
        )
        self.scan_button.grid(row=0, column=2, padx=4)
        ttk.Button(controls, text="Remediate Selected", command=self._remove_selected).grid(
            row=0, column=3, padx=4
        )
        ttk.Button(controls, text="Export Results", command=self._export).grid(
            row=0, column=4, padx=4
        )
        ttk.Button(controls, text="What's New", command=self._show_whats_new).grid(
            row=0, column=5, padx=(4, 0)
        )
        ttk.Button(controls, text="Settings", command=self._open_settings).grid(
            row=1, column=5, padx=(4, 0), pady=(6, 0)
        )

        modules_frame = ttk.LabelFrame(shell, text="Scan modules", padding=10)
        modules_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 12))
        module_buttons = ttk.Frame(modules_frame)
        module_buttons.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(
            module_buttons,
            text="Select All",
            command=lambda: self._set_all_modules(True),
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(
            module_buttons,
            text="Unselect All",
            command=lambda: self._set_all_modules(False),
        ).pack(side=tk.LEFT)
        enabled = set(self.settings.enabled_modules or self.engine.module_names)
        for row, module_name in enumerate(self.engine.module_names):
            variable = tk.BooleanVar(value=module_name in enabled)
            self.module_variables[module_name] = variable
            ttk.Checkbutton(modules_frame, text=module_name, variable=variable).grid(
                row=row + 1, column=0, sticky="w", pady=2
            )

        results_frame = ttk.Frame(shell)
        results_frame.grid(row=2, column=1, sticky="nsew")
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        columns = ("Finding", "Category", "Location", "Risk", "Status", "Action")
        self.results = ttk.Treeview(
            results_frame, columns=columns, show="headings", selectmode="extended"
        )
        widths = {"Finding": 150, "Category": 160, "Location": 270, "Risk": 70, "Status": 100, "Action": 260}
        for column in columns:
            self.results.heading(column, text=column)
            self.results.column(column, width=widths[column], minwidth=60, stretch=True)
        self.results.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.results.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.results.configure(yscrollcommand=scroll.set)
        self.results.tag_configure("High", background="#fff0f0")
        self.results.tag_configure("Critical", background="#ffdede")
        self.results.bind("<<TreeviewSelect>>", self._show_details)
        self.results.bind("<Button-3>", self._show_results_context_menu)
        self.results.bind("<Shift-F10>", self._show_results_context_menu)

        progress_frame = ttk.Frame(shell)
        progress_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=12)
        progress_frame.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_frame, mode="determinate")
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.progress_label = ttk.Label(progress_frame, text="Ready")
        self.progress_label.grid(row=0, column=1)

        output = ttk.Panedwindow(shell, orient=tk.HORIZONTAL)
        output.grid(row=4, column=0, columnspan=2, sticky="nsew")
        log_frame = ttk.LabelFrame(output, text="Status log", padding=6)
        detail_frame = ttk.LabelFrame(output, text="Finding details / VirusTotal", padding=6)
        output.add(log_frame, weight=1)
        output.add(detail_frame, weight=1)
        self.log = tk.Text(
            log_frame, height=9, wrap="word", state="disabled", font=("Consolas", 9), relief="flat"
        )
        self.log.pack(fill=tk.BOTH, expand=True)
        self.details = tk.Text(
            detail_frame, height=9, wrap="word", state="disabled", font=("Consolas", 9), relief="flat"
        )
        self.details.pack(fill=tk.BOTH, expand=True)
        self.details.bind("<Double-Button-1>", self._open_vt_report)

    def _build_task_inventory_tab(self, parent: ttk.Frame) -> None:
        shell = ttk.Frame(parent, padding=18)
        shell.pack(fill=tk.BOTH, expand=True)
        shell.columnconfigure(0, weight=1)

        ttk.Label(shell, text="Scheduled Task Inventory", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            shell,
            text=(
                "Review and manage scheduled tasks. Remote hostnames use your current "
                "Windows identity; Microsoft system tasks are protected from changes."
            ),
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 14))

        controls = ttk.Frame(shell)
        controls.grid(row=2, column=0, sticky="new", pady=(0, 10))
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(4, weight=1)
        ttk.Label(controls, text="Hostname").grid(row=0, column=0, padx=(0, 8))
        self.task_hostname = ttk.Entry(controls)
        self.task_hostname.grid(row=0, column=1, sticky="ew", padx=(0, 12))
        self.task_hostname.insert(0, socket.gethostname())
        self.task_query_button = ttk.Button(
            controls,
            text="Refresh Tasks",
            style="Primary.TButton",
            command=self._start_task_query,
        )
        self.task_query_button.grid(row=0, column=2, padx=(0, 18))
        ttk.Label(controls, text="Filter").grid(row=0, column=3, padx=(0, 8))
        self.task_filter = tk.StringVar()
        task_filter_entry = ttk.Entry(controls, textvariable=self.task_filter)
        task_filter_entry.grid(row=0, column=4, sticky="ew")
        task_filter_entry.bind("<KeyRelease>", self._filter_task_inventory)
        self.hide_microsoft_tasks = tk.BooleanVar(value=True)
        self.show_disabled_tasks = tk.BooleanVar(value=False)
        self.hide_empty_tasks = tk.BooleanVar(value=True)
        self.verbose_task_query = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls,
            text="Hide Microsoft Windows tasks",
            variable=self.hide_microsoft_tasks,
            command=self._filter_task_inventory,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            controls,
            text="Show disabled tasks",
            variable=self.show_disabled_tasks,
            command=self._filter_task_inventory,
        ).grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            controls,
            text="Hide empty tasks",
            variable=self.hide_empty_tasks,
            command=self._filter_task_inventory,
        ).grid(row=1, column=3, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            controls,
            text="Verbose initial query (slower)",
            variable=self.verbose_task_query,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(
            controls,
            text="Empty means no status, schedule, action, or description.",
            style="Subtitle.TLabel",
        ).grid(row=2, column=2, columnspan=3, sticky="w", pady=(6, 0))

        table_frame = ttk.Frame(shell)
        table_frame.grid(row=3, column=0, sticky="nsew")
        shell.rowconfigure(3, weight=1)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = (
            "Task Name",
            "Status",
            "Next Run",
            "Hostname",
        )
        self.task_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        widths = {
            "Task Name": 520,
            "Status": 120,
            "Next Run": 180,
            "Hostname": 160,
        }
        for column in columns:
            self.task_tree.heading(
                column,
                text=column,
                command=lambda selected=column: self._sort_task_inventory(
                    selected, reverse=False
                ),
            )
            self.task_tree.column(column, width=widths[column], minwidth=70)
        self.task_tree.grid(row=0, column=0, sticky="nsew")
        task_scroll_y = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.task_tree.yview
        )
        task_scroll_y.grid(row=0, column=1, sticky="ns")
        task_scroll_x = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.task_tree.xview
        )
        task_scroll_x.grid(row=1, column=0, sticky="ew")
        self.task_tree.configure(
            yscrollcommand=task_scroll_y.set,
            xscrollcommand=task_scroll_x.set,
        )
        self.task_tree.bind("<<TreeviewSelect>>", self._show_task_details)
        self.task_tree.bind("<Button-3>", self._show_task_context_menu)
        self.task_tree.bind("<Shift-F10>", self._show_task_context_menu)

        footer = ttk.Frame(shell)
        footer.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        footer.columnconfigure(1, weight=1)
        self.task_status = ttk.Label(footer, text="Ready")
        self.task_status.grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.task_details = tk.Text(
            footer,
            height=7,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            relief="flat",
        )
        self.task_details.grid(row=0, column=1, sticky="ew")

    def _start_scan(self) -> None:
        selected = [name for name, variable in self.module_variables.items() if variable.get()]
        if not selected:
            messagebox.showwarning("No modules selected", "Select at least one scan module.")
            return
        self._clear_results()
        self.scan_button.configure(state="disabled")
        self.progress.configure(maximum=len(selected), value=0)
        self.last_scan_admin_share_mode = self.admin_share_mode.get()
        target = self.hostname.get().strip() or socket.gethostname()
        keyword = self.search_keyword.get().strip()
        transport = (
            f"Admin Share / SMB at \\\\{target}\\C$"
            if self.last_scan_admin_share_mode
            else "local PowerShell or WinRM"
        )
        self._write_log(f"Starting scan of {target} using {transport}...")
        if keyword:
            self._write_log(f"Including custom keyword match: {keyword}")
        thread = threading.Thread(
            target=self._scan_worker,
            args=(
                self.hostname.get().strip(),
                selected,
                self.last_scan_admin_share_mode,
                keyword,
            ),
            daemon=True,
        )
        thread.start()

    def _set_all_modules(self, selected: bool) -> None:
        for variable in self.module_variables.values():
            variable.set(selected)

    def _on_notebook_tab_changed(self, _event=None) -> None:
        if self.notebook.select() != str(self.task_inventory_tab):
            return
        self.after_idle(self._start_initial_task_query)

    def _start_initial_task_query(self) -> None:
        if not self.task_inventory_load_started:
            self._start_task_query()

    def _start_task_query(self) -> None:
        self.task_inventory_load_started = True
        target = self.task_hostname.get().strip() or socket.gethostname()
        local_names = {
            ".",
            "localhost",
            socket.gethostname().casefold(),
            socket.getfqdn().casefold(),
        }
        remote = target.casefold() not in local_names
        self.task_query_button.configure(state="disabled")
        self.task_status.configure(
            text=f"Querying {target}{' remotely' if remote else ''}..."
        )
        self.task_query_target = target
        self.task_query_remote = remote
        self.task_query_verbose = self.verbose_task_query.get()
        self.task_query_generation += 1
        generation = self.task_query_generation
        self.task_records = []
        self.task_records_by_item.clear()
        self.task_detail_cache.clear()
        self.task_detail_loading.clear()
        self._close_all_task_detail_windows()
        self._render_task_inventory([])
        self._set_text(self.task_details, "")
        threading.Thread(
            target=self._task_query_worker,
            args=(target, remote, self.task_query_verbose, generation),
            daemon=True,
        ).start()

    def _task_query_worker(
        self, hostname: str, remote: bool, verbose: bool, generation: int
    ) -> None:
        try:
            records = (
                query_scheduled_tasks(hostname, remote=remote, verbose=True)
                if verbose
                else query_task_summaries(hostname, remote=remote)
            )
            self.events.put(("task_inventory", (generation, records)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("task_inventory_error", (generation, str(error))))

    def _filter_task_inventory(self, _event=None) -> None:
        keyword = self.task_filter.get().strip().casefold()
        records = []
        for record in self.task_records:
            if self.hide_microsoft_tasks.get() and record.is_microsoft_windows_task:
                continue
            if not self.show_disabled_tasks.get() and record.is_disabled:
                continue
            searchable = self.task_detail_cache.get(record.cache_key, record)
            if self.hide_empty_tasks.get() and searchable.is_empty:
                continue
            if keyword and keyword not in searchable.searchable_text():
                continue
            records.append(record)
        self._render_task_inventory(records)
        self.task_status.configure(
            text=f"Showing {len(records)} of {len(self.task_records)} task(s)"
        )

    def _render_task_inventory(self, records: list[ScheduledTaskRecord]) -> None:
        for item in self.task_tree.get_children():
            self.task_tree.delete(item)
        self.task_records_by_item.clear()
        for record in records:
            item = self.task_tree.insert(
                "",
                "end",
                values=(
                    record.task_name,
                    record.status,
                    record.next_run_time,
                    record.hostname,
                ),
            )
            self.task_records_by_item[item] = record

    def _sort_task_inventory(self, column: str, reverse: bool) -> None:
        items = [
            (str(self.task_tree.set(item, column)).casefold(), item)
            for item in self.task_tree.get_children("")
        ]
        items.sort(reverse=reverse)
        for position, (_value, item) in enumerate(items):
            self.task_tree.move(item, "", position)
        self.task_tree.heading(
            column,
            command=lambda: self._sort_task_inventory(column, not reverse),
        )

    def _show_task_details(self, _event=None) -> None:
        selection = self.task_tree.selection()
        if not selection:
            return
        record = self.task_records_by_item[selection[0]]
        detail = self.task_detail_cache.get(record.cache_key)
        if detail:
            self._render_task_details(detail)
            return
        self._render_task_details(record, loading=True)
        if record.cache_key in self.task_detail_loading:
            return
        self.task_detail_loading.add(record.cache_key)
        threading.Thread(
            target=self._task_detail_worker,
            args=(
                record,
                self.task_query_target,
                self.task_query_remote,
                self.task_query_generation,
            ),
            daemon=True,
        ).start()

    def _task_detail_worker(
        self,
        record: ScheduledTaskRecord,
        hostname: str,
        remote: bool,
        generation: int,
    ) -> None:
        try:
            detail = query_task_details(
                hostname,
                record.task_name,
                remote=remote,
            )
            self.events.put(
                ("task_detail", (generation, record.cache_key, detail))
            )
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(
                ("task_detail_error", (generation, record.cache_key, str(error)))
            )

    def _render_task_details(
        self, record: ScheduledTaskRecord, *, loading: bool = False
    ) -> None:
        suffix = "\n\nLoading verbose details..." if loading else ""
        self._set_text(
            self.task_details,
            "\n".join(
                (
                    f"Task: {record.task_name}",
                    f"Action: {record.action or 'N/A'}",
                    f"Start in: {record.start_in or 'N/A'}",
                    f"Run as: {record.run_as_user or 'N/A'}",
                    f"Status: {record.status or 'N/A'}",
                    f"Last result: {record.last_result or 'N/A'}",
                    f"Comment: {record.comment or 'N/A'}",
                )
            )
            + suffix,
        )

    def _show_task_context_menu(self, event) -> str:
        if getattr(event, "num", None) == 3:
            item = self.task_tree.identify_row(event.y)
            if not item:
                return "break"
            self.task_tree.selection_set(item)
            self.task_tree.focus(item)
            x_root, y_root = event.x_root, event.y_root
        else:
            selection = self.task_tree.selection()
            if not selection:
                return "break"
            item = self.task_tree.focus() or selection[0]
            bounds = self.task_tree.bbox(item)
            if not bounds:
                return "break"
            x_root = self.task_tree.winfo_rootx() + bounds[0] + 24
            y_root = self.task_tree.winfo_rooty() + bounds[1] + bounds[3]

        menu = self._build_task_context_menu()
        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()
        return "break"

    def _build_task_context_menu(self) -> tk.Menu:
        record = self._selected_task_record()
        protected = bool(record and record.is_microsoft_windows_task)
        actions_available = bool(
            record and not protected and not self.task_action_in_progress
        )
        menu = tk.Menu(self, tearoff=False, font=("Segoe UI", 9))
        menu.add_command(
            label="View Full Task Details...",
            command=self._show_task_full_details,
            state="normal" if record else "disabled",
        )
        menu.add_separator()
        menu.add_command(
            label="Enable Task",
            command=lambda: self._confirm_task_state_change(enabled=True),
            state=(
                "normal"
                if actions_available and record and record.is_disabled
                else "disabled"
            ),
        )
        menu.add_command(
            label="Disable Task...",
            command=lambda: self._confirm_task_state_change(enabled=False),
            state=(
                "normal"
                if actions_available and record and not record.is_disabled
                else "disabled"
            ),
        )
        menu.add_command(
            label="Delete Scheduled Task...",
            command=self._confirm_task_delete,
            state="normal" if actions_available else "disabled",
        )
        if protected:
            menu.add_separator()
            menu.add_command(
                label="Protected Microsoft system task - changes are disabled",
                state="disabled",
            )
        return menu

    def _selected_task_record(self) -> ScheduledTaskRecord | None:
        selection = self.task_tree.selection()
        return self.task_records_by_item.get(selection[0]) if selection else None

    def _confirm_task_state_change(self, *, enabled: bool) -> None:
        record = self._selected_task_record()
        if not self._task_action_is_allowed(record):
            return
        verb = "Enable" if enabled else "Disable"
        effect = (
            "This allows the task to run according to its schedule."
            if enabled
            else (
                "This prevents future scheduled runs. It does not stop a copy that is "
                "already running."
            )
        )
        if not messagebox.askyesno(
            f"{verb} Scheduled Task",
            f"{verb} this task on {record.hostname}?\n\n"
            f"{record.task_name}\n\n{effect}",
            icon="question" if enabled else "warning",
        ):
            return
        self._start_task_action("enable" if enabled else "disable", record)

    def _confirm_task_delete(self) -> None:
        record = self._selected_task_record()
        if not self._task_action_is_allowed(record):
            return
        if not messagebox.askyesno(
            "Delete Scheduled Task",
            f"Permanently delete this task from {record.hostname}?\n\n"
            f"{record.task_name}\n\n"
            "This removes the task definition and cannot be undone. It does not "
            "delete the program or script that the task runs.",
            icon="warning",
        ):
            return
        self._start_task_action("delete", record)

    def _task_action_is_allowed(self, record: ScheduledTaskRecord | None) -> bool:
        if not record:
            return False
        if record.is_microsoft_windows_task:
            messagebox.showwarning(
                "Protected System Task",
                "PUA Inspector does not modify tasks under \\Microsoft\\Windows. "
                "Use Windows administrative tools if an authorized change is required.",
            )
            return False
        if self.task_action_in_progress:
            messagebox.showinfo(
                "Task Action in Progress",
                "Wait for the current scheduled-task action to finish.",
            )
            return False
        return True

    def _start_task_action(
        self, action: str, record: ScheduledTaskRecord
    ) -> None:
        self.task_action_in_progress = True
        self.task_query_button.configure(state="disabled")
        self.task_status.configure(
            text=f"{action.title()} in progress: {record.task_name}"
        )
        threading.Thread(
            target=self._task_action_worker,
            args=(
                action,
                record,
                self.task_query_target,
                self.task_query_remote,
                self.task_query_generation,
            ),
            daemon=True,
        ).start()

    def _task_action_worker(
        self,
        action: str,
        record: ScheduledTaskRecord,
        hostname: str,
        remote: bool,
        generation: int,
    ) -> None:
        try:
            if action == "delete":
                result = delete_scheduled_task(
                    hostname, record.task_name, remote=remote
                )
            else:
                result = set_task_enabled(
                    hostname,
                    record.task_name,
                    enabled=action == "enable",
                    remote=remote,
                )
            self.events.put(
                ("task_action_complete", (generation, action, record, result))
            )
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(
                ("task_action_error", (generation, action, record, str(error)))
            )

    def _show_task_full_details(self) -> None:
        record = self._selected_task_record()
        if not record:
            return
        existing = self.task_detail_windows.get(record.cache_key)
        if existing and existing[0].winfo_exists():
            existing[0].lift()
            existing[0].focus_set()
            return

        detail = self.task_detail_cache.get(record.cache_key, record)
        dialog = tk.Toplevel(self)
        dialog.title(f"Scheduled Task Details - {record.task_name}")
        dialog.geometry("760x560")
        dialog.minsize(620, 420)
        dialog.transient(self)

        shell = ttk.Frame(dialog, padding=16)
        shell.pack(fill=tk.BOTH, expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(2, weight=1)
        ttk.Label(shell, text="Scheduled Task Details", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            shell,
            text="A plain-language summary of when the task runs and what it launches.",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        detail_frame = ttk.Frame(shell)
        detail_frame.grid(row=2, column=0, sticky="nsew")
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(0, weight=1)
        detail_text = tk.Text(
            detail_frame,
            wrap="word",
            state="normal",
            font=("Segoe UI", 10),
            relief="flat",
            padx=14,
            pady=12,
        )
        detail_text.grid(row=0, column=0, sticky="nsew")
        detail_scroll = ttk.Scrollbar(
            detail_frame, orient="vertical", command=detail_text.yview
        )
        detail_scroll.grid(row=0, column=1, sticky="ns")
        detail_text.configure(yscrollcommand=detail_scroll.set)
        detail_text.insert("1.0", self._format_task_details(detail))
        if record.cache_key not in self.task_detail_cache:
            detail_text.insert(
                "end",
                "\n\nLoading additional task information in the background...",
            )
        detail_text.configure(state="disabled")

        buttons = ttk.Frame(shell)
        buttons.grid(row=3, column=0, sticky="e", pady=(12, 0))
        ttk.Button(
            buttons,
            text="Copy Details",
            command=lambda: self._copy_to_clipboard(
                detail_text.get("1.0", "end-1c"), "Scheduled task details"
            ),
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            buttons,
            text="Close",
            command=lambda key=record.cache_key: self._close_task_detail_window(key),
        ).pack(side=tk.LEFT)

        self.task_detail_windows[record.cache_key] = (dialog, detail_text)
        dialog.protocol(
            "WM_DELETE_WINDOW",
            lambda key=record.cache_key: self._close_task_detail_window(key),
        )
        dialog.bind(
            "<Escape>",
            lambda _event, key=record.cache_key: self._close_task_detail_window(key),
        )
        dialog.focus_set()
        if record.cache_key not in self.task_detail_cache:
            self._show_task_details()

    def _close_task_detail_window(self, cache_key: tuple[str, str]) -> None:
        dialog_entry = self.task_detail_windows.pop(cache_key, None)
        if dialog_entry and dialog_entry[0].winfo_exists():
            dialog_entry[0].destroy()

    def _close_all_task_detail_windows(self) -> None:
        for cache_key in list(self.task_detail_windows):
            self._close_task_detail_window(cache_key)

    def _refresh_task_detail_window(
        self, cache_key: tuple[str, str], record: ScheduledTaskRecord
    ) -> None:
        dialog_entry = self.task_detail_windows.get(cache_key)
        if not dialog_entry or not dialog_entry[0].winfo_exists():
            return
        self._set_text(dialog_entry[1], self._format_task_details(record))

    @staticmethod
    def _format_task_details(record: ScheduledTaskRecord) -> str:
        status = record.status or "Unknown"
        status_explanation = {
            "ready": "Enabled and waiting for its next trigger.",
            "running": "The task is currently running.",
            "disabled": "Disabled; it will not start on its schedule.",
        }.get(status.casefold(), "Windows reported the state shown above.")
        result = record.last_result or "Not available"
        result_explanation = {
            "0": "The most recent run completed successfully.",
            "0x0": "The most recent run completed successfully.",
            "267009": "Windows reports that the task is currently running.",
            "0x41301": "Windows reports that the task is currently running.",
            "267011": "The task has not run yet.",
            "0x41303": "The task has not run yet.",
        }.get(result.casefold(), "This is the result code reported by Windows.")
        return "\n".join(
            (
                "OVERVIEW",
                f"Task name: {record.task_name}",
                f"Computer: {record.hostname or 'Not available'}",
                f"Current state: {status}",
                f"What that means: {status_explanation}",
                "",
                "WHAT IT RUNS",
                f"Program or command: {record.action or 'Not available'}",
                f"Starting folder: {record.start_in or 'Not specified'}",
                f"Runs as account: {record.run_as_user or 'Not available'}",
                f"Created by: {record.author or 'Not available'}",
                "",
                "TIMING AND HISTORY",
                f"Next scheduled run: {record.next_run_time or 'Not available'}",
                f"Most recent run: {record.last_run_time or 'Not available'}",
                f"Last result: {result}",
                f"What that means: {result_explanation}",
                "",
                "DESCRIPTION",
                record.comment or "No description was provided for this task.",
            )
        )

    def _scan_worker(
        self,
        hostname: str,
        modules: list[str],
        admin_share_mode: bool,
        search_keyword: str,
    ) -> None:
        try:
            report = self.engine.scan(
                hostname,
                modules,
                self._queue_progress,
                admin_share_mode=admin_share_mode,
                search_keyword=search_keyword,
            )
            self.events.put(("complete", report))
        except Exception as error:
            self.events.put(("fatal", str(error)))

    def _queue_progress(self, progress: ScanProgress) -> None:
        self.events.put(("progress", progress))

    def _drain_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "progress":
                    progress = payload
                    self.progress.configure(value=progress.completed)
                    self.progress_label.configure(text=progress.message)
                    self._write_log(progress.message)
                elif event == "complete":
                    self._scan_complete(payload)
                elif event == "fatal":
                    self.scan_button.configure(state="normal")
                    self.progress_label.configure(text="Scan failed")
                    messagebox.showerror("Scan failed", str(payload))
                elif event == "changelog":
                    self.recent_changes = payload
                    self.changelog_status = ""
                elif event == "changelog_error":
                    self.changelog_status = str(payload)
                elif event == "task_inventory":
                    generation, records = payload
                    if generation != self.task_query_generation:
                        continue
                    self.task_records = records
                    if self.task_query_verbose:
                        self.task_detail_cache = {
                            record.cache_key: record for record in self.task_records
                        }
                    self.task_query_button.configure(state="normal")
                    self._filter_task_inventory()
                elif event == "task_inventory_error":
                    generation, message = payload
                    if generation != self.task_query_generation:
                        continue
                    self.task_query_button.configure(state="normal")
                    self.task_status.configure(text="Query failed")
                    messagebox.showerror("Scheduled Task Query", message)
                elif event == "task_detail":
                    generation, cache_key, record = payload
                    if generation != self.task_query_generation:
                        continue
                    self.task_detail_loading.discard(cache_key)
                    self.task_detail_cache[cache_key] = record
                    self._refresh_selected_task_detail(cache_key)
                elif event == "task_detail_error":
                    generation, cache_key, message = payload
                    if generation != self.task_query_generation:
                        continue
                    self.task_detail_loading.discard(cache_key)
                    self._show_task_detail_error(cache_key, message)
                elif event == "task_action_complete":
                    generation, action, record, _result = payload
                    if generation != self.task_query_generation:
                        continue
                    self.task_action_in_progress = False
                    if action == "delete":
                        self._close_task_detail_window(record.cache_key)
                    past_tense = {
                        "enable": "enabled",
                        "disable": "disabled",
                        "delete": "deleted",
                    }[action]
                    messagebox.showinfo(
                        "Scheduled Task Updated",
                        f"The task was {past_tense} successfully.\n\n"
                        f"{record.task_name}",
                    )
                    self._start_task_query()
                elif event == "task_action_error":
                    generation, action, record, message = payload
                    if generation != self.task_query_generation:
                        continue
                    self.task_action_in_progress = False
                    self.task_query_button.configure(state="normal")
                    self.task_status.configure(text=f"Could not {action} task")
                    messagebox.showerror(
                        "Scheduled Task Action Failed",
                        f"Could not {action} this task:\n\n{record.task_name}\n\n{message}",
                    )
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _load_changelog_worker(self) -> None:
        try:
            self.events.put(("changelog", load_recent_changes(limit=5)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("changelog_error", str(error)))

    def _refresh_selected_task_detail(self, cache_key: tuple[str, str]) -> None:
        detail = self.task_detail_cache[cache_key]
        self._refresh_task_detail_window(cache_key, detail)
        selection = self.task_tree.selection()
        if not selection:
            return
        selected = self.task_records_by_item.get(selection[0])
        if selected and selected.cache_key == cache_key:
            self._render_task_details(detail)

    def _show_task_detail_error(
        self, cache_key: tuple[str, str], message: str
    ) -> None:
        selection = self.task_tree.selection()
        if selection:
            selected = self.task_records_by_item.get(selection[0])
            if selected and selected.cache_key == cache_key:
                self._set_text(
                    self.task_details,
                    f"Task: {selected.task_name}\n\n"
                    f"Unable to load verbose details:\n{message}",
                )
        dialog_entry = self.task_detail_windows.get(cache_key)
        if dialog_entry and dialog_entry[0].winfo_exists():
            self._set_text(
                dialog_entry[1],
                f"Unable to load additional task details.\n\n{message}",
            )

    def _show_whats_new(self) -> None:
        message = (
            format_recent_changes(self.recent_changes)
            if self.recent_changes
            else self.changelog_status or "No Git changes are available."
        )
        messagebox.showinfo("What's New — Last 5 Changes", message)

    def _scan_complete(self, report: ScanReport) -> None:
        self.report = report
        for finding in report.findings:
            vt_ratio = finding.virustotal.detection_ratio if finding.virustotal else ""
            status = finding.status.value + (f" · VT {vt_ratio}" if vt_ratio else "")
            item = self.results.insert(
                "",
                "end",
                values=(
                    finding.finding,
                    finding.category,
                    finding.location,
                    finding.risk.value,
                    status,
                    finding.action,
                ),
                tags=(finding.risk.value,),
            )
            self.findings_by_item[item] = finding
        for error in report.errors:
            self._write_log(f"Warning: {error}")
        self._write_log(f"Completed with {len(report.findings)} finding(s) and {len(report.errors)} warning(s).")
        self.progress.configure(value=self.progress["maximum"])
        self.progress_label.configure(text="Complete")
        self.scan_button.configure(state="normal")

    def _remove_selected(self) -> None:
        selected = self.results.selection()
        if not selected:
            messagebox.showinfo("Remediate Selected", "Select one or more findings first.")
            return
        if self.last_scan_admin_share_mode:
            messagebox.showwarning(
                "SMB remediation blocked",
                "Admin Share / SMB scan mode is read-only in this release.",
            )
            return
        if self.report and self.report.hostname.casefold() not in {
            socket.gethostname().casefold(), "localhost", "."
        }:
            messagebox.showwarning(
                "Remote remediation blocked",
                "This release only performs remediation on the local endpoint.",
            )
            return
        eligible = [
            item for item in selected if self.findings_by_item[item].remediation_allowed
        ]
        blocked = [item for item in selected if item not in eligible]
        if not eligible:
            reasons = {
                self.findings_by_item[item].remediation_block_reason
                or "Remediation is blocked by policy."
                for item in blocked
            }
            messagebox.showwarning(
                "Remediation blocked",
                "\n".join(sorted(reasons)),
            )
            return
        confirmation = (
            "Remediate the eligible selected findings? Files are moved to quarantine."
        )
        if blocked:
            confirmation += f" {len(blocked)} policy-blocked finding(s) will be skipped."
        if not messagebox.askyesno(
            "Confirm remediation",
            confirmation,
        ):
            return
        for item in blocked:
            finding = self.findings_by_item[item]
            self._write_log(
                f"Skipped {finding.finding}: {finding.remediation_block_reason}"
            )
        for item in eligible:
            finding = self.findings_by_item[item]
            success, message = self.remediation.remediate(finding)
            values = list(self.results.item(item, "values"))
            values[4] = finding.status.value
            self.results.item(item, values=values)
            self._write_log(("Success: " if success else "Unable: ") + message)

    def _export(self) -> None:
        if not self.report:
            messagebox.showinfo("Export Results", "Run a scan before exporting results.")
            return
        self._export_report(self.report, "Export scan results")

    def _export_selected(self) -> None:
        findings = self._selected_findings()
        if not findings or not self.report:
            messagebox.showinfo(
                "Export Selected Findings",
                "Select one or more findings first.",
            )
            return
        selected_report = ScanReport(
            hostname=self.report.hostname,
            findings=findings,
            errors=[],
            started_at=self.report.started_at,
            finished_at=self.report.finished_at,
            search_keyword=self.report.search_keyword,
        )
        self._export_report(selected_report, "Export selected findings")

    def _export_report(self, report: ScanReport, title: str) -> None:
        filename = filedialog.asksaveasfilename(
            title=title,
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("JSON files", "*.json")),
        )
        if not filename:
            return
        try:
            export_report(report, Path(filename))
            self._write_log(f"Exported results to {filename}")
        except (OSError, ValueError) as error:
            messagebox.showerror("Export failed", str(error))

    def _open_settings(self) -> None:
        SettingsDialog(self, self.settings, self._save_settings)

    def _save_settings(self) -> None:
        self.settings.enabled_modules = [
            name for name, variable in self.module_variables.items() if variable.get()
        ]
        try:
            path = save_settings(self.settings)
            self._write_log(f"Settings saved to {path}")
        except OSError as error:
            messagebox.showerror("Settings", f"Could not save settings: {error}")

    def _show_details(self, _event=None) -> None:
        selection = self.results.selection()
        if not selection:
            return
        finding = self.findings_by_item[selection[0]]
        lines = [
            f"Finding: {finding.finding}",
            f"Location: {finding.location}",
            f"Executable: {finding.executable or 'N/A'}",
            f"SHA-256: {finding.sha256 or 'N/A'}",
            f"Remediation allowed: {'Yes' if finding.remediation_allowed else 'No'}",
        ]
        if finding.remediation_block_reason:
            lines.append(f"Remediation policy: {finding.remediation_block_reason}")
        if finding.virustotal:
            vt = finding.virustotal
            lines.extend(
                [
                    f"VT detection ratio: {vt.detection_ratio}",
                    f"VT reputation: {vt.reputation if vt.reputation is not None else 'N/A'}",
                    f"VT last analysis: {vt.last_analysis_date or 'N/A'}",
                    f"VT report: {vt.report_url or 'N/A'}",
                    f"VT error: {vt.error or 'None'}",
                ]
            )
        lines.append("\nDouble-click this panel to open the VirusTotal report when available.")
        self._set_text(self.details, "\n".join(lines))

    def _show_results_context_menu(self, event) -> str:
        if getattr(event, "num", None) == 3:
            item = self.results.identify_row(event.y)
            if not item:
                return "break"
            if item not in self.results.selection():
                self.results.selection_set(item)
            self.results.focus(item)
            x_root, y_root = event.x_root, event.y_root
        else:
            selection = self.results.selection()
            if not selection:
                return "break"
            item = self.results.focus() or selection[0]
            bounds = self.results.bbox(item)
            if not bounds:
                return "break"
            x_root = self.results.winfo_rootx() + bounds[0] + 24
            y_root = self.results.winfo_rooty() + bounds[1] + bounds[3]

        menu = self._build_results_context_menu()
        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()
        return "break"

    def _build_results_context_menu(self) -> tk.Menu:
        findings = self._selected_findings()
        single = findings[0] if len(findings) == 1 else None
        can_remediate = self._can_remediate(findings)
        local_path = self._local_finding_path(single) if single else None
        has_vt_report = bool(
            single and single.virustotal and single.virustotal.report_url
        )
        is_scheduled_task = bool(
            single
            and (
                single.remediation_type == "scheduled_task"
                or "scheduled task" in single.category.casefold()
            )
        )

        menu = tk.Menu(self, tearoff=False, font=("Segoe UI", 9))
        menu.add_command(
            label="View Full Details...",
            command=self._show_full_details,
            state="normal" if single else "disabled",
        )

        copy_menu = tk.Menu(menu, tearoff=False, font=("Segoe UI", 9))
        copy_menu.add_command(
            label="Finding Name",
            command=lambda: self._copy_finding_value("finding"),
        )
        copy_menu.add_command(
            label="Location",
            command=lambda: self._copy_finding_value("location"),
        )
        copy_menu.add_command(
            label="Executable Path",
            command=lambda: self._copy_finding_value("executable"),
            state="normal" if single and single.executable else "disabled",
        )
        copy_menu.add_command(
            label="SHA-256 Hash",
            command=lambda: self._copy_finding_value("sha256"),
            state="normal" if single and single.sha256 else "disabled",
        )
        copy_menu.add_command(
            label="VirusTotal Report Link",
            command=lambda: self._copy_finding_value("vt_report_url"),
            state="normal" if has_vt_report else "disabled",
        )
        menu.add_cascade(
            label="Copy",
            menu=copy_menu,
            state="normal" if single else "disabled",
        )
        menu.add_separator()
        menu.add_command(
            label="Open Containing Folder",
            command=self._open_containing_folder,
            state="normal" if local_path else "disabled",
        )
        menu.add_command(
            label="Open VirusTotal Report",
            command=self._open_vt_report,
            state="normal" if has_vt_report else "disabled",
        )
        menu.add_command(
            label="View in Scheduled Task Inventory",
            command=self._view_in_task_inventory,
            state="normal" if is_scheduled_task else "disabled",
        )
        menu.add_separator()
        menu.add_command(
            label="Export Selected Findings...",
            command=self._export_selected,
            state="normal" if findings else "disabled",
        )
        menu.add_command(
            label="Remediate Selected Findings...",
            command=self._remove_selected,
            state="normal" if can_remediate else "disabled",
        )
        return menu

    def _selected_findings(self) -> list[Finding]:
        return [
            self.findings_by_item[item]
            for item in self.results.selection()
            if item in self.findings_by_item
        ]

    def _can_remediate(self, findings: list[Finding]) -> bool:
        if not findings or self.last_scan_admin_share_mode:
            return False
        if self.report and self.report.hostname.casefold() not in {
            socket.gethostname().casefold(),
            "localhost",
            ".",
        }:
            return False
        return any(finding.remediation_allowed for finding in findings)

    def _show_full_details(self) -> None:
        findings = self._selected_findings()
        if len(findings) != 1:
            return
        finding = findings[0]
        dialog = tk.Toplevel(self)
        dialog.title(f"Finding Details - {finding.finding}")
        dialog.geometry("760x520")
        dialog.minsize(620, 400)
        dialog.transient(self)

        shell = ttk.Frame(dialog, padding=16)
        shell.pack(fill=tk.BOTH, expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(1, weight=1)
        ttk.Label(shell, text=finding.finding, style="Title.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 12)
        )
        text_frame = ttk.Frame(shell)
        text_frame.grid(row=1, column=0, sticky="nsew")
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        detail_text = tk.Text(
            text_frame,
            wrap="word",
            state="normal",
            font=("Consolas", 9),
            relief="flat",
            padx=10,
            pady=10,
        )
        detail_text.grid(row=0, column=0, sticky="nsew")
        detail_scroll = ttk.Scrollbar(
            text_frame, orient="vertical", command=detail_text.yview
        )
        detail_scroll.grid(row=0, column=1, sticky="ns")
        detail_text.configure(yscrollcommand=detail_scroll.set)
        detail_text.insert("1.0", self._format_finding_details(finding))
        detail_text.configure(state="disabled")

        buttons = ttk.Frame(shell)
        buttons.grid(row=2, column=0, sticky="e", pady=(12, 0))
        ttk.Button(
            buttons,
            text="Copy Details",
            command=lambda: self._copy_to_clipboard(
                self._format_finding_details(finding), "Finding details"
            ),
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Close", command=dialog.destroy).pack(side=tk.LEFT)
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.focus_set()

    @staticmethod
    def _format_finding_details(finding: Finding) -> str:
        vt = finding.virustotal
        lines = [
            f"Finding: {finding.finding}",
            f"Category: {finding.category}",
            f"Risk: {finding.risk.value}",
            f"Status: {finding.status.value}",
            f"Recommended action: {finding.action}",
            f"Location: {finding.location or 'N/A'}",
            f"Executable: {finding.executable or 'N/A'}",
            f"SHA-256: {finding.sha256 or 'N/A'}",
            f"Detected at: {finding.detected_at}",
            f"Remediation allowed: {'Yes' if finding.remediation_allowed else 'No'}",
        ]
        if finding.remediation_block_reason:
            lines.append(f"Remediation policy: {finding.remediation_block_reason}")
        if vt:
            lines.extend(
                (
                    "",
                    "VirusTotal",
                    f"Detection ratio: {vt.detection_ratio}",
                    f"Reputation: {vt.reputation if vt.reputation is not None else 'N/A'}",
                    f"Last analysis: {vt.last_analysis_date or 'N/A'}",
                    f"Report: {vt.report_url or 'N/A'}",
                    f"Query status: {vt.error or 'No errors'}",
                )
            )
        if finding.details:
            lines.extend(
                (
                    "",
                    "Scanner details",
                    json.dumps(finding.details, indent=2, sort_keys=True, default=str),
                )
            )
        return "\n".join(lines)

    def _copy_finding_value(self, field: str) -> None:
        findings = self._selected_findings()
        if len(findings) != 1:
            return
        finding = findings[0]
        if field == "vt_report_url":
            value = finding.virustotal.report_url if finding.virustotal else ""
        else:
            value = str(getattr(finding, field, ""))
        if value:
            self._copy_to_clipboard(value, field.replace("_", " ").title())

    def _copy_to_clipboard(self, value: str, label: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update_idletasks()
        self._write_log(f"Copied {label.lower()} to the clipboard.")

    def _local_finding_path(self, finding: Finding | None) -> Path | None:
        if not finding or self.last_scan_admin_share_mode:
            return None
        if self.report and self.report.hostname.casefold() not in {
            socket.gethostname().casefold(),
            "localhost",
            ".",
        }:
            return None
        candidates = (
            finding.executable,
            str(finding.remediation_data.get("path") or ""),
            finding.location,
        )
        for candidate in candidates:
            if not candidate:
                continue
            try:
                path = Path(os.path.expandvars(candidate))
                if path.exists():
                    return path
            except (OSError, ValueError):
                continue
        return None

    def _open_containing_folder(self) -> None:
        findings = self._selected_findings()
        path = self._local_finding_path(findings[0]) if len(findings) == 1 else None
        if not path:
            messagebox.showinfo(
                "Open Containing Folder",
                "A local file or folder is not available for this finding.",
            )
            return
        target = path if path.is_dir() else path.parent
        try:
            os.startfile(str(target))
        except OSError as error:
            messagebox.showerror("Open Containing Folder", str(error))

    def _view_in_task_inventory(self) -> None:
        findings = self._selected_findings()
        if len(findings) != 1:
            return
        finding = findings[0]
        task_name = str(finding.remediation_data.get("TaskName") or finding.finding)
        hostname = self.report.hostname if self.report else socket.gethostname()
        self.notebook.select(self.task_inventory_tab)
        self.task_hostname.delete(0, tk.END)
        self.task_hostname.insert(0, hostname)
        self.task_filter.set(task_name)
        self._start_task_query()

    def _open_vt_report(self, _event=None) -> None:
        selection = self.results.selection()
        if not selection:
            return
        vt = self.findings_by_item[selection[0]].virustotal
        if vt and vt.report_url:
            webbrowser.open(vt.report_url)

    def _clear_results(self) -> None:
        for item in self.results.get_children():
            self.results.delete(item)
        self.findings_by_item.clear()
        self.report = None
        self._set_text(self.log, "")
        self._set_text(self.details, "")

    def _write_log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent: MainWindow, settings: AppSettings, on_save):
        super().__init__(parent)
        self.parent = parent
        self.settings = settings
        self.on_save = on_save
        self.title("Settings")
        self.geometry("460x280")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(1, weight=1)
        self.vt_enabled = tk.BooleanVar(value=settings.virustotal_enabled)
        self.depth = tk.IntVar(value=settings.scan_path_depth)
        self.maximum = tk.IntVar(value=settings.max_files_per_location)
        self.quarantine = tk.StringVar(value=settings.quarantine_directory)

        ttk.Checkbutton(frame, text="Enable VirusTotal lookups", variable=self.vt_enabled).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 14)
        )
        ttk.Label(frame, text="Filesystem scan depth").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=1, to=8, textvariable=self.depth, width=8).grid(row=1, column=1, sticky="w")
        ttk.Label(frame, text="Max entries per location").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=100, to=100000, increment=100, textvariable=self.maximum, width=12).grid(row=2, column=1, sticky="w")
        ttk.Label(frame, text="Quarantine directory").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.quarantine).grid(row=3, column=1, sticky="ew")
        ttk.Label(
            frame,
            text="The VirusTotal API key is read from VIRUSTOTAL_API_KEY in .env.",
            style="Subtitle.TLabel",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(16, 10))
        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Save", style="Primary.TButton", command=self._save).pack(side=tk.LEFT)

    def _save(self) -> None:
        try:
            depth = int(self.depth.get())
            maximum = int(self.maximum.get())
            if depth < 1 or maximum < 100:
                raise ValueError
        except (tk.TclError, ValueError):
            messagebox.showerror("Settings", "Enter a valid scan depth and entry limit.", parent=self)
            return
        self.settings.virustotal_enabled = self.vt_enabled.get()
        self.settings.scan_path_depth = depth
        self.settings.max_files_per_location = maximum
        self.settings.quarantine_directory = self.quarantine.get().strip()
        self.on_save()
        self.destroy()
