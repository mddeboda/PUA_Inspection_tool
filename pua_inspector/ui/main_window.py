from __future__ import annotations

import queue
import socket
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from pua_inspector.config import AppSettings, save_settings
from pua_inspector.engine import ScanEngine
from pua_inspector.exporter import export_report
from pua_inspector.models import Finding, ScanProgress, ScanReport
from pua_inspector.remediation import RemediationService


class MainWindow(tk.Tk):
    def __init__(self, engine: ScanEngine, settings: AppSettings):
        super().__init__()
        self.engine = engine
        self.settings = settings
        self.remediation = RemediationService(settings)
        self.report: ScanReport | None = None
        self.last_scan_admin_share_mode = False
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
        shell = ttk.Frame(self, padding=18)
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
        ttk.Button(controls, text="Remove Selected", command=self._remove_selected).grid(
            row=0, column=3, padx=4
        )
        ttk.Button(controls, text="Export Results", command=self._export).grid(
            row=0, column=4, padx=4
        )
        ttk.Button(controls, text="Settings", command=self._open_settings).grid(
            row=0, column=5, padx=(4, 0)
        )

        modules_frame = ttk.LabelFrame(shell, text="Scan modules", padding=10)
        modules_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 12))
        enabled = set(self.settings.enabled_modules or self.engine.module_names)
        for row, module_name in enumerate(self.engine.module_names):
            variable = tk.BooleanVar(value=module_name in enabled)
            self.module_variables[module_name] = variable
            ttk.Checkbutton(modules_frame, text=module_name, variable=variable).grid(
                row=row, column=0, sticky="w", pady=2
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
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

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
            messagebox.showinfo("Remove Selected", "Select one or more findings first.")
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
        if not messagebox.askyesno(
            "Confirm remediation",
            "Remediate the selected findings? Files are moved to quarantine; some findings require manual action.",
        ):
            return
        for item in selected:
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
        filename = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("JSON files", "*.json")),
        )
        if not filename:
            return
        try:
            export_report(self.report, Path(filename))
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
        ]
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
