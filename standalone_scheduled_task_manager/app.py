from __future__ import annotations

import queue
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from task_inventory import (
    ScheduledTaskRecord,
    delete_scheduled_task,
    query_scheduled_tasks,
    query_task_details,
    query_task_summaries,
    set_task_enabled,
)


class ScheduledTaskManager(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Scheduled Task Manager")
        self.geometry("1180x760")
        self.minsize(900, 620)
        self.records: list[ScheduledTaskRecord] = []
        self.records_by_item: dict[str, ScheduledTaskRecord] = {}
        self.detail_cache: dict[tuple[str, str], ScheduledTaskRecord] = {}
        self.detail_loading: set[tuple[str, str]] = set()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.query_generation = 0
        self.query_target = socket.gethostname()
        self.query_remote = False
        self.query_verbose = False
        self.action_in_progress = False
        self.sort_reverse: dict[str, bool] = {}
        self._configure_style()
        self._build_ui()
        self.after(100, self._drain_events)
        self.after_idle(self.refresh_tasks)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 20), foreground="#172033")
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground="#5d6678")
        style.configure("Primary.TButton", font=("Segoe UI Semibold", 10), padding=(14, 8))
        style.configure("TButton", font=("Segoe UI", 10), padding=(10, 7))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))

    def _build_ui(self) -> None:
        shell = ttk.Frame(self, padding=18)
        shell.pack(fill=tk.BOTH, expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(4, weight=1)
        ttk.Label(shell, text="Scheduled Task Manager", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            shell,
            text="Inventory and manage local or remote Windows scheduled tasks using your current identity.",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 14))

        controls = ttk.Frame(shell)
        controls.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(4, weight=1)
        ttk.Label(controls, text="Hostname").grid(row=0, column=0, padx=(0, 8))
        self.hostname = ttk.Entry(controls)
        self.hostname.grid(row=0, column=1, sticky="ew", padx=(0, 12))
        self.hostname.insert(0, socket.gethostname())
        self.refresh_button = ttk.Button(controls, text="Refresh Tasks", style="Primary.TButton", command=self.refresh_tasks)
        self.refresh_button.grid(row=0, column=2, padx=(0, 18))
        ttk.Label(controls, text="Filter").grid(row=0, column=3, padx=(0, 8))
        self.filter_text = tk.StringVar()
        filter_entry = ttk.Entry(controls, textvariable=self.filter_text)
        filter_entry.grid(row=0, column=4, sticky="ew")
        filter_entry.bind("<KeyRelease>", self.apply_filters)

        self.hide_microsoft = tk.BooleanVar(value=True)
        self.show_disabled = tk.BooleanVar(value=False)
        self.hide_empty = tk.BooleanVar(value=True)
        self.verbose_query = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Hide Microsoft Windows tasks", variable=self.hide_microsoft, command=self.apply_filters).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(controls, text="Show disabled tasks", variable=self.show_disabled, command=self.apply_filters).grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(controls, text="Hide empty tasks", variable=self.hide_empty, command=self.apply_filters).grid(row=1, column=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(controls, text="Verbose refresh (slower)", variable=self.verbose_query).grid(row=1, column=4, sticky="w", pady=(8, 0))

        actions = ttk.Frame(shell)
        actions.grid(row=3, column=0, sticky="w", pady=(0, 8))
        self.details_button = ttk.Button(actions, text="Full Details", command=self.show_full_details, state="disabled")
        self.enable_button = ttk.Button(actions, text="Enable", command=lambda: self.confirm_state_change(True), state="disabled")
        self.disable_button = ttk.Button(actions, text="Disable", command=lambda: self.confirm_state_change(False), state="disabled")
        self.delete_button = ttk.Button(actions, text="Delete...", command=self.confirm_delete, state="disabled")
        for button in (self.details_button, self.enable_button, self.disable_button, self.delete_button):
            button.pack(side=tk.LEFT, padx=(0, 6))

        table = ttk.Frame(shell)
        table.grid(row=4, column=0, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        columns = ("Task Name", "Status", "Next Run", "Action")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", selectmode="browse")
        widths = {"Task Name": 400, "Status": 100, "Next Run": 170, "Action": 380}
        for column in columns:
            self.tree.heading(column, text=column, command=lambda c=column: self.sort_inventory(c))
            self.tree.column(column, width=widths[column], minwidth=70)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        scroll_x.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_details)
        self.tree.bind("<Double-Button-1>", lambda _event: self.show_full_details())
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Shift-F10>", self.show_context_menu)

        footer = ttk.Frame(shell)
        footer.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        footer.columnconfigure(1, weight=1)
        self.status = ttk.Label(footer, text="Ready")
        self.status.grid(row=0, column=0, sticky="nw", padx=(0, 12))
        self.details = tk.Text(footer, height=8, wrap="word", state="disabled", font=("Consolas", 9), relief="flat")
        self.details.grid(row=0, column=1, sticky="ew")

    def refresh_tasks(self) -> None:
        target = self.hostname.get().strip() or socket.gethostname()
        local_names = {".", "localhost", socket.gethostname().casefold(), socket.getfqdn().casefold()}
        remote = target.casefold() not in local_names
        self.query_target, self.query_remote = target, remote
        self.query_verbose = self.verbose_query.get()
        self.query_generation += 1
        generation = self.query_generation
        self.records = []
        self.detail_cache.clear()
        self.detail_loading.clear()
        self.refresh_button.configure(state="disabled")
        self.status.configure(text=f"Querying {target}{' remotely' if remote else ''}...")
        self._render([])
        self._set_text("")
        threading.Thread(target=self._query_worker, args=(target, remote, self.query_verbose, generation), daemon=True).start()

    def _query_worker(self, hostname: str, remote: bool, verbose: bool, generation: int) -> None:
        try:
            records = query_scheduled_tasks(hostname, remote=remote, verbose=True) if verbose else query_task_summaries(hostname, remote=remote)
            self.events.put(("inventory", (generation, records)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("inventory_error", (generation, str(error))))

    def apply_filters(self, _event=None) -> None:
        keyword = self.filter_text.get().strip().casefold()
        visible: list[ScheduledTaskRecord] = []
        for record in self.records:
            detail = self.detail_cache.get(record.cache_key, record)
            if self.hide_microsoft.get() and record.is_microsoft_windows_task:
                continue
            if not self.show_disabled.get() and record.is_disabled:
                continue
            if self.hide_empty.get() and detail.is_empty:
                continue
            if keyword and keyword not in detail.searchable_text():
                continue
            visible.append(record)
        self._render(visible)
        self.status.configure(text=f"Showing {len(visible)} of {len(self.records)} task(s)")

    def _render(self, records: list[ScheduledTaskRecord]) -> None:
        self.tree.delete(*self.tree.get_children())
        self.records_by_item.clear()
        for record in records:
            detail = self.detail_cache.get(record.cache_key, record)
            item = self.tree.insert("", "end", values=(record.task_name, record.status, record.next_run_time, detail.action))
            self.records_by_item[item] = record
        self._update_action_buttons()

    def sort_inventory(self, column: str) -> None:
        reverse = self.sort_reverse.get(column, False)
        items = [(str(self.tree.set(item, column)).casefold(), item) for item in self.tree.get_children("")]
        items.sort(reverse=reverse)
        for position, (_value, item) in enumerate(items):
            self.tree.move(item, "", position)
        self.sort_reverse[column] = not reverse

    def selected_record(self) -> ScheduledTaskRecord | None:
        selection = self.tree.selection()
        return self.records_by_item.get(selection[0]) if selection else None

    def show_selected_details(self, _event=None) -> None:
        record = self.selected_record()
        self._update_action_buttons()
        if not record:
            return
        detail = self.detail_cache.get(record.cache_key)
        if detail:
            self._render_details(detail)
            return
        self._render_details(record, loading=True)
        if record.cache_key in self.detail_loading:
            return
        self.detail_loading.add(record.cache_key)
        threading.Thread(target=self._detail_worker, args=(record, self.query_generation), daemon=True).start()

    def _detail_worker(self, record: ScheduledTaskRecord, generation: int) -> None:
        try:
            detail = query_task_details(self.query_target, record.task_name, remote=self.query_remote)
            self.events.put(("detail", (generation, record.cache_key, detail)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("detail_error", (generation, record.cache_key, str(error))))

    def _render_details(self, record: ScheduledTaskRecord, *, loading: bool = False) -> None:
        text = "\n".join((
            f"Task: {record.task_name}", f"Action: {record.action or 'N/A'}",
            f"Start in: {record.start_in or 'N/A'}", f"Run as: {record.run_as_user or 'N/A'}",
            f"Status: {record.status or 'N/A'}", f"Last result: {record.last_result or 'N/A'}",
            f"Comment: {record.comment or 'N/A'}",
        ))
        self._set_text(text + ("\n\nLoading verbose details..." if loading else ""))

    def _update_action_buttons(self) -> None:
        record = self.selected_record()
        available = bool(record and not record.is_microsoft_windows_task and not self.action_in_progress)
        self.details_button.configure(state="normal" if record else "disabled")
        self.enable_button.configure(state="normal" if available and record and record.is_disabled else "disabled")
        self.disable_button.configure(state="normal" if available and record and not record.is_disabled else "disabled")
        self.delete_button.configure(state="normal" if available else "disabled")

    def show_context_menu(self, event) -> str:
        if getattr(event, "num", None) == 3:
            item = self.tree.identify_row(event.y)
            if not item:
                return "break"
            self.tree.selection_set(item)
            self.tree.focus(item)
            x_root, y_root = event.x_root, event.y_root
        else:
            item = self.tree.focus()
            if not item:
                return "break"
            bounds = self.tree.bbox(item)
            if not bounds:
                return "break"
            x_root = self.tree.winfo_rootx() + bounds[0] + 24
            y_root = self.tree.winfo_rooty() + bounds[1] + bounds[3]
        self._update_action_buttons()
        record = self.selected_record()
        protected = bool(record and record.is_microsoft_windows_task)
        available = bool(record and not protected and not self.action_in_progress)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="View Full Task Details...", command=self.show_full_details, state="normal" if record else "disabled")
        menu.add_separator()
        menu.add_command(label="Enable Task", command=lambda: self.confirm_state_change(True), state="normal" if available and record and record.is_disabled else "disabled")
        menu.add_command(label="Disable Task...", command=lambda: self.confirm_state_change(False), state="normal" if available and record and not record.is_disabled else "disabled")
        menu.add_command(label="Delete Scheduled Task...", command=self.confirm_delete, state="normal" if available else "disabled")
        if protected:
            menu.add_separator()
            menu.add_command(label="Protected Microsoft system task", state="disabled")
        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()
        return "break"

    def confirm_state_change(self, enabled: bool) -> None:
        record = self.selected_record()
        if not self._action_allowed(record):
            return
        verb = "Enable" if enabled else "Disable"
        effect = "This allows scheduled execution." if enabled else "This prevents future runs but does not stop a currently running instance."
        if messagebox.askyesno(f"{verb} Scheduled Task", f"{verb} this task on {record.hostname}?\n\n{record.task_name}\n\n{effect}", icon="question" if enabled else "warning"):
            self._start_action("enable" if enabled else "disable", record)

    def confirm_delete(self) -> None:
        record = self.selected_record()
        if not self._action_allowed(record):
            return
        prompt = f"Permanently delete this task from {record.hostname}?\n\n{record.task_name}\n\nThis cannot be undone and does not delete the program or script it runs."
        if messagebox.askyesno("Delete Scheduled Task", prompt, icon="warning"):
            self._start_action("delete", record)

    def _action_allowed(self, record: ScheduledTaskRecord | None) -> bool:
        if not record:
            return False
        if record.is_microsoft_windows_task:
            messagebox.showwarning("Protected System Task", "Tasks under \\Microsoft\\Windows are protected from changes.")
            return False
        if self.action_in_progress:
            messagebox.showinfo("Action in Progress", "Wait for the current task action to finish.")
            return False
        return True

    def _start_action(self, action: str, record: ScheduledTaskRecord) -> None:
        self.action_in_progress = True
        self.refresh_button.configure(state="disabled")
        self._update_action_buttons()
        self.status.configure(text=f"{action.title()} in progress: {record.task_name}")
        threading.Thread(target=self._action_worker, args=(action, record, self.query_generation), daemon=True).start()

    def _action_worker(self, action: str, record: ScheduledTaskRecord, generation: int) -> None:
        try:
            if action == "delete":
                result = delete_scheduled_task(self.query_target, record.task_name, remote=self.query_remote)
            else:
                result = set_task_enabled(self.query_target, record.task_name, enabled=action == "enable", remote=self.query_remote)
            self.events.put(("action_complete", (generation, action, record, result)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("action_error", (generation, action, record, str(error))))

    def show_full_details(self) -> None:
        record = self.selected_record()
        if not record:
            return
        detail = self.detail_cache.get(record.cache_key, record)
        dialog = tk.Toplevel(self)
        dialog.title(f"Scheduled Task Details - {record.task_name}")
        dialog.geometry("760x560")
        dialog.transient(self)
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        ttk.Label(frame, text="Scheduled Task Details", style="Title.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 12))
        text = tk.Text(frame, wrap="word", font=("Segoe UI", 10), relief="flat", padx=12, pady=12)
        text.grid(row=1, column=0, sticky="nsew")
        text.insert("1.0", self.format_full_details(detail))
        text.configure(state="disabled")
        ttk.Button(frame, text="Close", command=dialog.destroy).grid(row=2, column=0, sticky="e", pady=(12, 0))
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.focus_set()

    @staticmethod
    def format_full_details(record: ScheduledTaskRecord) -> str:
        status = record.status or "Unknown"
        status_meaning = {"ready": "Enabled and waiting for its next trigger.", "running": "Currently running.", "disabled": "Disabled; it will not start on schedule."}.get(status.casefold(), "Windows reported the state shown above.")
        result = record.last_result or "Not available"
        result_meaning = {"0": "Most recent run completed successfully.", "0x0": "Most recent run completed successfully.", "267009": "Task is currently running.", "0x41301": "Task is currently running.", "267011": "Task has not run yet.", "0x41303": "Task has not run yet."}.get(result.casefold(), "Result code reported by Windows.")
        return "\n".join((
            "OVERVIEW", f"Task name: {record.task_name}", f"Computer: {record.hostname or 'Not available'}", f"Current state: {status}", f"What that means: {status_meaning}", "",
            "WHAT IT RUNS", f"Program or command: {record.action or 'Not available'}", f"Starting folder: {record.start_in or 'Not specified'}", f"Runs as account: {record.run_as_user or 'Not available'}", f"Created by: {record.author or 'Not available'}", "",
            "TIMING AND HISTORY", f"Next scheduled run: {record.next_run_time or 'Not available'}", f"Most recent run: {record.last_run_time or 'Not available'}", f"Last result: {result}", f"What that means: {result_meaning}", "",
            "DESCRIPTION", record.comment or "No description was provided for this task.",
        ))

    def _drain_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                generation = payload[0]
                if generation != self.query_generation:
                    continue
                if event == "inventory":
                    self.records = payload[1]
                    if self.query_verbose:
                        self.detail_cache = {record.cache_key: record for record in self.records}
                    self.refresh_button.configure(state="normal")
                    self.apply_filters()
                elif event == "inventory_error":
                    self.refresh_button.configure(state="normal")
                    self.status.configure(text="Query failed")
                    messagebox.showerror("Scheduled Task Query", payload[1])
                elif event == "detail":
                    cache_key, record = payload[1], payload[2]
                    self.detail_loading.discard(cache_key)
                    self.detail_cache[cache_key] = record
                    selected = self.selected_record()
                    if selected and selected.cache_key == cache_key:
                        self._render_details(record)
                elif event == "detail_error":
                    cache_key, message = payload[1], payload[2]
                    self.detail_loading.discard(cache_key)
                    selected = self.selected_record()
                    if selected and selected.cache_key == cache_key:
                        self._set_text(f"Task: {selected.task_name}\n\nUnable to load verbose details:\n{message}")
                elif event == "action_complete":
                    action, record = payload[1], payload[2]
                    self.action_in_progress = False
                    past = {"enable": "enabled", "disable": "disabled", "delete": "deleted"}[action]
                    messagebox.showinfo("Scheduled Task Updated", f"The task was {past} successfully.\n\n{record.task_name}")
                    self.refresh_tasks()
                elif event == "action_error":
                    action, record, message = payload[1], payload[2], payload[3]
                    self.action_in_progress = False
                    self.refresh_button.configure(state="normal")
                    self._update_action_buttons()
                    self.status.configure(text=f"Could not {action} task")
                    messagebox.showerror("Scheduled Task Action Failed", f"Could not {action} this task:\n\n{record.task_name}\n\n{message}")
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _set_text(self, value: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")


def main() -> None:
    ScheduledTaskManager().mainloop()


if __name__ == "__main__":
    main()
