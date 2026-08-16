"""
SecureAccess Pro - Admin Security Dashboard
===========================================

The specialised security dashboard for administrators (seminar's second GUI).
After an Admin authenticates with password + TOTP, it shows live KPI tiles and
auto-refreshing tabs for Access Logs, Login History and Site Access, plus a
User & Role management panel.

Run:
    python admin_dashboard.py     # backend must be running on :5000
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from api_client import ApiClient, ApiError

# --- Palette (dark security-console) ---------------------------------------
BG = "#0b132b"
PANEL = "#1c2541"
FIELD = "#26314f"
ACCENT = "#3a86ff"
OK = "#2ecc71"
WARN = "#f39c12"
DANGER = "#e74c3c"
TEXT = "#e6edf3"
MUTED = "#9aa7bd"

REFRESH_MS = 2000  # dashboard refresh interval (< 2s per Expected Outcomes)
ROLES = ("Admin", "User", "Viewer")


class AdminDashboard:
    def __init__(self, root):
        self.root = root
        self.api = ApiClient()
        self.root.title("SecureAccess Pro — Security Dashboard")
        self.root.geometry("1180x760")
        self.root.configure(bg=BG)
        self.root.minsize(1040, 700)
        self._refresh_job = None
        self.show_login()

    def clear(self):
        if self._refresh_job:
            self.root.after_cancel(self._refresh_job)
            self._refresh_job = None
        for w in self.root.winfo_children():
            w.destroy()

    # ------------------------------------------------------------------ #
    # Login (Admin only)
    # ------------------------------------------------------------------ #
    def show_login(self):
        self.clear()
        tk.Label(self.root, text="\U0001F6E1  SecureAccess Pro", font=("Segoe UI", 26, "bold"),
                 bg=BG, fg=TEXT).pack(pady=(60, 4))
        tk.Label(self.root, text="Administrator Security Dashboard", font=("Segoe UI", 13),
                 bg=BG, fg=MUTED).pack()

        card = tk.Frame(self.root, bg=PANEL, padx=42, pady=34)
        card.pack(pady=36)
        tk.Label(card, text="Admin sign in", font=("Segoe UI", 15, "bold"),
                 bg=PANEL, fg=TEXT).pack(anchor="w", pady=(0, 16))

        self.e_user = self._field(card, "Username")
        self.e_pass = self._field(card, "Password", show="*")
        self.e_totp = self._field(card, "6-digit code (email OTP or authenticator)")

        tk.Button(card, text="Send OTP", font=("Segoe UI", 10, "bold"),
                  bg=FIELD, fg=TEXT, relief="flat", padx=10, pady=6, cursor="hand2",
                  command=self.do_request_otp).pack(fill="x", pady=(8, 0))
        tk.Button(card, text="Authenticate", font=("Segoe UI", 12, "bold"), bg=ACCENT,
                  fg="white", relief="flat", padx=10, pady=9, cursor="hand2",
                  command=self.do_login).pack(fill="x", pady=(10, 6))
        self.root.bind("<Return>", lambda _e: self.do_login())

        tk.Label(self.root, text="Administrator sign-in  •  click 'Send OTP' for your MFA code",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED).pack(side="bottom", pady=18)

    def do_request_otp(self):
        u, p = self.e_user.get().strip(), self.e_pass.get()
        if not u or not p:
            messagebox.showwarning("Missing info", "Enter your username and password first.")
            return
        try:
            data = self.api.request_otp(u, p)
        except ApiError as exc:
            messagebox.showerror("Could not send code", exc.message)
            return
        if data.get("dev_code"):
            self.e_totp.delete(0, "end")
            self.e_totp.insert(0, data["dev_code"])
        messagebox.showinfo("Login code", data.get("message", "A code has been sent."))

    def _field(self, parent, label, show=None):
        tk.Label(parent, text=label, font=("Segoe UI", 11), bg=PANEL, fg=MUTED,
                 anchor="w").pack(fill="x", pady=(8, 2))
        e = tk.Entry(parent, font=("Segoe UI", 12), width=30, show=show, bg=FIELD,
                     fg=TEXT, insertbackground=TEXT, relief="flat")
        e.pack(fill="x", ipady=6)
        return e

    def do_login(self):
        try:
            data = self.api.login(self.e_user.get().strip(), self.e_pass.get(),
                                  self.e_totp.get().strip())
        except ApiError as exc:
            messagebox.showerror("Authentication failed", exc.message)
            return
        if data["role"] != "Admin":
            messagebox.showerror("Access denied",
                                 "This dashboard is restricted to Administrators.")
            self.api.logout()
            return
        self.show_dashboard()

    # ------------------------------------------------------------------ #
    # Dashboard
    # ------------------------------------------------------------------ #
    def show_dashboard(self):
        self.clear()
        self.root.unbind("<Return>")

        top = tk.Frame(self.root, bg=PANEL, padx=22, pady=14)
        top.pack(fill="x")
        tk.Label(top, text="\U0001F6E1  Security Dashboard", font=("Segoe UI", 17, "bold"),
                 bg=PANEL, fg=TEXT).pack(side="left")
        tk.Button(top, text="Sign out", font=("Segoe UI", 10, "bold"), bg=DANGER, fg="white",
                  relief="flat", padx=12, pady=6, cursor="hand2",
                  command=self.sign_out).pack(side="right")
        self.status_lbl = tk.Label(top, text="live", font=("Segoe UI", 10),
                                    bg=PANEL, fg=OK)
        self.status_lbl.pack(side="right", padx=14)

        # KPI tiles
        self.kpi_frame = tk.Frame(self.root, bg=BG, padx=16, pady=12)
        self.kpi_frame.pack(fill="x")
        self.kpi_labels = {}
        specs = [
            ("total_users", "Total Users", ACCENT),
            ("total_logins", "Login Attempts", ACCENT),
            ("failed_logins", "Failed Logins", WARN),
            ("denied_access", "Access Denied", DANGER),
            ("active_alerts", "Active Alerts", DANGER),
            ("granted_access", "Access Granted", OK),
        ]
        for i, (key, label, color) in enumerate(specs):
            self.kpi_labels[key] = self._kpi_tile(self.kpi_frame, label, color, i)
            self.kpi_frame.columnconfigure(i, weight=1)

        # Export toolbar (audit log export to CSV)
        bar = tk.Frame(self.root, bg=BG, padx=16)
        bar.pack(fill="x")
        tk.Label(bar, text="Export audit CSV:", font=("Segoe UI", 10),
                 bg=BG, fg=MUTED).pack(side="left", pady=6)
        for label, dataset in (("Access Logs", "access-logs"),
                               ("Login History", "login-history"),
                               ("Site Access", "site-access")):
            tk.Button(bar, text=label, font=("Segoe UI", 9, "bold"), bg=PANEL,
                      fg=TEXT, relief="flat", padx=10, pady=4, cursor="hand2",
                      command=lambda d=dataset, l=label: self.export(d, l)
                      ).pack(side="left", padx=4, pady=6)

        # Tabs
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT,
                        padding=(16, 8), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, rowheight=24, font=("Consolas", 10))
        style.configure("Treeview.Heading", background=FIELD, foreground=TEXT,
                        font=("Segoe UI", 10, "bold"))

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        self._build_security_tab(nb)
        self.tree_access = self._table(nb, "Access Logs",
                                       ("Time", "User", "Action", "Resource", "Status", "IP"))
        self.tree_login = self._table(nb, "Login History",
                                      ("Time", "User", "Status", "Reason", "IP"))
        self.tree_site = self._table(nb, "Site Access",
                                     ("Time", "Method", "Path", "IP", "User-Agent"))
        self._build_patients_tab(nb)
        self._build_users_tab(nb)

        self.refresh_patients()
        self.refresh()  # kicks off the auto-refresh loop

    def _build_security_tab(self, notebook):
        frame = tk.Frame(notebook, bg=BG, padx=10, pady=10)
        notebook.add(frame, text="Security Alerts")

        # Audit-integrity badge.
        self.audit_badge = tk.Label(frame, text="Audit integrity: checking…",
                                    font=("Segoe UI", 11, "bold"), bg=PANEL, fg=MUTED,
                                    anchor="w", padx=12, pady=8)
        self.audit_badge.pack(fill="x", pady=(0, 8))

        tk.Label(frame, text="Real-time anomaly detection (brute-force, privilege probing, lockouts)",
                 font=("Segoe UI", 10), bg=BG, fg=MUTED, anchor="w").pack(fill="x", pady=(0, 6))

        cols = ("Severity", "Type", "Subject", "Detail")
        wrap = tk.Frame(frame, bg=BG)
        wrap.pack(fill="both", expand=True)
        self.tree_alerts = ttk.Treeview(wrap, columns=cols, show="headings")
        for c, w in zip(cols, (90, 260, 120, 320)):
            self.tree_alerts.heading(c, text=c)
            self.tree_alerts.column(c, anchor="w", width=w)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=vsb.set)
        self.tree_alerts.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree_alerts.tag_configure("HIGH", foreground=DANGER)
        self.tree_alerts.tag_configure("MEDIUM", foreground=WARN)
        self.no_alerts = tk.Label(frame, text="", font=("Segoe UI", 11),
                                  bg=BG, fg=OK, anchor="w")
        self.no_alerts.pack(fill="x", pady=(6, 0))

    def refresh_security(self):
        # Anomaly alerts
        try:
            data = self.api.alerts()
            alerts = data.get("alerts", [])
            self.tree_alerts.delete(*self.tree_alerts.get_children())
            for a in alerts:
                self.tree_alerts.insert("", "end",
                    values=(a["severity"], a["type"], a["subject"], a["detail"]),
                    tags=(a["severity"],))
            self.no_alerts.configure(
                text="No active threats detected." if not alerts else "")
            if "active_alerts" in self.kpi_labels:
                self.kpi_labels["active_alerts"].configure(text=str(len(alerts)))
        except ApiError:
            pass
        # Audit integrity
        try:
            v = self.api.verify_audit()
            if v.get("intact"):
                self.audit_badge.configure(
                    text=f"Audit integrity: VERIFIED — {v.get('total', 0)} entries, no tampering",
                    fg=OK)
            else:
                self.audit_badge.configure(
                    text=f"Audit integrity: TAMPERING DETECTED at entry #{v.get('broken_at')} — {v.get('reason','')}",
                    fg=DANGER)
        except ApiError:
            pass

    def _kpi_tile(self, parent, label, color, col):
        card = tk.Frame(parent, bg=PANEL, padx=14, pady=14)
        card.grid(row=0, column=col, padx=6, sticky="nsew")
        val = tk.Label(card, text="—", font=("Segoe UI", 26, "bold"), bg=PANEL, fg=color)
        val.pack()
        tk.Label(card, text=label, font=("Segoe UI", 9), bg=PANEL, fg=MUTED).pack()
        return val

    def _table(self, notebook, name, columns):
        frame = tk.Frame(notebook, bg=BG)
        notebook.add(frame, text=name)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for c in columns:
            tree.heading(c, text=c)
            tree.column(c, anchor="w", width=140, stretch=True)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        tree.tag_configure("denied", foreground=DANGER)
        tree.tag_configure("failed", foreground=WARN)
        tree.tag_configure("granted", foreground=OK)
        return tree

    # ------------------------------------------------------------------ #
    # Patients tab (Admin CRUD — create/update/delete)
    # ------------------------------------------------------------------ #
    def _build_patients_tab(self, notebook):
        frame = tk.Frame(notebook, bg=BG, padx=10, pady=10)
        notebook.add(frame, text="Patients (CRUD)")

        bar = tk.Frame(frame, bg=BG)
        bar.pack(fill="x", pady=(0, 8))
        self.patients_count = tk.Label(bar, text="Patient Records", font=("Segoe UI", 11, "bold"),
                                       bg=BG, fg=TEXT)
        self.patients_count.pack(side="left")
        tk.Button(bar, text="Delete", font=("Segoe UI", 10, "bold"), bg=DANGER, fg="white",
                  relief="flat", padx=10, pady=5, cursor="hand2",
                  command=self.delete_patient).pack(side="right", padx=4)
        tk.Button(bar, text="Edit", font=("Segoe UI", 10, "bold"), bg=WARN, fg="white",
                  relief="flat", padx=10, pady=5, cursor="hand2",
                  command=self.edit_patient).pack(side="right", padx=4)
        tk.Button(bar, text="+ Add Patient", font=("Segoe UI", 10, "bold"), bg=OK, fg="white",
                  relief="flat", padx=10, pady=5, cursor="hand2",
                  command=self.add_patient).pack(side="right", padx=4)

        cols = ("PID", "Name", "Age", "Gender", "Diagnosis", "Severity", "Department", "Status")
        wrap = tk.Frame(frame, bg=BG)
        wrap.pack(fill="both", expand=True)
        self.tree_patients = ttk.Treeview(wrap, columns=cols, show="headings")
        widths = (70, 130, 45, 60, 190, 80, 120, 90)
        for c, w in zip(cols, widths):
            self.tree_patients.heading(c, text=c)
            self.tree_patients.column(c, anchor="w", width=w)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_patients.yview)
        self.tree_patients.configure(yscrollcommand=vsb.set)
        self.tree_patients.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree_patients.tag_configure("critical", foreground=DANGER)
        self.tree_patients.tag_configure("serious", foreground=WARN)
        self.tree_patients.bind("<Double-1>", lambda _e: self.edit_patient())

    def refresh_patients(self):
        try:
            data = self.api.open_patients()
        except ApiError:
            return
        rows = data.get("patients", [])
        self._patient_index = {}
        self.tree_patients.delete(*self.tree_patients.get_children())
        for p in rows:
            tag = p["severity"].lower() if p["severity"] in ("Critical", "Serious") else ""
            iid = self.tree_patients.insert(
                "", "end",
                values=(p["patient_id"], p["name"], p["age"], p["gender"],
                        p["diagnosis"], p["severity"], p["department"], p["status"]),
                tags=(tag,) if tag else ())
            self._patient_index[iid] = p
        s = data.get("summary", {})
        self.patients_count.configure(
            text=f"Patient Records — {s.get('total_patients', len(rows))} total   "
                 f"(Critical {s.get('critical', 0)} · Serious {s.get('serious', 0)} · ICU {s.get('in_icu', 0)})")

    def _selected_patient(self):
        sel = self.tree_patients.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a patient in the table first.")
            return None
        return self._patient_index.get(sel[0])

    def add_patient(self):
        self._patient_dialog(None)

    def edit_patient(self):
        p = self._selected_patient()
        if p:
            self._patient_dialog(p)

    def delete_patient(self):
        p = self._selected_patient()
        if not p:
            return
        if not messagebox.askyesno("Confirm delete",
                                   f"Delete patient {p['patient_id']} — {p['name']}?\n"
                                   "This cannot be undone."):
            return
        try:
            self.api.delete_patient(p["patient_id"])
        except ApiError as exc:
            messagebox.showerror("Delete failed", exc.message)
            return
        self.refresh_patients()

    def _patient_dialog(self, patient):
        """Modal form for creating (patient=None) or editing a patient."""
        win = tk.Toplevel(self.root)
        win.title("Add Patient" if patient is None else f"Edit {patient['patient_id']}")
        win.configure(bg=PANEL)
        win.geometry("420x560")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text=("New Patient Record" if patient is None
                            else f"Edit {patient['patient_id']}"),
                 font=("Segoe UI", 14, "bold"), bg=PANEL, fg=TEXT).pack(pady=(16, 10))

        fields = [
            ("name", "Name", "entry"),
            ("age", "Age", "entry"),
            ("gender", "Gender", ("M", "F")),
            ("blood_group", "Blood Group", ("A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-")),
            ("diagnosis", "Diagnosis", "entry"),
            ("severity", "Severity", ("Critical", "Serious", "Moderate", "Stable")),
            ("department", "Department", "entry"),
            ("attending", "Attending Doctor", "entry"),
            ("status", "Status", ("ICU", "Admitted", "Outpatient", "Discharged")),
            ("contact", "Contact", "entry"),
        ]
        vars_ = {}
        body = tk.Frame(win, bg=PANEL, padx=24)
        body.pack(fill="both", expand=True)
        for key, label, kind in fields:
            tk.Label(body, text=label, font=("Segoe UI", 10), bg=PANEL,
                     fg=MUTED, anchor="w").pack(fill="x", pady=(6, 1))
            var = tk.StringVar(value=str(patient[key]) if patient and patient.get(key) is not None else "")
            vars_[key] = var
            if kind == "entry":
                tk.Entry(body, textvariable=var, font=("Segoe UI", 11), bg=FIELD, fg=TEXT,
                         insertbackground=TEXT, relief="flat").pack(fill="x", ipady=4)
            else:
                ttk.Combobox(body, textvariable=var, values=list(kind),
                             state="readonly").pack(fill="x")

        def save():
            payload = {k: v.get().strip() for k, v in vars_.items()}
            payload = {k: v for k, v in payload.items() if v != ""}
            if payload.get("age"):
                try:
                    payload["age"] = int(payload["age"])
                except ValueError:
                    messagebox.showerror("Invalid", "Age must be a number.", parent=win)
                    return
            try:
                if patient is None:
                    self.api.create_patient(payload)
                else:
                    self.api.update_patient(patient["patient_id"], payload)
            except ApiError as exc:
                messagebox.showerror("Save failed", exc.message, parent=win)
                return
            win.destroy()
            self.refresh_patients()

        tk.Button(win, text="Save", font=("Segoe UI", 12, "bold"), bg=ACCENT, fg="white",
                  relief="flat", padx=10, pady=8, cursor="hand2", command=save).pack(
            fill="x", padx=24, pady=(6, 16))

    def _build_users_tab(self, notebook):
        frame = tk.Frame(notebook, bg=BG, padx=10, pady=10)
        notebook.add(frame, text="Users & Roles")
        cols = ("ID", "Username", "Email", "Role", "Locked")
        self.tree_users = ttk.Treeview(frame, columns=cols, show="headings", height=10)
        for c in cols:
            self.tree_users.heading(c, text=c)
            self.tree_users.column(c, anchor="w", width=130)
        self.tree_users.pack(fill="both", expand=True, side="top")

        ctrl = tk.Frame(frame, bg=BG)
        ctrl.pack(fill="x", pady=10)
        tk.Label(ctrl, text="Set role:", font=("Segoe UI", 10), bg=BG, fg=TEXT).pack(side="left")
        self.role_var = tk.StringVar(value="Viewer")
        ttk.Combobox(ctrl, textvariable=self.role_var, values=list(ROLES),
                     width=10, state="readonly").pack(side="left", padx=8)
        tk.Button(ctrl, text="Apply role", font=("Segoe UI", 10, "bold"), bg=ACCENT,
                  fg="white", relief="flat", padx=10, pady=5, cursor="hand2",
                  command=self.apply_role).pack(side="left", padx=4)
        tk.Button(ctrl, text="Unlock account", font=("Segoe UI", 10, "bold"), bg=WARN,
                  fg="white", relief="flat", padx=10, pady=5, cursor="hand2",
                  command=self.unlock_account).pack(side="left", padx=4)

    # ------------------------------------------------------------------ #
    def _selected_user_id(self):
        sel = self.tree_users.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a user in the table first.")
            return None
        return self.tree_users.item(sel[0])["values"][0]

    def apply_role(self):
        uid = self._selected_user_id()
        if uid is None:
            return
        try:
            self.api.set_role(uid, self.role_var.get())
        except ApiError as exc:
            messagebox.showerror("Failed", exc.message)
            return
        self.refresh_users()

    def unlock_account(self):
        uid = self._selected_user_id()
        if uid is None:
            return
        try:
            self.api.unlock(uid)
        except ApiError as exc:
            messagebox.showerror("Failed", exc.message)
            return
        self.refresh_users()

    def export(self, dataset, label):
        try:
            csv_text = self.api.export_csv(dataset)
        except ApiError as exc:
            messagebox.showerror("Export failed", exc.message)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"{dataset}.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title=f"Save {label} export",
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            fh.write(csv_text)
        messagebox.showinfo("Export complete", f"{label} saved to:\n{path}")

    # ------------------------------------------------------------------ #
    # Data refresh
    # ------------------------------------------------------------------ #
    def _fill(self, tree, rows):
        tree.delete(*tree.get_children())
        for values, tag in rows:
            tree.insert("", "end", values=values, tags=(tag,) if tag else ())

    @staticmethod
    def _short_time(iso):
        return (iso or "").replace("T", " ")[:19]

    def refresh(self):
        try:
            m = self.api.metrics()
            for key, lbl in self.kpi_labels.items():
                lbl.configure(text=str(m.get(key, "—")))

            self._fill(self.tree_access, [
                ((self._short_time(r["timestamp"]), r["username"], r["action"],
                  r["resource"], r["status"], r["ip_address"]),
                 self._status_tag(r["status"]))
                for r in self.api.access_logs(80)
            ])
            self._fill(self.tree_login, [
                ((self._short_time(r["login_time"]), r["username"], r["status"],
                  r["failure_reason"] or "", r["ip_address"]),
                 "failed" if r["status"] == "FAILED" else "granted")
                for r in self.api.login_history(80)
            ])
            self._fill(self.tree_site, [
                ((self._short_time(r["access_time"]), r["method"], r["page_accessed"],
                  r["ip_address"], (r["user_agent"] or "")[:40]), None)
                for r in self.api.site_access(80)
            ])
            self.refresh_users()
            self.refresh_security()
            self.status_lbl.configure(text="live", fg=OK)
        except ApiError as exc:
            self.status_lbl.configure(text=f"{exc.message[:40]}", fg=DANGER)

        self._refresh_job = self.root.after(REFRESH_MS, self.refresh)

    def refresh_users(self):
        try:
            users = self.api.users()
        except ApiError:
            return
        self._fill(self.tree_users, [
            ((u["id"], u["username"], u["email"] or "", u["role"],
              "YES" if u["locked"] else "no"),
             "denied" if u["locked"] else None)
            for u in users
        ])

    @staticmethod
    def _status_tag(status):
        if status in ("DENIED", "FAILED", "LOCKED"):
            return "denied"
        if status in ("GRANTED", "SUCCESS"):
            return "granted"
        return None

    def sign_out(self):
        if self._refresh_job:
            self.root.after_cancel(self._refresh_job)
            self._refresh_job = None
        self.api.logout()
        self.show_login()


def main():
    root = tk.Tk()
    AdminDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
