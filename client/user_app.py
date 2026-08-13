"""
SecureAccess Pro - End-User Application
=======================================

The user-facing GUI described in the seminar: a friendly desktop app where
users authenticate with password + TOTP (MFA) and then reach the protected
applications their role permits. Access decisions are enforced server-side;
this client simply reflects GRANTED / DENIED responses.

Run:
    python user_app.py           # backend must be running on :5000
"""

import tkinter as tk
from tkinter import messagebox, ttk

from api_client import ApiClient, ApiError

# --- Palette (Teal Trust) ---------------------------------------------------
BG = "#0f2027"
CARD = "#16323a"
FIELD = "#1f3f49"
TEAL = "#028090"
MINT = "#02c39a"
DANGER = "#e63946"
TEXT = "#eaf4f4"
MUTED = "#9db4b8"


class UserApp:
    def __init__(self, root):
        self.root = root
        self.api = ApiClient()
        self.root.title("SecureAccess Pro")
        self.root.geometry("1000x820")
        self.root.configure(bg=BG)
        self.root.minsize(900, 720)
        self.show_login()

    # ------------------------------------------------------------------ #
    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def header(self, parent, subtitle):
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill="x", pady=(28, 6))
        tk.Label(bar, text="\U0001F510  SecureAccess Pro", font=("Segoe UI", 26, "bold"),
                 bg=BG, fg=TEXT).pack()
        tk.Label(bar, text=subtitle, font=("Segoe UI", 12), bg=BG, fg=MUTED).pack(pady=(2, 0))

    # ------------------------------------------------------------------ #
    # Login / Register
    # ------------------------------------------------------------------ #
    def show_login(self):
        self.clear()
        self.header(self.root, "Zero Trust Network Access  •  Multi-Factor Authentication")

        card = tk.Frame(self.root, bg=CARD, padx=40, pady=34)
        card.pack(pady=30)

        tk.Label(card, text="Sign in to your account", font=("Segoe UI", 15, "bold"),
                 bg=CARD, fg=TEXT).grid(row=0, column=0, columnspan=2, pady=(0, 22))

        self.e_user = self._field(card, "Username", 1)
        self.e_pass = self._field(card, "Password", 2, show="*")
        self.e_totp = self._field(card, "6-digit code (email OTP or authenticator)", 3)

        otp_btn = tk.Button(card, text="✉  Email me a code", font=("Segoe UI", 10, "bold"),
                            bg=FIELD, fg=TEXT, activebackground=MINT, relief="flat",
                            padx=10, pady=6, cursor="hand2", command=self.do_request_otp)
        otp_btn.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 0))

        btn = tk.Button(card, text="Verify & Sign In", font=("Segoe UI", 12, "bold"),
                        bg=TEAL, fg="white", activebackground=MINT, activeforeground="white",
                        relief="flat", padx=10, pady=9, cursor="hand2", command=self.do_login)
        btn.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(10, 8))

        link = tk.Label(card, text="New here?  Create an account", font=("Segoe UI", 10, "underline"),
                        bg=CARD, fg=MINT, cursor="hand2")
        link.grid(row=6, column=0, columnspan=2)
        link.bind("<Button-1>", lambda _e: self.show_register())

        self.root.bind("<Return>", lambda _e: self.do_login())

        tk.Label(self.root,
                 text="Accounts:  Abdul Rehman / AbdulRehman2711   •   user / User@123   •   viewer / Viewer@123\n"
                      "Login code: click 'Email me a code' (emailed), or use  python backend/show_code.py <username>",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED, justify="center").pack(side="bottom", pady=16)

    def show_register(self):
        self.clear()
        self.header(self.root, "Create a new account  •  default role: Viewer")

        card = tk.Frame(self.root, bg=CARD, padx=40, pady=30)
        card.pack(pady=24)
        tk.Label(card, text="Register", font=("Segoe UI", 15, "bold"),
                 bg=CARD, fg=TEXT).grid(row=0, column=0, columnspan=2, pady=(0, 18))

        self.r_user = self._field(card, "Username", 1)
        self.r_email = self._field(card, "Email", 2)
        self.r_pass = self._field(card, "Password", 3, show="*")
        self.r_conf = self._field(card, "Confirm password", 4, show="*")

        tk.Button(card, text="Create account", font=("Segoe UI", 12, "bold"),
                  bg=TEAL, fg="white", activebackground=MINT, relief="flat",
                  padx=10, pady=9, cursor="hand2", command=self.do_register
                  ).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(20, 8))

        back = tk.Label(card, text="← Back to sign in", font=("Segoe UI", 10, "underline"),
                        bg=CARD, fg=MINT, cursor="hand2")
        back.grid(row=6, column=0, columnspan=2)
        back.bind("<Button-1>", lambda _e: self.show_login())

    def _field(self, parent, label, row, show=None):
        # Each field is its own container gridded on a single row, so the label
        # sits above the entry instead of being overlapped by it.
        holder = tk.Frame(parent, bg=parent["bg"])
        holder.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(6, 2))
        tk.Label(holder, text=label, font=("Segoe UI", 11), bg=parent["bg"],
                 fg=MUTED, anchor="w").pack(fill="x", pady=(0, 2))
        entry = tk.Entry(holder, font=("Segoe UI", 12), width=30, show=show,
                         bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat")
        entry.pack(fill="x", ipady=6)
        return entry

    # ------------------------------------------------------------------ #
    def do_request_otp(self):
        u = self.e_user.get().strip()
        p = self.e_pass.get()
        if not u or not p:
            messagebox.showwarning("Missing info", "Enter your username and password first.")
            return
        try:
            data = self.api.request_otp(u, p)
        except ApiError as exc:
            messagebox.showerror("Could not send code", exc.message)
            return
        msg = data.get("message", "A code has been sent.")
        if data.get("dev_code"):
            # Dev mode (no SMTP configured) — prefill the code for convenience.
            self.e_totp.delete(0, "end")
            self.e_totp.insert(0, data["dev_code"])
        messagebox.showinfo("Login code", msg)

    def do_login(self):
        u = self.e_user.get().strip()
        p = self.e_pass.get()
        t = self.e_totp.get().strip()
        if not u or not p or not t:
            messagebox.showwarning("Missing info", "Enter username, password and the login code.")
            return
        try:
            data = self.api.login(u, p, t)
        except ApiError as exc:
            messagebox.showerror("Authentication failed", exc.message)
            return
        self.show_success(data)

    def do_register(self):
        try:
            data = self.api.register(self.r_user.get().strip(), self.r_email.get().strip(),
                                     self.r_pass.get(), self.r_conf.get())
        except ApiError as exc:
            messagebox.showerror("Registration failed", exc.message)
            return
        messagebox.showinfo(
            "Account created",
            f"{data['message']}\n\nYour TOTP secret (enrol in an authenticator app):\n"
            f"{data['totp_secret']}",
        )
        self.show_login()

    # ------------------------------------------------------------------ #
    # Authenticated views
    # ------------------------------------------------------------------ #
    def show_success(self, data):
        self.clear()
        self.root.unbind("<Return>")
        top = tk.Frame(self.root, bg=TEAL, padx=24, pady=16)
        top.pack(fill="x")
        tk.Label(top, text="✅  Authentication Successful",
                 font=("Segoe UI", 18, "bold"), bg=TEAL, fg="white").pack(side="left")
        tk.Button(top, text="Sign out", font=("Segoe UI", 10, "bold"), bg=CARD, fg=TEXT,
                  relief="flat", padx=12, pady=6, cursor="hand2",
                  command=self.sign_out).pack(side="right")

        info = tk.Frame(self.root, bg=BG, padx=24, pady=14)
        info.pack(fill="x")
        tk.Label(info, text=f"Signed in as  {data['username']}", font=("Segoe UI", 13, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(info, text=f"Role: {data['role']}   •   Session (JWT) expires in "
                            f"{data.get('expires_in_minutes', 15)} minutes",
                 font=("Segoe UI", 10), bg=BG, fg=MUTED).pack(anchor="w")

        tk.Label(self.root, text="Protected Applications", font=("Segoe UI", 15, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=24, pady=(10, 4))

        grid = tk.Frame(self.root, bg=BG, padx=18)
        grid.pack(fill="both", expand=True)

        # Each app carries the roles allowed to use it (mirrors the server-side
        # RBAC matrix). Only the applications the signed-in role may access are
        # shown — the rest are simply not rendered.
        role = data["role"]
        apps = [
            ("\U0001F465", "HR Portal", "Employee records & leave management",
             self.open_hr, {"Admin", "User"}),
            ("\U0001F4B0", "Finance Dashboard", "Revenue, expenses & invoices",
             self.open_finance, {"Admin"}),
            ("\U0001F3E5", "Patient Records", "Confidential patient health data",
             self.open_patients, {"Admin", "User"}),
            ("\U0001F4C1", "Document Manager", "Shared documents (read access)",
             self.open_documents, {"Admin", "User", "Viewer"}),
        ]
        visible = [a for a in apps if role in a[4]]
        per_row = 3
        for i, (icon, title, desc, cmd, _roles) in enumerate(visible):
            r, c = divmod(i, per_row)
            self._app_tile(grid, icon, title, desc, cmd).grid(
                row=r, column=c, padx=12, pady=14, sticky="nsew")
        for c in range(min(len(visible), per_row)):
            grid.columnconfigure(c, weight=1)

        self.result = tk.Text(self.root, height=8, bg=CARD, fg=TEXT, relief="flat",
                              font=("Consolas", 10), padx=14, pady=12, wrap="word")
        self.result.pack(fill="both", expand=False, padx=24, pady=(4, 20))
        self.result.insert(
            "1.0",
            f"You have access to {len(visible)} application(s) for the '{role}' role. "
            "Click one to open it — the server re-verifies your permission on every "
            "request (Zero Trust).\n",
        )
        self.result.configure(state="disabled")

    def _app_tile(self, parent, icon, title, desc, cmd):
        card = tk.Frame(parent, bg=CARD, padx=18, pady=20)
        tk.Label(card, text=icon, font=("Segoe UI", 34), bg=CARD, fg=MINT).pack()
        tk.Label(card, text=title, font=("Segoe UI", 13, "bold"), bg=CARD, fg=TEXT).pack(pady=(8, 2))
        tk.Label(card, text=desc, font=("Segoe UI", 9), bg=CARD, fg=MUTED,
                 wraplength=200, justify="center").pack()
        tk.Button(card, text="Open", font=("Segoe UI", 11, "bold"), bg=TEAL, fg="white",
                  activebackground=MINT, relief="flat", padx=10, pady=6, cursor="hand2",
                  command=cmd).pack(pady=(14, 0), fill="x")
        return card

    # ------------------------------------------------------------------ #
    def _show_result(self, title, ok, body):
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        badge = "✅ ACCESS GRANTED" if ok else "⛔ ACCESS DENIED"
        self.result.insert("1.0", f"{badge}  —  {title}\n\n{body}\n")
        self.result.configure(state="disabled")

    @staticmethod
    def _render(value, indent=0):
        """Pretty-print the confidential data payload (nested dicts/lists)."""
        pad = "  " * indent
        lines = []
        if isinstance(value, dict):
            for k, v in value.items():
                if str(k).startswith("_"):
                    continue
                label = str(k).replace("_", " ").title()
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{label}:")
                    lines.append(UserApp._render(v, indent + 1))
                else:
                    lines.append(f"{pad}{label}: {v}")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    summary = "  ".join(f"{str(k2).replace('_',' ').title()}={v2}"
                                        for k2, v2 in item.items())
                    lines.append(f"{pad}• {summary}")
                else:
                    lines.append(f"{pad}• {item}")
        else:
            lines.append(f"{pad}{value}")
        return "\n".join(l for l in lines if l)

    def _open(self, title, fn):
        try:
            data = fn()
        except ApiError as exc:
            if exc.status == 403:
                self._show_result(title, False,
                                  "Your role does not permit this application.\n"
                                  "This denial has been logged on the admin dashboard.")
            else:
                self._show_result(title, False, exc.message)
            return
        body = data.get("message", "") + "\n\n" + self._render(data.get("data") or {})
        self._show_result(title, True, body)

    def open_hr(self):
        self._open("HR Portal", self.api.open_hr)

    def open_finance(self):
        self._open("Finance Dashboard", self.api.open_finance)

    def open_patients(self):
        # Patient list has its own response shape (summary + patients); render a
        # read-only overview. Write actions are Admin-only (admin dashboard).
        try:
            data = self.api.open_patients()
        except ApiError as exc:
            msg = ("Your role does not permit this application.\n"
                   "This denial has been logged on the admin dashboard."
                   if exc.status == 403 else exc.message)
            self._show_result("Patient Records", False, msg)
            return
        s = data.get("summary", {})
        patients = data.get("patients", [])
        lines = [
            data.get("classification", ""),
            f"Total: {s.get('total_patients', len(patients))}   "
            f"Critical: {s.get('critical', 0)}   Serious: {s.get('serious', 0)}   "
            f"ICU: {s.get('in_icu', 0)}",
            "",
        ]
        for p in patients[:12]:
            lines.append(f"• {p['patient_id']}  {p['name']}  ({p['age']}/{p['gender']})  "
                         f"{p['diagnosis']}  [{p['severity']}] — {p['department']}")
        if len(patients) > 12:
            lines.append(f"...and {len(patients) - 12} more (read-only for your role)")
        self._show_result("Patient Records", True, "\n".join(lines))

    def open_documents(self):
        self._open("Document Manager", self.api.open_documents)

    def sign_out(self):
        self.api.logout()
        self.show_login()


def main():
    root = tk.Tk()
    UserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
