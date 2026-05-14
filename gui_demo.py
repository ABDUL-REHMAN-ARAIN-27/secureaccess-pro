import tkinter as tk
from tkinter import messagebox, ttk
import datetime
import random

class SecureAccessProGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureAccess Pro - Zero Trust Network Access")
        self.root.geometry("900x600")
        self.root.configure(bg="#2c3e50")
        
        # Current user (None = not logged in)
        self.current_user = None
        self.current_role = None
        
        # Show login screen first
        self.show_login_screen()
    
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        self.clear_screen()
        
        # Title
        title = tk.Label(self.root, text="🔐 SecureAccess Pro", 
                         font=("Arial", 24, "bold"), 
                         bg="#2c3e50", fg="white")
        title.pack(pady=30)
        
        subtitle = tk.Label(self.root, text="Zero Trust Network Access Control System", 
                           font=("Arial", 12), 
                           bg="#2c3e50", fg="#ecf0f1")
        subtitle.pack(pady=10)
        
        # Login Frame
        login_frame = tk.Frame(self.root, bg="#34495e", padx=50, pady=30)
        login_frame.pack(pady=30)
        
        # Username
        tk.Label(login_frame, text="Username:", font=("Arial", 12), 
                bg="#34495e", fg="white").grid(row=0, column=0, pady=10, sticky="e")
        self.username_entry = tk.Entry(login_frame, font=("Arial", 12), width=20)
        self.username_entry.grid(row=0, column=1, pady=10, padx=10)
        
        # Password
        tk.Label(login_frame, text="Password:", font=("Arial", 12), 
                bg="#34495e", fg="white").grid(row=1, column=0, pady=10, sticky="e")
        self.password_entry = tk.Entry(login_frame, font=("Arial", 12), width=20, show="*")
        self.password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        # 2FA Code (simulated)
        tk.Label(login_frame, text="2FA Code:", font=("Arial", 12), 
                bg="#34495e", fg="white").grid(row=2, column=0, pady=10, sticky="e")
        self.tfa_entry = tk.Entry(login_frame, font=("Arial", 12), width=20)
        self.tfa_entry.grid(row=2, column=1, pady=10, padx=10)
        tk.Label(login_frame, text="(Use: 123456)", font=("Arial", 9), 
                bg="#34495e", fg="#bdc3c7").grid(row=2, column=2, padx=5)
        
        # Login Button
        login_btn = tk.Button(login_frame, text="LOGIN", font=("Arial", 12, "bold"),
                             bg="#27ae60", fg="white", padx=30, pady=5,
                             command=self.authenticate)
        login_btn.grid(row=3, column=0, columnspan=2, pady=20)
        
        # Demo credentials
        demo_text = tk.Label(self.root, text="Demo Credentials: admin/admin123 / user/user123 / viewer/viewer123",
                            font=("Arial", 10), bg="#2c3e50", fg="#f1c40f")
        demo_text.pack(pady=10)
    
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        tfa_code = self.tfa_entry.get()
        
        # Simple authentication (demo only - will be replaced with real DB)
        if tfa_code != "123456":
            messagebox.showerror("Access Denied", "Invalid 2FA Code")
            self.log_event(username, "FAILED", "Invalid 2FA")
            return
        
        # Demo users
        users = {
            "admin": {"password": "admin123", "role": "Administrator"},
            "user": {"password": "user123", "role": "Employee"},
            "viewer": {"password": "viewer123", "role": "Viewer"}
        }
        
        if username in users and users[username]["password"] == password:
            self.current_user = username
            self.current_role = users[username]["role"]
            messagebox.showinfo("Success", f"Welcome {username}! (Role: {self.current_role})")
            self.log_event(username, "SUCCESS", f"Logged in as {self.current_role}")
            self.show_dashboard()
        else:
            messagebox.showerror("Access Denied", "Invalid username or password")
            self.log_event(username, "FAILED", "Invalid credentials")
    
    def log_event(self, user, status, details):
        # Simulate logging to database
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[LOG] {timestamp} | User: {user} | Status: {status} | {details}")
        # In real app, this would insert into PostgreSQL
    
    def show_dashboard(self):
        self.clear_screen()
        
        # Header
        header = tk.Frame(self.root, bg="#2c3e50", height=80)
        header.pack(fill="x")
        
        tk.Label(header, text=f"🔐 SecureAccess Pro - Dashboard", 
                font=("Arial", 18, "bold"), bg="#2c3e50", fg="white").pack(side="left", padx=20, pady=20)
        
        user_info = tk.Label(header, text=f"User: {self.current_user} | Role: {self.current_role}", 
                            font=("Arial", 11), bg="#2c3e50", fg="#3498db")
        user_info.pack(side="right", padx=20, pady=20)
        
        # Main content area with 3 protected apps
        main_frame = tk.Frame(self.root, bg="#ecf0f1")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # App cards
        tk.Label(main_frame, text="Protected Applications", font=("Arial", 16, "bold"),
                bg="#ecf0f1", fg="#2c3e50").pack(pady=10)
        
        apps_frame = tk.Frame(main_frame, bg="#ecf0f1")
        apps_frame.pack(pady=20)
        
        # HR Portal
        hr_frame = tk.Frame(apps_frame, bg="white", relief="raised", bd=2, padx=20, pady=20)
        hr_frame.pack(side="left", padx=10)
        tk.Label(hr_frame, text="👥 HR Portal", font=("Arial", 14, "bold"), 
                bg="white", fg="#2c3e50").pack()
        tk.Label(hr_frame, text="Employee records\nPayroll data", 
                font=("Arial", 10), bg="white", fg="#7f8c8d").pack(pady=5)
        if self.current_role in ["Administrator", "Employee"]:
            tk.Button(hr_frame, text="Access", bg="#27ae60", fg="white", 
                     command=lambda: self.access_app("HR Portal")).pack(pady=5)
        else:
            tk.Label(hr_frame, text="⛔ Access Denied", fg="red", bg="white").pack()
        
        # Finance Dashboard
        finance_frame = tk.Frame(apps_frame, bg="white", relief="raised", bd=2, padx=20, pady=20)
        finance_frame.pack(side="left", padx=10)
        tk.Label(finance_frame, text="💰 Finance", font=("Arial", 14, "bold"), 
                bg="white", fg="#2c3e50").pack()
        tk.Label(finance_frame, text="Financial reports\nBudget data", 
                font=("Arial", 10), bg="white", fg="#7f8c8d").pack(pady=5)
        if self.current_role == "Administrator":
            tk.Button(finance_frame, text="Access", bg="#27ae60", fg="white",
                     command=lambda: self.access_app("Finance Dashboard")).pack(pady=5)
        else:
            tk.Label(finance_frame, text="⛔ Access Denied", fg="red", bg="white").pack()
        
        # Document Manager
        docs_frame = tk.Frame(apps_frame, bg="white", relief="raised", bd=2, padx=20, pady=20)
        docs_frame.pack(side="left", padx=10)
        tk.Label(docs_frame, text="📁 Documents", font=("Arial", 14, "bold"), 
                bg="white", fg="#2c3e50").pack()
        tk.Label(docs_frame, text="Company files\nShared documents", 
                font=("Arial", 10), bg="white", fg="#7f8c8d").pack(pady=5)
        if self.current_role in ["Administrator", "Employee", "Viewer"]:
            tk.Button(docs_frame, text="Access", bg="#27ae60", fg="white",
                     command=lambda: self.access_app("Document Manager")).pack(pady=5)
        else:
            tk.Label(docs_frame, text="⛔ Access Denied", fg="red", bg="white").pack()
        
        # Security Dashboard (Admin only)
        security_frame = tk.Frame(main_frame, bg="white", relief="raised", bd=2, padx=20, pady=20)
        security_frame.pack(pady=20, fill="x")
        
        tk.Label(security_frame, text="📊 Real-Time Security Monitoring", 
                font=("Arial", 14, "bold"), bg="white", fg="#2c3e50").pack()
        
        # Access Logs Table
        log_frame = tk.Frame(security_frame, bg="white")
        log_frame.pack(pady=10, padx=10, fill="x")
        
        # Sample logs
        logs = [
            {"time": "10:32:15", "user": "admin", "resource": "HR Portal", "status": "✅ GRANTED"},
            {"time": "10:31:22", "user": "user", "resource": "Finance", "status": "⛔ DENIED"},
            {"time": "10:30:05", "user": "viewer", "resource": "Documents", "status": "✅ GRANTED"},
            {"time": "10:28:44", "user": "hacker", "resource": "HR Portal", "status": "⛔ BLOCKED"},
        ]
        
        # Log headers
        headers = tk.Frame(log_frame, bg="#34495e")
        headers.pack(fill="x")
        tk.Label(headers, text="Time", width=10, bg="#34495e", fg="white", font=("Arial", 10, "bold")).pack(side="left")
        tk.Label(headers, text="User", width=10, bg="#34495e", fg="white", font=("Arial", 10, "bold")).pack(side="left")
        tk.Label(headers, text="Resource", width=15, bg="#34495e", fg="white", font=("Arial", 10, "bold")).pack(side="left")
        tk.Label(headers, text="Status", width=10, bg="#34495e", fg="white", font=("Arial", 10, "bold")).pack(side="left")
        
        # Log entries
        for log in logs:
            row = tk.Frame(log_frame, bg="white" if logs.index(log) % 2 == 0 else "#f8f9f9")
            row.pack(fill="x", pady=1)
            tk.Label(row, text=log["time"], width=10, bg=row["bg"]).pack(side="left")
            tk.Label(row, text=log["user"], width=10, bg=row["bg"]).pack(side="left")
            tk.Label(row, text=log["resource"], width=15, bg=row["bg"]).pack(side="left")
            tk.Label(row, text=log["status"], width=10, bg=row["bg"]).pack(side="left")
        
        # Logout button
        tk.Button(security_frame, text="Logout", bg="#e74c3c", fg="white",
                 command=self.show_login_screen).pack(pady=10)
    
    def access_app(self, app_name):
        messagebox.showinfo("Access Granted", 
                           f"You accessed: {app_name}\n\nIn a real app, this would open the {app_name} interface.\n\nThis access has been logged for security monitoring.")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureAccessProGUI(root)
    root.mainloop()