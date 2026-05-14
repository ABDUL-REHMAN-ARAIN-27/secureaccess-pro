import tkinter as tk
from tkinter import messagebox, ttk
import requests
import datetime

# Backend API URL
API_URL = "http://127.0.0.1:5000"

class SecureAccessProGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureAccess Pro - Zero Trust Network Access")
        self.root.geometry("1000x700")
        self.root.configure(bg="#2c3e50")
        
        self.current_user = None
        self.current_role = None
        self.token = None
        
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
        
        # 2FA Code
        tk.Label(login_frame, text="2FA Code:", font=("Arial", 12), 
                bg="#34495e", fg="white").grid(row=2, column=0, pady=10, sticky="e")
        self.tfa_entry = tk.Entry(login_frame, font=("Arial", 12), width=20)
        self.tfa_entry.grid(row=2, column=1, pady=10, padx=10)
        tk.Label(login_frame, text="(Use: 123456)", font=("Arial", 9), 
                bg="#34495e", fg="#bdc3c7").grid(row=2, column=2, padx=5)
        
        # Buttons Frame
        button_frame = tk.Frame(login_frame, bg="#34495e")
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)
        
        # Login Button
        login_btn = tk.Button(button_frame, text="LOGIN", font=("Arial", 12, "bold"),
                             bg="#27ae60", fg="white", padx=20, pady=5,
                             command=self.authenticate)
        login_btn.pack(side="left", padx=10)
        
        # Sign Up Button
        signup_btn = tk.Button(button_frame, text="CREATE ACCOUNT", font=("Arial", 12, "bold"),
                              bg="#3498db", fg="white", padx=20, pady=5,
                              command=self.show_signup_screen)
        signup_btn.pack(side="left", padx=10)
        
        # Demo credentials
        demo_text = tk.Label(self.root, text="Demo Credentials: admin/admin123 / user/user123 / viewer/viewer123",
                            font=("Arial", 10), bg="#2c3e50", fg="#f1c40f")
        demo_text.pack(pady=10)
    
    def show_signup_screen(self):
        self.clear_screen()
        
        # Title
        title = tk.Label(self.root, text="📝 Create New Account", 
                         font=("Arial", 24, "bold"), 
                         bg="#2c3e50", fg="white")
        title.pack(pady=20)
        
        subtitle = tk.Label(self.root, text="Join SecureAccess Pro - Zero Trust Network Access", 
                           font=("Arial", 12), 
                           bg="#2c3e50", fg="#ecf0f1")
        subtitle.pack(pady=10)
        
        # Sign Up Frame
        signup_frame = tk.Frame(self.root, bg="#34495e", padx=40, pady=30)
        signup_frame.pack(pady=20)
        
        # Username
        tk.Label(signup_frame, text="Username:", font=("Arial", 11), 
                bg="#34495e", fg="white").grid(row=0, column=0, pady=8, sticky="e")
        self.signup_username = tk.Entry(signup_frame, font=("Arial", 11), width=25)
        self.signup_username.grid(row=0, column=1, pady=8, padx=10)
        
        # Email
        tk.Label(signup_frame, text="Email:", font=("Arial", 11), 
                bg="#34495e", fg="white").grid(row=1, column=0, pady=8, sticky="e")
        self.signup_email = tk.Entry(signup_frame, font=("Arial", 11), width=25)
        self.signup_email.grid(row=1, column=1, pady=8, padx=10)
        
        # Password
        tk.Label(signup_frame, text="Password:", font=("Arial", 11), 
                bg="#34495e", fg="white").grid(row=2, column=0, pady=8, sticky="e")
        self.signup_password = tk.Entry(signup_frame, font=("Arial", 11), width=25, show="*")
        self.signup_password.grid(row=2, column=1, pady=8, padx=10)
        
        # Confirm Password
        tk.Label(signup_frame, text="Confirm Password:", font=("Arial", 11), 
                bg="#34495e", fg="white").grid(row=3, column=0, pady=8, sticky="e")
        self.signup_confirm = tk.Entry(signup_frame, font=("Arial", 11), width=25, show="*")
        self.signup_confirm.grid(row=3, column=1, pady=8, padx=10)
        
        # Password hint
        tk.Label(signup_frame, text="(Password must be at least 6 characters)", 
                font=("Arial", 8), bg="#34495e", fg="#f1c40f").grid(row=4, column=1, sticky="w", padx=10)
        
        # Buttons Frame
        btn_frame = tk.Frame(signup_frame, bg="#34495e")
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        # Register Button
        register_btn = tk.Button(btn_frame, text="REGISTER", font=("Arial", 11, "bold"),
                                bg="#27ae60", fg="white", padx=20, pady=5,
                                command=self.register_user)
        register_btn.pack(side="left", padx=10)
        
        # Back to Login Button
        back_btn = tk.Button(btn_frame, text="BACK TO LOGIN", font=("Arial", 11, "bold"),
                            bg="#e74c3c", fg="white", padx=20, pady=5,
                            command=self.show_login_screen)
        back_btn.pack(side="left", padx=10)
        
        # Status label
        self.signup_status = tk.Label(self.root, text="", font=("Arial", 10), 
                                      bg="#2c3e50", fg="#f1c40f")
        self.signup_status.pack(pady=10)
    
    def register_user(self):
        username = self.signup_username.get().strip()
        email = self.signup_email.get().strip()
        password = self.signup_password.get()
        confirm = self.signup_confirm.get()
        
        # Validation
        if not username or not email or not password or not confirm:
            messagebox.showerror("Error", "All fields are required")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return
        
        if '@' not in email or '.' not in email:
            messagebox.showerror("Error", "Please enter a valid email address")
            return
        
        self.signup_status.config(text="Creating account...")
        self.root.update()
        
        try:
            response = requests.post(
                f"{API_URL}/api/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password,
                    "confirm_password": confirm
                },
                timeout=10
            )
            
            if response.status_code == 201:
                messagebox.showinfo("Success", 
                                   f"Account created successfully!\n\n"
                                   f"Username: {username}\n"
                                   f"Role: Viewer\n\n"
                                   f"You can now login with your new account.")
                self.show_login_screen()
            else:
                error = response.json().get('error', 'Registration failed')
                messagebox.showerror("Registration Failed", error)
                self.signup_status.config(text="")
                
        except requests.exceptions.ConnectionError:
            messagebox.showerror("Error", "Cannot connect to server. Make sure Flask is running.")
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {str(e)}")
        
        self.signup_status.config(text="")
    
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        tfa_code = self.tfa_entry.get()
        
        if not username or not password or not tfa_code:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            response = requests.post(
                f"{API_URL}/api/login",
                json={"username": username, "password": password, "tfa_code": tfa_code},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data['token']
                self.current_user = data['username']
                self.current_role = data['role']
                
                messagebox.showinfo("Success", f"Welcome {username}! (Role: {self.current_role})")
                self.show_dashboard()
            else:
                error = response.json().get('error', 'Login failed')
                messagebox.showerror("Access Denied", error)
                
        except requests.exceptions.ConnectionError:
            messagebox.showerror("Error", "Cannot connect to server. Make sure Flask is running on http://127.0.0.1:5000")
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {str(e)}")
    
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
        
        # Main content area
        main_frame = tk.Frame(self.root, bg="#ecf0f1")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True)
        
        # Applications tab
        apps_frame = tk.Frame(notebook, bg="#ecf0f1")
        notebook.add(apps_frame, text="Applications")
        
        tk.Label(apps_frame, text="Protected Applications", font=("Arial", 16, "bold"),
                bg="#ecf0f1", fg="#2c3e50").pack(pady=10)
        
        apps_container = tk.Frame(apps_frame, bg="#ecf0f1")
        apps_container.pack(pady=20)
        
        # HR Portal
        hr_frame = tk.Frame(apps_container, bg="white", relief="raised", bd=2, padx=20, pady=20)
        hr_frame.pack(side="left", padx=10)
        tk.Label(hr_frame, text="👥 HR Portal", font=("Arial", 14, "bold"), 
                bg="white", fg="#2c3e50").pack()
        tk.Label(hr_frame, text="Employee records\nPayroll data", 
                font=("Arial", 10), bg="white", fg="#7f8c8d").pack(pady=5)
        tk.Button(hr_frame, text="Access", bg="#27ae60", fg="white",
                 command=lambda: self.access_app("hr")).pack(pady=5)
        
        # Finance Dashboard
        finance_frame = tk.Frame(apps_container, bg="white", relief="raised", bd=2, padx=20, pady=20)
        finance_frame.pack(side="left", padx=10)
        tk.Label(finance_frame, text="💰 Finance", font=("Arial", 14, "bold"), 
                bg="white", fg="#2c3e50").pack()
        tk.Label(finance_frame, text="Financial reports\nBudget data", 
                font=("Arial", 10), bg="white", fg="#7f8c8d").pack(pady=5)
        tk.Button(finance_frame, text="Access", bg="#27ae60", fg="white",
                 command=lambda: self.access_app("finance")).pack(pady=5)
        
        # Document Manager
        docs_frame = tk.Frame(apps_container, bg="white", relief="raised", bd=2, padx=20, pady=20)
        docs_frame.pack(side="left", padx=10)
        tk.Label(docs_frame, text="📁 Documents", font=("Arial", 14, "bold"), 
                bg="white", fg="#2c3e50").pack()
        tk.Label(docs_frame, text="Company files\nShared documents", 
                font=("Arial", 10), bg="white", fg="#7f8c8d").pack(pady=5)
        tk.Button(docs_frame, text="Access", bg="#27ae60", fg="white",
                 command=lambda: self.access_app("documents")).pack(pady=5)
        
        # Access Logs Tab
        monitor_frame = tk.Frame(notebook, bg="#ecf0f1")
        notebook.add(monitor_frame, text="Access Logs")
        
        tk.Label(monitor_frame, text="Real-Time Access Logs", font=("Arial", 16, "bold"),
                bg="#ecf0f1", fg="#2c3e50").pack(pady=10)
        
        self.logs_text = tk.Text(monitor_frame, height=15, width=100, font=("Courier", 10))
        self.logs_text.pack(pady=10, padx=10, fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(self.logs_text)
        scrollbar.pack(side="right", fill="y")
        self.logs_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.logs_text.yview)
        
        button_frame = tk.Frame(monitor_frame, bg="#ecf0f1")
        button_frame.pack(pady=5)
        
        refresh_btn = tk.Button(button_frame, text="🔄 Refresh Logs", bg="#3498db", fg="white",
                               command=self.refresh_logs, font=("Arial", 10, "bold"), padx=10)
        refresh_btn.pack(side="left", padx=5)
        
        # Admin Only Tabs
        if self.current_role == 'Administrator':
            # Login History Tab
            login_history_frame = tk.Frame(notebook, bg="#ecf0f1")
            notebook.add(login_history_frame, text="Login History")
            
            tk.Label(login_history_frame, text="Login History Log Sheet", font=("Arial", 16, "bold"),
                    bg="#ecf0f1", fg="#2c3e50").pack(pady=10)
            
            self.login_history_text = tk.Text(login_history_frame, height=15, width=100, font=("Courier", 10))
            self.login_history_text.pack(pady=10, padx=10, fill="both", expand=True)
            
            login_scrollbar = tk.Scrollbar(self.login_history_text)
            login_scrollbar.pack(side="right", fill="y")
            self.login_history_text.config(yscrollcommand=login_scrollbar.set)
            login_scrollbar.config(command=self.login_history_text.yview)
            
            refresh_login_btn = tk.Button(login_history_frame, text="🔄 Refresh Login History", bg="#9b59b6", fg="white",
                                         command=self.refresh_login_history, font=("Arial", 10, "bold"), padx=10)
            refresh_login_btn.pack(pady=5)
            
            # Site Access Tab
            site_access_frame = tk.Frame(notebook, bg="#ecf0f1")
            notebook.add(site_access_frame, text="Site Access Log")
            
            tk.Label(site_access_frame, text="Site Access Log Sheet - Who Opened the Website", font=("Arial", 16, "bold"),
                    bg="#ecf0f1", fg="#2c3e50").pack(pady=10)
            
            self.site_access_text = tk.Text(site_access_frame, height=15, width=100, font=("Courier", 10))
            self.site_access_text.pack(pady=10, padx=10, fill="both", expand=True)
            
            site_scrollbar = tk.Scrollbar(self.site_access_text)
            site_scrollbar.pack(side="right", fill="y")
            self.site_access_text.config(yscrollcommand=site_scrollbar.set)
            site_scrollbar.config(command=self.site_access_text.yview)
            
            refresh_site_btn = tk.Button(site_access_frame, text="🔄 Refresh Site Access Log", bg="#e67e22", fg="white",
                                         command=self.refresh_site_access, font=("Arial", 10, "bold"), padx=10)
            refresh_site_btn.pack(pady=5)
        
        # Logout button
        logout_btn = tk.Button(main_frame, text="Logout", bg="#e74c3c", fg="white",
                              command=self.show_login_screen, font=("Arial", 10, "bold"))
        logout_btn.pack(pady=20)
        
        # Load initial data
        self.refresh_logs()
        if self.current_role == 'Administrator':
            self.refresh_login_history()
            self.refresh_site_access()
    
    def access_app(self, app_name):
        if not self.token:
            messagebox.showerror("Error", "Not authenticated")
            return
        
        endpoints = {
            "hr": "/api/protected/hr",
            "finance": "/api/protected/finance",
            "documents": "/api/protected/documents"
        }
        
        app_titles = {
            "hr": "HR Portal",
            "finance": "Finance Dashboard",
            "documents": "Document Manager"
        }
        
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{API_URL}{endpoints[app_name]}", headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                messagebox.showinfo("Access Granted", 
                                   f"{data['message']}\n\nData: {data.get('data', {})}")
                self.refresh_logs()
            elif response.status_code == 403:
                messagebox.showerror("Access Denied", "You don't have permission to access this application")
            else:
                messagebox.showerror("Error", f"Failed to access: {response.status_code}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {str(e)}")
    
    def refresh_logs(self):
        if not self.token:
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{API_URL}/api/logs", headers=headers, timeout=5)
            
            if response.status_code == 200:
                logs = response.json()
                self.logs_text.delete(1.0, tk.END)
                
                if not logs:
                    self.logs_text.insert(tk.END, "No access logs found.")
                    return
                
                self.logs_text.insert(tk.END, "="*90 + "\n")
                self.logs_text.insert(tk.END, "ACCESS LOGS\n")
                self.logs_text.insert(tk.END, "="*90 + "\n\n")
                self.logs_text.insert(tk.END, f"{'Time':<20} {'User':<12} {'Action':<10} {'Resource':<20} {'Status':<10}\n")
                self.logs_text.insert(tk.END, "-"*90 + "\n")
                
                for log in logs:
                    timestamp = log.get('timestamp', '')[:19] if log.get('timestamp') else ''
                    username = log.get('username', '')[:12]
                    action = log.get('action', '')[:10]
                    resource = log.get('resource', '')[:20]
                    status = log.get('status', '')[:10]
                    
                    line = f"{timestamp:<20} {username:<12} {action:<10} {resource:<20} {status:<10}\n"
                    self.logs_text.insert(tk.END, line)
                
                self.logs_text.insert(tk.END, "\n" + "="*90 + "\n")
                
        except Exception as e:
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, f"Error: {str(e)}")
    
    def refresh_login_history(self):
        if not self.token:
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{API_URL}/api/login-history", headers=headers, timeout=5)
            
            if response.status_code == 200:
                history = response.json()
                self.login_history_text.delete(1.0, tk.END)
                
                if not history:
                    self.login_history_text.insert(tk.END, "No login history found.")
                    return
                
                self.login_history_text.insert(tk.END, "="*100 + "\n")
                self.login_history_text.insert(tk.END, "LOGIN HISTORY LOG SHEET\n")
                self.login_history_text.insert(tk.END, "="*100 + "\n\n")
                self.login_history_text.insert(tk.END, f"{'Time':<22} {'Username':<12} {'IP Address':<16} {'Status':<10} {'Failure Reason':<30}\n")
                self.login_history_text.insert(tk.END, "-"*100 + "\n")
                
                for entry in history:
                    login_time = entry.get('login_time', '')[:19] if entry.get('login_time') else ''
                    username = entry.get('username', '')[:12]
                    ip = entry.get('ip_address', '')[:16]
                    status = entry.get('status', '')[:10]
                    reason = entry.get('failure_reason', '')[:30] or '-'
                    
                    line = f"{login_time:<22} {username:<12} {ip:<16} {status:<10} {reason:<30}\n"
                    
                    if status == "SUCCESS":
                        self.login_history_text.insert(tk.END, line, "success")
                    else:
                        self.login_history_text.insert(tk.END, line, "failed")
                
                self.login_history_text.insert(tk.END, "\n" + "="*100 + "\n")
                self.login_history_text.tag_configure("success", foreground="green")
                self.login_history_text.tag_configure("failed", foreground="red")
                
        except Exception as e:
            self.login_history_text.delete(1.0, tk.END)
            self.login_history_text.insert(tk.END, f"Error: {str(e)}")
    
    def refresh_site_access(self):
        if not self.token:
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{API_URL}/api/site-access", headers=headers, timeout=5)
            
            if response.status_code == 200:
                logs = response.json()
                self.site_access_text.delete(1.0, tk.END)
                
                if not logs:
                    self.site_access_text.insert(tk.END, "No site access records found.")
                    return
                
                self.site_access_text.insert(tk.END, "="*100 + "\n")
                self.site_access_text.insert(tk.END, "SITE ACCESS LOG SHEET - Who Opened the Website\n")
                self.site_access_text.insert(tk.END, "="*100 + "\n\n")
                self.site_access_text.insert(tk.END, f"{'Time':<22} {'IP Address':<16} {'Page Accessed':<30} {'Status':<10}\n")
                self.site_access_text.insert(tk.END, "-"*100 + "\n")
                
                for log in logs:
                    access_time = log.get('access_time', '')[:19] if log.get('access_time') else ''
                    ip = log.get('ip_address', '')[:16]
                    page = log.get('page_accessed', '')[:30]
                    status = log.get('status', '')[:10]
                    
                    line = f"{access_time:<22} {ip:<16} {page:<30} {status:<10}\n"
                    self.site_access_text.insert(tk.END, line)
                
                self.site_access_text.insert(tk.END, "\n" + "="*100 + "\n")
                self.site_access_text.insert(tk.END, f"Total Site Visits: {len(logs)}\n")
                
            elif response.status_code == 403:
                self.site_access_text.delete(1.0, tk.END)
                self.site_access_text.insert(tk.END, "Access Denied: Only Administrators can view site access logs.")
                
        except Exception as e:
            self.site_access_text.delete(1.0, tk.END)
            self.site_access_text.insert(tk.END, f"Error: {str(e)}")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureAccessProGUI(root)
    root.mainloop()