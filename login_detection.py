import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import datetime
import socket

# ==========================================
# DATABASE SETUP
# ==========================================

conn = sqlite3.connect("login_security.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    status TEXT,
    ip_address TEXT,
    login_time TEXT
)
""")

conn.commit()

# ==========================================
# SECURITY SETTINGS
# ==========================================

MAX_ATTEMPTS = 3
failed_attempts = {}
locked_accounts = set()


# ==========================================
# PASSWORD HASHING
# ==========================================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ==========================================
# GET IP ADDRESS
# ==========================================

def get_ip():

    try:
        return socket.gethostbyname(socket.gethostname())

    except:
        return "Unknown"


# ==========================================
# RECORD LOGIN ACTIVITY
# ==========================================

def record_activity(username, status):

    ip = get_ip()

    current_time = datetime.datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    cursor.execute("""
    INSERT INTO login_history
    (username, status, ip_address, login_time)
    VALUES (?, ?, ?, ?)
    """, (username, status, ip, current_time))

    conn.commit()


# ==========================================
# CREATE NEW ACCOUNT
# ==========================================

def register():

    username = reg_username.get().strip()
    password = reg_password.get()
    confirm = reg_confirm.get()

    if not username or not password or not confirm:

        messagebox.showwarning(
            "Missing Details",
            "Please fill all the fields."
        )

        return

    if len(username) < 3:

        messagebox.showwarning(
            "Invalid Username",
            "Username must contain at least 3 characters."
        )

        return

    if len(password) < 6:

        messagebox.showwarning(
            "Weak Password",
            "Password must contain at least 6 characters."
        )

        return

    if password != confirm:

        messagebox.showerror(
            "Password Error",
            "Passwords do not match."
        )

        return

    cursor.execute(
        "SELECT username FROM users WHERE username=?",
        (username,)
    )

    if cursor.fetchone():

        messagebox.showerror(
            "Account Exists",
            "This username is already registered."
        )

        return

    cursor.execute(
        "INSERT INTO users VALUES (?, ?)",
        (username, hash_password(password))
    )

    conn.commit()

    messagebox.showinfo(
        "Success",
        "Account created successfully!\nYou can now login."
    )

    register_window.destroy()


# ==========================================
# REGISTRATION WINDOW
# ==========================================

def open_register():

    global reg_username
    global reg_password
    global reg_confirm
    global register_window

    register_window = tk.Toplevel(root)

    register_window.title("Create New Account")
    register_window.geometry("450x480")
    register_window.configure(bg="#101820")

    tk.Label(
        register_window,
        text="CREATE NEW ACCOUNT",
        font=("Arial", 19, "bold"),
        bg="#101820",
        fg="#00FF99"
    ).pack(pady=30)

    tk.Label(
        register_window,
        text="Create Username",
        bg="#101820",
        fg="white"
    ).pack(pady=5)

    reg_username = tk.Entry(
        register_window,
        font=("Arial", 12),
        width=28
    )

    reg_username.pack(ipady=7)

    tk.Label(
        register_window,
        text="Create Password",
        bg="#101820",
        fg="white"
    ).pack(pady=12)

    reg_password = tk.Entry(
        register_window,
        font=("Arial", 12),
        width=28,
        show="*"
    )

    reg_password.pack(ipady=7)

    tk.Label(
        register_window,
        text="Confirm Password",
        bg="#101820",
        fg="white"
    ).pack(pady=12)

    reg_confirm = tk.Entry(
        register_window,
        font=("Arial", 12),
        width=28,
        show="*"
    )

    reg_confirm.pack(ipady=7)

    tk.Button(
        register_window,
        text="CREATE ACCOUNT",
        font=("Arial", 11, "bold"),
        bg="#00CC88",
        fg="#101820",
        width=22,
        command=register
    ).pack(pady=30, ipady=7)


# ==========================================
# LOGIN FUNCTION
# ==========================================

def login(username, password):

    if not username or not password:

        messagebox.showwarning(
            "Input Error",
            "Please enter username and password."
        )

        return

    if username in locked_accounts:

        messagebox.showerror(
            "Account Locked",
            "This account is locked due to suspicious activity."
        )

        return

    cursor.execute(
        "SELECT password FROM users WHERE username=?",
        (username,)
    )

    result = cursor.fetchone()

    if result and result[0] == hash_password(password):

        failed_attempts[username] = 0

        record_activity(username, "SUCCESS")

        messagebox.showinfo(
            "Login Successful",
            f"Welcome {username}!\nLogin successful."
        )

    else:

        failed_attempts[username] = (
            failed_attempts.get(username, 0) + 1
        )

        record_activity(username, "FAILED")

        attempts = failed_attempts[username]

        if attempts >= MAX_ATTEMPTS:

            locked_accounts.add(username)

            messagebox.showerror(
                "SECURITY ALERT",
                "Suspicious Login Activity Detected!\n\n"
                "Three failed attempts detected.\n"
                "Account temporarily locked."
            )

        else:

            remaining = MAX_ATTEMPTS - attempts

            messagebox.showwarning(
                "Login Failed",
                f"Incorrect username or password.\n"
                f"Attempts remaining: {remaining}"
            )


# ==========================================
# LOGIN WINDOW
# ==========================================

def open_login():

    login_window = tk.Toplevel(root)

    login_window.title("User Login")
    login_window.geometry("450x400")
    login_window.configure(bg="#101820")

    tk.Label(
        login_window,
        text="USER LOGIN",
        font=("Arial", 20, "bold"),
        bg="#101820",
        fg="#00FF99"
    ).pack(pady=30)

    tk.Label(
        login_window,
        text="Username",
        bg="#101820",
        fg="white"
    ).pack(pady=5)

    user_entry = tk.Entry(
        login_window,
        font=("Arial", 12),
        width=28
    )

    user_entry.pack(ipady=7)

    tk.Label(
        login_window,
        text="Password",
        bg="#101820",
        fg="white"
    ).pack(pady=15)

    pass_entry = tk.Entry(
        login_window,
        font=("Arial", 12),
        width=28,
        show="*"
    )

    pass_entry.pack(ipady=7)

    def perform_login():

        username = user_entry.get().strip()
        password = pass_entry.get()

        login(username, password)

        pass_entry.delete(0, tk.END)

    tk.Button(
        login_window,
        text="LOGIN",
        font=("Arial", 12, "bold"),
        bg="#00CC88",
        fg="#101820",
        width=22,
        command=perform_login
    ).pack(pady=30, ipady=7)


# ==========================================
# SECURITY DASHBOARD
# ==========================================

def open_dashboard():

    dashboard = tk.Toplevel(root)

    dashboard.title("Security Dashboard")
    dashboard.geometry("950x580")
    dashboard.configure(bg="#101820")

    tk.Label(
        dashboard,
        text="SECURITY MONITORING DASHBOARD",
        font=("Arial", 19, "bold"),
        bg="#101820",
        fg="#00FF99"
    ).pack(pady=20)

    cursor.execute("SELECT COUNT(*) FROM login_history")
    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM login_history WHERE status='SUCCESS'"
    )

    successful = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM login_history WHERE status='FAILED'"
    )

    failed = cursor.fetchone()[0]

    stats = tk.Frame(
        dashboard,
        bg="#101820"
    )

    stats.pack(pady=10)

    for title, value in [
        ("TOTAL ATTEMPTS", total),
        ("SUCCESSFUL LOGINS", successful),
        ("FAILED LOGINS", failed)
    ]:

        card = tk.Frame(
            stats,
            bg="#1D3545",
            padx=25,
            pady=15
        )

        card.pack(side=tk.LEFT, padx=10)

        tk.Label(
            card,
            text=title,
            bg="#1D3545",
            fg="white",
            font=("Arial", 10, "bold")
        ).pack()

        tk.Label(
            card,
            text=str(value),
            bg="#1D3545",
            fg="#00FF99",
            font=("Arial", 21, "bold")
        ).pack()

    columns = (
        "ID",
        "Username",
        "Status",
        "IP Address",
        "Login Time"
    )

    table = ttk.Treeview(
        dashboard,
        columns=columns,
        show="headings",
        height=14
    )

    for col in columns:

        table.heading(col, text=col)

        table.column(col, width=170)

    table.pack(
        fill=tk.BOTH,
        expand=True,
        padx=15,
        pady=15
    )

    cursor.execute("""
    SELECT id, username, status, ip_address, login_time
    FROM login_history
    ORDER BY id DESC
    """)

    for record in cursor.fetchall():

        table.insert(
            "",
            tk.END,
            values=record
        )


# ==========================================
# MAIN APPLICATION SCREEN
# ==========================================

root = tk.Tk()

root.title("Suspicious Login Detection System")
root.geometry("550x650")
root.configure(bg="#101820")

tk.Label(
    root,
    text="CYBER SECURITY",
    font=("Arial", 14, "bold"),
    bg="#101820",
    fg="#00FF99"
).pack(pady=(45, 5))

tk.Label(
    root,
    text="Suspicious Login Detection",
    font=("Arial", 22, "bold"),
    bg="#101820",
    fg="white"
).pack(pady=12)

tk.Label(
    root,
    text="Secure Authentication & Activity Monitoring",
    font=("Arial", 10),
    bg="#101820",
    fg="#B0BEC5"
).pack(pady=5)

tk.Label(
    root,
    text="WELCOME!",
    font=("Arial", 18, "bold"),
    bg="#101820",
    fg="#00FF99"
).pack(pady=(45, 10))

tk.Label(
    root,
    text="Create an account first or login if you already have one.",
    font=("Arial", 10),
    bg="#101820",
    fg="white"
).pack(pady=10)


# CREATE ACCOUNT BUTTON - FIRST

tk.Button(
    root,
    text="CREATE NEW ACCOUNT",
    font=("Arial", 13, "bold"),
    bg="#00CC88",
    fg="#101820",
    width=27,
    command=open_register
).pack(pady=18, ipady=9)


# LOGIN BUTTON - SECOND

tk.Button(
    root,
    text="LOGIN",
    font=("Arial", 13, "bold"),
    bg="#263D4D",
    fg="white",
    width=27,
    command=open_login
).pack(pady=12, ipady=9)


# SECURITY DASHBOARD BUTTON - THIRD

tk.Button(
    root,
    text="SECURITY DASHBOARD",
    font=("Arial", 11, "bold"),
    bg="#263D4D",
    fg="white",
    width=27,
    command=open_dashboard
).pack(pady=18, ipady=8)


tk.Label(
    root,
    text="Python Based Cyber Security Project",
    font=("Arial", 9),
    bg="#101820",
    fg="#78909C"
).pack(side=tk.BOTTOM, pady=20)


# ==========================================
# RUN APPLICATION
# ==========================================

root.mainloop()

conn.close()
