import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
import hashlib
from cryptography.fernet import Fernet



# set up database
def init_db():
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS master (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT,
                    key BLOB
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY,
                    site TEXT,
                    username TEXT,
                    password BLOB
                )""")
    conn.commit()
    conn.close()


# security functions
def hash_master(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_master():
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("SELECT password_hash, key FROM master WHERE id = 1")
    result = c.fetchone()
    conn.close()
    return result


def set_master(password: str):
    key = Fernet.generate_key()
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("INSERT INTO master (id, password_hash, key) VALUES (1, ?, ?)",
              (hash_master(password), key))
    conn.commit()
    conn.close()


def get_fernet():
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("SELECT key FROM master WHERE id = 1")
    key = c.fetchone()[0]
    conn.close()
    return Fernet(key)


# operations on vault entries
def add_entry(site, username, password):
    f = get_fernet()
    encrypted = f.encrypt(password.encode())
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("INSERT INTO vault (site, username, password) VALUES (?, ?, ?)",
              (site, username, encrypted))
    conn.commit()
    conn.close()


def get_entries(search=""):
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    if search:
        c.execute("SELECT id, site, username, password FROM vault WHERE site LIKE ?", ('%' + search + '%',))
    else:
        c.execute("SELECT id, site, username, password FROM vault")
    rows = c.fetchall()
    conn.close()
    return rows


def delete_entry(entry_id):
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()

def delete_all_entries():
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("DELETE FROM vault")
    conn.commit()
    conn.close()

def update_entry(entry_id, site, username, password):
    f = get_fernet()
    encrypted = f.encrypt(password.encode())
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("UPDATE vault SET site=?, username=?, password=? WHERE id=?",
              (site, username, encrypted, entry_id))
    conn.commit()
    conn.close()


# gui
class VaultApp:
    def __init__(self, root):
        self.root = root
        self.attempts = 0
        self.root.title("Password Vault")
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(padx=10, pady=10)
        self.show_login()

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_frame()
        master = get_master()
        if not master:
            # first time set up
            tk.Label(self.main_frame, text="Create Master Password").pack()
            entry = tk.Entry(self.main_frame, show="*")
            entry.pack()
            tk.Button(self.main_frame, text="Set",
                      command=lambda: self.create_master(entry.get())).pack()
        else:
            # login screen
            tk.Label(self.main_frame, text="Enter Master Password").pack()
            entry = tk.Entry(self.main_frame, show="*")
            entry.pack()
            tk.Button(self.main_frame, text="Login",
                      command=lambda: self.check_login(entry.get())).pack()

    def create_master(self, pw):
        if not pw:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        set_master(pw)
        messagebox.showinfo("Success", "Master password set!")
        self.show_login()

    def check_login(self, pw):
        global attempts
        master = get_master()
        if master and hash_master(pw) == master[0]:
            self.show_vault()
        else:
            messagebox.showerror("Error", "Incorrect master password")
            # limit attempts to 3
            self.attempts += 1
            if self.attempts >= 3:
                #show alert box and close app
                messagebox.showerror("Error", "Too many incorrect attempts. Exiting.")
                self.root.destroy()

    def show_vault(self):
        self.clear_frame()

        # search
        search_frame = tk.Frame(self.main_frame)
        search_frame.pack(fill="x")
        search_entry = tk.Entry(search_frame)
        search_entry.pack(side="left", expand=True, fill="x")
        tk.Button(search_frame, text="Search",
                  command=lambda: self.refresh_vault(search_entry.get())).pack(side="left")

        # vault list
        self.vault_list = tk.Listbox(self.main_frame, width=50)
        self.vault_list.pack(pady=5)
        self.refresh_vault()

        # buttons
        tk.Button(self.main_frame, text="Add", command=self.add_dialog).pack(side="left", padx=5)
        tk.Button(self.main_frame, text="Edit", command=self.edit_dialog).pack(side="left", padx=5)
        tk.Button(self.main_frame, text="Delete", command=self.delete_selected).pack(side="left", padx=5)
        tk.Button(self.main_frame, text="Delete All", command=self.delete_all).pack(side="right", padx=5)

    def refresh_vault(self, search=""):
        self.vault_list.delete(0, tk.END)
        self.entries = get_entries(search)
        f = get_fernet()
        for eid, site, user, pw in self.entries:
            decrypted = f.decrypt(pw).decode()
            self.vault_list.insert(tk.END, f"{eid}: {site} | {user} | {decrypted}")

    def add_dialog(self):
        site = simpledialog.askstring("Site/App", "Enter site/app name:")
        user = simpledialog.askstring("Username", "Enter username/email:")
        pw = simpledialog.askstring("Password", "Enter password:")
        if site and user and pw:
            add_entry(site, user, pw)
            self.refresh_vault()

    def edit_dialog(self):
        selection = self.vault_list.curselection()
        if not selection:
            return
        idx = selection[0]
        entry_id, site, user, pw = self.entries[idx]
        f = get_fernet()
        pw = f.decrypt(pw).decode()

        site_new = simpledialog.askstring("Site/App", "Edit site/app name:", initialvalue=site)
        user_new = simpledialog.askstring("Username", "Edit username/email:", initialvalue=user)
        pw_new = simpledialog.askstring("Password", "Edit password:", initialvalue=pw)

        if site_new and user_new and pw_new:
            update_entry(entry_id, site_new, user_new, pw_new)
            self.refresh_vault()

    def delete_selected(self):
        selection = self.vault_list.curselection()
        if not selection:
            return
        idx = selection[0]
        entry_id = self.entries[idx][0]
        delete_entry(entry_id)
        self.refresh_vault()

    def delete_all(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete all entries?"):
            delete_all_entries()
            self.refresh_vault()

# main
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = VaultApp(root)
    root.mainloop()
