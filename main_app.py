import customtkinter as ctk
from tkinter import messagebox, filedialog, ttk
from src.database_manager import DatabaseManager
from src.crypto_engine import CryptoEngine
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import shutil
import re
import subprocess
import hashlib
import base64

db = DatabaseManager()
crypto = CryptoEngine()


def find_vscode_launch_cmd():
    code_in_path = shutil.which("code")
    if code_in_path:
        return [code_in_path]

    candidates = []
    localappdata = os.environ.get("LOCALAPPDATA", "")
    programfiles = os.environ.get("ProgramFiles", "")
    programfilesx86 = os.environ.get("ProgramFiles(x86)", "")

    if localappdata:
        candidates.append(os.path.join(localappdata, "Programs", "Microsoft VS Code", "Code.exe"))
    if programfiles:
        candidates.append(os.path.join(programfiles, "Microsoft VS Code", "Code.exe"))
    if programfilesx86:
        candidates.append(os.path.join(programfilesx86, "Microsoft VS Code", "Code.exe"))

    for path in candidates:
        if path and os.path.exists(path):
            return [path]
    return None


class DevTrustApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DevTrust - Secure Supply Chain Verifier")
        self.geometry("1280x850")
        ctk.set_appearance_mode("dark")
        self.current_user = None
        self.ensure_folders()
        self.show_login()

    def ensure_folders(self):
        for f in ["keys", "database", "uploads/staging", "uploads/prod_ready", "uploads/review_temp"]:
            os.makedirs(f, exist_ok=True)

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_screen()
        self.current_user = None

        frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=15)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(frame, text="Secure Login", font=("Arial", 28, "bold")).pack(pady=20, padx=40)
        e = ctk.CTkEntry(frame, placeholder_text="Email", width=320, height=45)
        e.pack(pady=10)
        p = ctk.CTkEntry(frame, placeholder_text="Password", show="*", width=320, height=45)
        p.pack(pady=10)

        r_var = ctk.StringVar(value="Junior Developer")
        ctk.CTkOptionMenu(frame, values=["Junior Developer", "Senior Developer"], variable=r_var, width=320).pack(pady=10)

        def login_action():
            u = db.get_user_by_role(e.get(), r_var.get())
            if not u:
                return messagebox.showerror("Error", "Account Not Found!")

            try:
                data = crypto.load_private_key_pem(e.get(), p.get(), keys_dir="keys")

                serialization.load_pem_private_key(
                    data,
                    password=p.get().encode(),
                    backend=default_backend()
                )

                self.current_user = {"email": e.get(), "role": r_var.get(), "pwd": p.get()}
                self.show_dashboard()

            except Exception:
                messagebox.showerror("Error", "Invalid Password or Access Key!")

        ctk.CTkButton(frame, text="Login", command=login_action, width=250, height=45).pack(pady=20)
        ctk.CTkButton(frame, text="Create New Account", fg_color="transparent", command=self.show_register).pack()

    def show_register(self):
        self.clear_screen()

        frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(frame, text="User Registration", font=("Arial", 28, "bold")).pack(pady=20)
        e_reg = ctk.CTkEntry(frame, placeholder_text="Email (example@gmail.com)", width=320)
        e_reg.pack(pady=10)

        r_var = ctk.StringVar(value="Junior Developer")
        ctk.CTkComboBox(frame, values=["Junior Developer", "Senior Developer"], variable=r_var, state="readonly", width=320).pack(pady=10)

        p_reg = ctk.CTkEntry(frame, placeholder_text="Set Password", show="*", width=320)
        p_reg.pack(pady=10)

        def reg():
            email = e_reg.get().strip()

            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                return messagebox.showerror("Error", "Use valid email format!")

            if not (email and p_reg.get()):
                return messagebox.showerror("Error", "Email and password are required!")

            priv, pub = crypto.generate_key_pair(p_reg.get())
            crypto.encrypt_and_store_private_key(email, priv, p_reg.get(), keys_dir="keys")

            db.register_user(email, r_var.get(), pub.decode(), "CERT", "HASH")
            messagebox.showinfo("Success", "Registered Successfully!")
            self.show_login()

        ctk.CTkButton(frame, text="Register", command=reg).pack(pady=20)

    def show_dashboard(self):
        self.clear_screen()

        top = ctk.CTkFrame(self, height=60, fg_color="#111111")
        top.pack(side="top", fill="x")
        ctk.CTkButton(top, text="Logout", fg_color="#d9534f", command=self.show_login).pack(side="right", padx=20, pady=10)

        display_name = self.current_user["email"].split("@")[0]
        ctk.CTkLabel(self, text=f"Welcome, {display_name}", font=("Arial", 38, "bold"), text_color="#2ecc71").pack(pady=(30, 5))
        ctk.CTkLabel(self, text=f"Account Type: {self.current_user['role']}", font=("Arial", 16)).pack(pady=(0, 20))

        if self.current_user["role"] == "Junior Developer":
            self.junior_ui()
        else:
            self.senior_ui()

    def junior_ui(self):
        tabs = ctk.CTkTabview(self, width=1200, height=600, fg_color="#111111")
        tabs.pack(pady=10, padx=20)
        tabs.add("Submit Code")
        tabs.add("Submission History")

        sub = tabs.tab("Submit Code")

        ctk.CTkLabel(sub, text="Select Senior Reviewer:", font=("Arial", 14)).pack(pady=5)
        self.rev_cb = ctk.CTkComboBox(sub, values=db.get_reviewers(), width=450, height=40)
        self.rev_cb.pack(pady=5)

        ctk.CTkLabel(sub, text="Brief Code Explanation (Message for Senior):", font=("Arial", 14)).pack(pady=5)
        self.j_msg = ctk.CTkEntry(sub, placeholder_text="Explain your code changes here...", width=450, height=40)
        self.j_msg.pack(pady=5)

        self.f_path = None
        self.f_lbl = ctk.CTkLabel(sub, text="No file selected", text_color="gray")
        self.f_lbl.pack(pady=10)

        def browse():
            self.f_path = filedialog.askopenfilename()
            if self.f_path:
                self.f_lbl.configure(text=f"Selected: {os.path.basename(self.f_path)}", text_color="white")

        ctk.CTkButton(sub, text="📂 Browse Code", command=browse).pack(pady=10)

        def submit():
            if not self.f_path:
                return messagebox.showerror("Error", "Select file first!")

            # SHA-256 hash
            try:
                with open(self.f_path, "rb") as f:
                    file_bytes = f.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
            except Exception as ex:
                return messagebox.showerror("Error", f"Could not read file for hashing: {ex}")

            priv = crypto.load_private_key_pem(self.current_user["email"], self.current_user["pwd"], keys_dir="keys")
            sig = crypto.sign_data(self.f_path, priv, self.current_user["pwd"])

            shutil.copy(self.f_path, os.path.join("uploads", "staging", os.path.basename(self.f_path)))

            db.add_file_record(
                os.path.basename(self.f_path),
                self.current_user["email"],
                self.rev_cb.get(),
                sig,
                file_hash,
                self.j_msg.get()
            )

            messagebox.showinfo("Success", "Code Submitted for Secure Review!")
            self.show_dashboard()

        ctk.CTkButton(sub, text="🚀 Sign & Submit Review", command=submit, fg_color="#28a745", height=45).pack(pady=20)

        hist = tabs.tab("Submission History")
        cols = ("ID", "File Name", "Reviewer", "Status", "Feedback", "Date Sent")

        tree = ttk.Treeview(hist, columns=cols, show="headings", height=18)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=190)
        tree.pack(fill="both", expand=True)

        for r in db.get_junior_activity(self.current_user["email"]):
            tree.insert("", "end", values=r)

    def senior_ui(self):
        tabs = ctk.CTkTabview(self, width=1200, height=600, fg_color="#111111")
        tabs.pack(pady=10, padx=20)
        tabs.add("Waiting for Review")
        tabs.add("Verification History")

        wait = tabs.tab("Waiting for Review")

        scroll = ctk.CTkScrollableFrame(wait, width=1150, height=450, fg_color="#1a1a1a")
        scroll.pack(fill="both", expand=True)

        pending = db.get_pending_for_senior(self.current_user["email"])
        for f in pending:
            row = ctk.CTkFrame(scroll, fg_color="#252525", height=50)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{f[1]} (From: {f[2]})", width=700, anchor="w").pack(side="left", padx=20)
            ctk.CTkButton(
                row,
                text="🔍 Review Code",
                width=120,
                command=lambda fid=f[0], fn=f[1], j=f[2], jm=f[3]: self.open_review_box(fid, fn, j, jm)
            ).pack(side="right", padx=20)

        hist = tabs.tab("Verification History")
        cols_h = ("ID", "File Name", "Junior Dev", "Status", "Feedback")

        tree_h = ttk.Treeview(hist, columns=cols_h, show="headings", height=18)
        for col in cols_h:
            tree_h.heading(col, text=col)
            tree_h.column(col, width=220)
        tree_h.pack(fill="both", expand=True)

        for r in db.get_reviewed_for_senior(self.current_user["email"]):
            tree_h.insert("", "end", values=r)

    def open_review_box(self, f_id, f_name, junior, junior_msg):
        box = ctk.CTkToplevel(self)
        box.title(f"Security Review: {f_name}")
        box.geometry("700x550")
        box.attributes("-topmost", True)
        box.configure(fg_color="#111111")

        ctk.CTkLabel(box, text="Code Verification Panel", font=("Arial", 22, "bold"), text_color="#3498db").pack(pady=20)
        ctk.CTkLabel(box, text=f"File: {f_name} | From: {junior}", font=("Arial", 14, "bold")).pack(pady=5)

        msg_frame = ctk.CTkFrame(box, fg_color="#1a1a1a", corner_radius=10)
        msg_frame.pack(pady=10, padx=20, fill="x")

        ctk.CTkLabel(
            msg_frame,
            text=f"Junior's Note: {junior_msg if junior_msg else 'No information provided'}",
            font=("Arial", 12, "italic"),
            wraplength=600
        ).pack(pady=10, padx=10)

        def review_copy_path():
            return os.path.join("uploads", "review_temp", f"{f_id}_{f_name}")

        def cleanup_review_temp():
            temp_path = review_copy_path()
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass

        def open_file():
            staging_path = os.path.join("uploads", "staging", f_name)
            temp_path = review_copy_path()
            os.makedirs(os.path.join("uploads", "review_temp"), exist_ok=True)

            if not os.path.exists(staging_path):
                return messagebox.showerror("Error", "File not found in staging!")

            try:
                shutil.copy2(staging_path, temp_path)
            except Exception as ex:
                return messagebox.showerror("Error", f"Could not prepare review copy: {ex}")

            ext = os.path.splitext(temp_path)[1].lower()
            text_like = {".py", ".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".csv", ".log", ".ini", ".cfg"}

            try:
                if ext in text_like:
                    vscode_cmd = find_vscode_launch_cmd()
                    if not vscode_cmd:
                        return messagebox.showerror(
                            "VS Code Not Found",
                            "DevTrust could not locate VS Code.\n\n"
                            "Fix options:\n"
                            "1) In VS Code: Ctrl+Shift+P → 'Shell Command: Install code command in PATH'\n"
                            "2) Or install VS Code normally.\n\n"
                            "Then restart the app and try again."
                        )

                    subprocess.Popen(vscode_cmd + ["--new-window", os.path.abspath(temp_path)], shell=False)
                else:
                    os.startfile(os.path.abspath(temp_path))
            except Exception as ex:
                messagebox.showerror("Error", f"Could not open file: {ex}")

        ctk.CTkButton(box, text="👁️ Open File for Review", command=open_file, width=300, height=40).pack(pady=10)

        fb = ctk.CTkEntry(box, placeholder_text="Add Reviewer Feedback...", width=550, height=80)
        fb.pack(pady=20)

        btn_frame = ctk.CTkFrame(box, fg_color="transparent")
        btn_frame.pack(pady=20)

        # ✅ Commit 3: Verify SHA-256 + RSA signature BEFORE approval
        def approve_action():
            staging_path = os.path.join("uploads", "staging", f_name)

            try:
                bundle = db.get_file_crypto_bundle(f_id)
                if not bundle:
                    return messagebox.showerror("Error", "DB record missing for this file!")

                db_file_name, db_junior, db_signature, db_hash = bundle

                if not os.path.exists(staging_path):
                    return messagebox.showerror("Error", "File missing from staging. Possible tampering!")

                # Recalculate hash
                with open(staging_path, "rb") as f:
                    current_bytes = f.read()
                current_hash = hashlib.sha256(current_bytes).hexdigest()

                if not db_hash or current_hash != db_hash:
                    db.update_review(f_id, "REJECTED", "Auto-Rejected: SHA-256 hash mismatch (possible tampering).")
                    box.destroy()
                    messagebox.showerror("Blocked", "Rejected: Hash mismatch detected!")
                    self.show_dashboard()
                    return

                # Verify signature using junior public key
                pubkey_pem = db.get_public_key(db_junior)
                if not pubkey_pem:
                    db.update_review(f_id, "REJECTED", "Auto-Rejected: Junior public key not found.")
                    box.destroy()
                    messagebox.showerror("Blocked", "Rejected: Junior public key missing!")
                    self.show_dashboard()
                    return

                # Signature might come as bytes or str; normalize to bytes
                sig_bytes = db_signature
                if isinstance(sig_bytes, str):
                    try:
                        sig_bytes = base64.b64decode(sig_bytes.encode())
                    except:
                        sig_bytes = sig_bytes.encode()

                ok = crypto.verify_signature(pubkey_pem, current_bytes, sig_bytes)
                if not ok:
                    db.update_review(f_id, "REJECTED", "Auto-Rejected: RSA signature verification failed.")
                    box.destroy()
                    messagebox.showerror("Blocked", "Rejected: Signature verification failed!")
                    self.show_dashboard()
                    return

                # Passed both checks -> Approve
                db.update_review(f_id, "APPROVED", fb.get())
                shutil.move(staging_path, os.path.join("uploads", "prod_ready", f_name))

            except Exception as ex:
                return messagebox.showerror("Error", f"Approve failed: {ex}")
            finally:
                cleanup_review_temp()

            box.destroy()
            messagebox.showinfo("Success", "Approved (Hash + Signature Verified)!")
            self.show_dashboard()

        def reject_action():
            try:
                db.update_review(f_id, "REJECTED", fb.get())
            except Exception as ex:
                return messagebox.showerror("Error", f"Reject failed: {ex}")
            finally:
                cleanup_review_temp()

            box.destroy()
            messagebox.showinfo("Rejected", "File Rejected")
            self.show_dashboard()

        ctk.CTkButton(
            btn_frame,
            text="✅ Approve",
            fg_color="#28a745",
            width=200,
            height=50,
            font=("Arial", 14, "bold"),
            command=approve_action
        ).pack(side="left", padx=20)

        ctk.CTkButton(
            btn_frame,
            text="❌ Reject",
            fg_color="#d9534f",
            width=200,
            height=50,
            font=("Arial", 14, "bold"),
            command=reject_action
        ).pack(side="left", padx=20)


if __name__ == "__main__":
    app = DevTrustApp()
    app.mainloop()