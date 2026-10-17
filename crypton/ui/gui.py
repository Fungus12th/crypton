import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from crypton.core.vault import VaultManager, InvalidPasswordError, VaultError
from crypton.core.header import VaultHeader
from crypton.core.fuse_vault import VaultMountService, FUSE

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class CryptonApp(ctk.CTk):
    def __init__(self, initial_dir: str = "."):
        super().__init__()
        self.title("Crypton - Secure USB Vault")
        self.geometry("560 x 440")
        self.minsize(520, 400)

        self.drive_path = os.path.abspath(initial_dir)
        self.mvk = None
        self.mountpoint = None

        # Clean exit hook: ensure virtual filesystem is unmounted when closing
        self.protocol("WM_DELETE_WINDOW", self.on_window_close)

        # Top Bar: Drive Selector
        self.top_frame = ctk.CTkFrame(self, corner_radius=10)
        self.top_frame.pack(fill="x", padx=15, pady=10)

        self.lbl_path = ctk.CTkLabel(
            self.top_frame,
            text=f"Drive: {self.drive_path}",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        )
        self.lbl_path.pack(side="left", padx=15, pady=10, expand=True, fill="x")

        self.btn_select_drive = ctk.CTkButton(
            self.top_frame,
            text="Change Drive",
            width=100,
            height=30,
            command=self.change_drive,
        )
        self.btn_select_drive.pack(side="right", padx=(5, 10), pady=10)

        self.btn_dev = ctk.CTkButton(
            self.top_frame,
            text="⚙️ Dev",
            width=65,
            height=30,
            fg_color="#34495e",
            hover_color="#2c3e50",
            command=self.open_dev_settings,
        )
        self.btn_dev.pack(side="right", padx=(5, 0), pady=10)

        # Dynamic Content Container
        self.content_container = ctk.CTkFrame(self, corner_radius=10)
        self.content_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.refresh_state()

    def change_drive(self):
        new_path = filedialog.askdirectory(
            title="Select USB Drive or Directory",
            initialdir=self.drive_path,
        )
        if new_path:
            if self.mvk:
                self.handle_lock()
            self.drive_path = os.path.abspath(new_path)
            self.lbl_path.configure(text=f"Drive: {self.drive_path}")
            self.refresh_state()

    def refresh_state(self):
        for widget in self.content_container.winfo_children():
            widget.destroy()

        if self.mvk is not None:
            self.render_unlocked_view()
        elif VaultManager.is_vault(self.drive_path):
            self.render_locked_view()
        else:
            self.render_init_view()

    # ================= VIEW 1: INITIALIZE DRIVE =================
    def render_init_view(self):
        title = ctk.CTkLabel(
            self.content_container,
            text="🛡️ Set Up Crypton Vault",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.pack(pady=(30, 8))

        desc = ctk.CTkLabel(
            self.content_container,
            text="Set a master password to encrypt and password-protect this drive.",
            font=ctk.CTkFont(size=12),
            text_color="gray70",
        )
        desc.pack(pady=(0, 20))

        self.init_pwd = ctk.CTkEntry(
            self.content_container,
            placeholder_text="Enter Master Password",
            show="*",
            width=320,
            height=40,
        )
        self.init_pwd.pack(pady=8)

        self.init_confirm = ctk.CTkEntry(
            self.content_container,
            placeholder_text="Confirm Master Password",
            show="*",
            width=320,
            height=40,
        )
        self.init_confirm.pack(pady=8)

        self.lbl_init_status = ctk.CTkLabel(
            self.content_container, text="", font=ctk.CTkFont(size=12)
        )
        self.lbl_init_status.pack(pady=5)

        self.btn_init = ctk.CTkButton(
            self.content_container,
            text="🔒 Initialize & Protect Drive",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=44,
            width=260,
            command=self.handle_init,
        )
        self.btn_init.pack(pady=10)

    def handle_init(self):
        pwd = self.init_pwd.get()
        confirm = self.init_confirm.get()

        if not pwd or len(pwd) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return

        if pwd != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        self.btn_init.configure(state="disabled")
        self.lbl_init_status.configure(text="Deriving Argon2id keys...", text_color="yellow")

        def worker():
            try:
                VaultManager.init_vault(self.drive_path, pwd)
                self.after(0, lambda: (
                    messagebox.showinfo("Success", "Crypton Vault successfully initialized!"),
                    self.refresh_state(),
                ))
            except Exception as e:
                self.after(0, lambda err=e: (
                    self.btn_init.configure(state="normal"),
                    self.lbl_init_status.configure(text=f"Error: {err}", text_color="red"),
                    messagebox.showerror("Initialization Failed", str(err)),
                ))

        threading.Thread(target=worker, daemon=True).start()

    # ================= VIEW 2: VAULT LOCKED =================
    def render_locked_view(self):
        title = ctk.CTkLabel(
            self.content_container,
            text="🔒 Crypton Vault Locked",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        title.pack(pady=(40, 10))

        sub = ctk.CTkLabel(
            self.content_container,
            text="Enter master password to mount your encrypted files.",
            font=ctk.CTkFont(size=13),
            text_color="gray70",
        )
        sub.pack(pady=(0, 20))

        self.entry_unlock_pwd = ctk.CTkEntry(
            self.content_container,
            placeholder_text="Enter Master Password",
            show="*",
            width=320,
            height=42,
        )
        self.entry_unlock_pwd.pack(pady=10)
        self.entry_unlock_pwd.bind("<Return>", lambda e: self.handle_unlock())

        self.lbl_unlock_status = ctk.CTkLabel(
            self.content_container, text="", font=ctk.CTkFont(size=12)
        )
        self.lbl_unlock_status.pack(pady=5)

        self.btn_unlock = ctk.CTkButton(
            self.content_container,
            text="🔓 Unlock & Open Drive",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=44,
            width=260,
            command=self.handle_unlock,
        )
        self.btn_unlock.pack(pady=10)

    def handle_unlock(self):
        pwd = self.entry_unlock_pwd.get()
        if not pwd:
            return

        self.btn_unlock.configure(state="disabled")
        self.lbl_unlock_status.configure(
            text="Unlocking & auto-repairing vault...", text_color="yellow"
        )

        def worker():
            try:
                # 1. Unlock MVK
                mvk = VaultManager.unlock_vault(self.drive_path, pwd)

                # 2. Automatic Self-Healing: clean any broken records silently
                VaultManager.verify_and_repair_vault(self.drive_path, mvk)

                # 3. Mount transparent FUSE filesystem
                mountpoint, _ = VaultMountService.mount(self.drive_path, mvk)

                self.after(0, lambda: self.on_unlock_success(mvk, mountpoint))
            except InvalidPasswordError:
                self.after(0, self.on_unlock_bad_password)
            except Exception as e:
                self.after(0, lambda err=e: self.on_unlock_error(str(err)))

        threading.Thread(target=worker, daemon=True).start()

    def on_unlock_success(self, mvk: bytes, mountpoint: str):
        self.mvk = mvk
        self.mountpoint = mountpoint
        self.refresh_state()

        # Automatically open the user's native file manager (Nautilus, Dolphin, Explorer)
        try:
            subprocess.Popen(["xdg-open", mountpoint])
        except Exception:
            pass

    def on_unlock_bad_password(self):
        self.btn_unlock.configure(state="normal")
        self.lbl_unlock_status.configure(text="Incorrect password. Access denied.", text_color="red")
        messagebox.showerror("Access Denied", "Incorrect master password.")

    def on_unlock_error(self, err_msg):
        self.btn_unlock.configure(state="normal")
        self.lbl_unlock_status.configure(text=f"Error: {err_msg}", text_color="red")
        messagebox.showerror("Unlock Failed", err_msg)

    # ================= VIEW 3: VAULT UNLOCKED =================
    def render_unlocked_view(self):
        icon = ctk.CTkLabel(
            self.content_container,
            text="🟢",
            font=ctk.CTkFont(size=36),
        )
        icon.pack(pady=(25, 5))

        title = ctk.CTkLabel(
            self.content_container,
            text="Vault Unlocked & Active",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#2ecc71",
        )
        title.pack(pady=(0, 6))

        path_lbl = ctk.CTkLabel(
            self.content_container,
            text=f"Mounted: {self.mountpoint}",
            font=ctk.CTkFont(size=12),
            text_color="gray70",
        )
        path_lbl.pack(pady=(0, 15))

        tip = ctk.CTkLabel(
            self.content_container,
            text="✨ Use your normal file manager to drag & drop, view, or edit files.\nEverything is encrypted transparently on the fly.",
            font=ctk.CTkFont(size=12),
            text_color="gray80",
            justify="center",
        )
        tip.pack(pady=(0, 25))

        # Main Actions (Minimalist: Open Folder + Lock Drive)
        btn_open = ctk.CTkButton(
            self.content_container,
            text="📂 Open in File Manager",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42,
            width=260,
            command=self.open_file_manager,
        )
        btn_open.pack(pady=6)

        btn_lock = ctk.CTkButton(
            self.content_container,
            text="🔒 Lock & Safely Close",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#e74c3c",
            hover_color="#c0392b",
            height=42,
            width=260,
            command=self.handle_lock,
        )
        btn_lock.pack(pady=6)

        # Subtle Optional Cloud Sync
        btn_gdrive = ctk.CTkButton(
            self.content_container,
            text="☁️ Sync with Google Drive (Optional)",
            font=ctk.CTkFont(size=12),
            fg_color="#2c3e50",
            hover_color="#34495e",
            height=34,
            width=260,
            command=self.handle_gdrive_sync,
        )
        btn_gdrive.pack(pady=(12, 10))

    def open_file_manager(self):
        if self.mountpoint and os.path.exists(self.mountpoint):
            try:
                subprocess.Popen(["xdg-open", self.mountpoint])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file manager: {e}")

    def handle_lock(self):
        if self.mountpoint:
            VaultMountService.unmount(self.mountpoint)
            self.mountpoint = None

        self.mvk = None
        self.refresh_state()
        messagebox.showinfo("Vault Locked", "Your files have been safely encrypted and unmounted.")

    def handle_gdrive_sync(self):
        messagebox.showinfo(
            "Google Drive Sync",
            "Google Drive Sync:\nOAuth login will prompt your Google account.\n"
            "(Credentials are used in memory and never stored on the USB drive).",
        )

    def open_dev_settings(self):
        DeveloperSettingsDialog(self, self.drive_path)

    def on_window_close(self):
        if self.mountpoint:
            VaultMountService.unmount(self.mountpoint)
        self.destroy()


class DeveloperSettingsDialog(ctk.CTkToplevel):
    """Developer & Performance Tuning Modal for RAM buffer settings."""

    def __init__(self, master, drive_path: str):
        super().__init__(master)
        self.title("Developer & Performance Settings")
        self.geometry("490x420")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self.drive_path = drive_path
        self.settings = VaultManager.get_settings(drive_path)
        current_limit = self.settings.get("ram_limit_mb", 32)

        # Header
        title = ctk.CTkLabel(
            self,
            text="⚡ RAM Staging & Performance",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        title.pack(pady=(20, 5))

        desc = ctk.CTkLabel(
            self,
            text=(
                "Crypton stages incoming files in lightning-fast RAM before writing to USB.\n"
                "This bypasses the slow 2x USB flash write penalty and doubles transfer speed.\n"
                "Files larger than your limit will safely stage directly on disk."
            ),
            font=ctk.CTkFont(size=11),
            text_color="gray70",
            justify="center",
        )
        desc.pack(padx=20, pady=(0, 15))

        # System RAM info frame
        info_frame = ctk.CTkFrame(self, corner_radius=8)
        info_frame.pack(fill="x", padx=25, pady=5)

        shm_main = "PC Fast RAM Cache: Not available"
        shm_sub = ""
        if os.path.isdir("/dev/shm"):
            try:
                st = os.statvfs("/dev/shm")
                free_mb = (st.f_bavail * st.f_frsize) / (1024 * 1024)
                total_mb = (st.f_blocks * st.f_frsize) / (1024 * 1024)
                shm_main = f"🖥️ PC Fast RAM Cache (/dev/shm): {free_mb:,.0f} MB free"
                shm_sub = f"Allocated from your PC's ~{round(total_mb*2/1024)} GB memory (NOT pendrive space)"
            except Exception:
                shm_main = "🖥️ PC Fast RAM Cache: Available"

        lbl_shm = ctk.CTkLabel(
            info_frame,
            text=shm_main,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#3498db",
        )
        lbl_shm.pack(padx=15, pady=(8, 2 if shm_sub else 8))

        if shm_sub:
            lbl_sub = ctk.CTkLabel(
                info_frame,
                text=shm_sub,
                font=ctk.CTkFont(size=10),
                text_color="gray70",
            )
            lbl_sub.pack(padx=15, pady=(0, 8))

        # Setting options frame
        setting_frame = ctk.CTkFrame(self, corner_radius=8)
        setting_frame.pack(fill="x", padx=25, pady=12)

        # Active Setting Badge
        cur_row = ctk.CTkFrame(setting_frame, fg_color="transparent")
        cur_row.pack(fill="x", padx=15, pady=(12, 6))

        lbl_cur_title = ctk.CTkLabel(
            cur_row,
            text="Currently Active Limit:",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        lbl_cur_title.pack(side="left")

        self.lbl_active_val = ctk.CTkLabel(
            cur_row,
            text=f"{current_limit} MB",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#2ecc71",
        )
        self.lbl_active_val.pack(side="left", padx=8)

        # Dropdown selection
        lbl_limit = ctk.CTkLabel(
            setting_frame,
            text="Change Limit to:",
            font=ctk.CTkFont(size=12),
            text_color="gray80",
        )
        lbl_limit.pack(anchor="w", padx=15, pady=(4, 4))

        self.options = [
            "16 MB",
            "32 MB (Recommended)",
            "64 MB",
            "128 MB",
            "256 MB",
            "512 MB",
            "1024 MB",
        ]

        default_val = "32 MB (Recommended)"
        for opt in self.options:
            val_mb = int(opt.split()[0])
            if val_mb == current_limit:
                default_val = opt
                break

        self.combo_limit = ctk.CTkOptionMenu(
            setting_frame,
            values=self.options,
            width=240,
            height=34,
        )
        self.combo_limit.set(default_val)
        self.combo_limit.pack(padx=15, pady=(0, 15), anchor="w")

        # Feedback label
        self.lbl_status = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=12),
        )
        self.lbl_status.pack(pady=4)

        # Action buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=25, pady=8)

        btn_save = ctk.CTkButton(
            btn_frame,
            text="💾 Save & Apply",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=140,
            height=36,
            command=self.save_settings,
        )
        btn_save.pack(side="left", padx=(0, 10))

        btn_close = ctk.CTkButton(
            btn_frame,
            text="Close",
            fg_color="#7f8c8d",
            hover_color="#95a5a6",
            width=100,
            height=36,
            command=self.destroy,
        )
        btn_close.pack(side="right")

    def save_settings(self):
        val_str = self.combo_limit.get()
        limit_mb = int(val_str.split()[0])
        self.settings["ram_limit_mb"] = limit_mb
        VaultManager.save_settings(self.drive_path, self.settings)
        VaultMountService.update_ram_limit(limit_mb)
        self.lbl_active_val.configure(text=f"{limit_mb} MB")
        self.lbl_status.configure(
            text=f"✔ Saved! Limit updated to {limit_mb} MB.",
            text_color="#2ecc71",
        )


def launch_gui(initial_dir: str = "."):
    app = CryptonApp(initial_dir)
    app.mainloop()
