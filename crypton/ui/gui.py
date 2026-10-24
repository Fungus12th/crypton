import os
import sys
import shutil
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from crypton.core.vault import VaultManager, InvalidPasswordError, VaultError
from crypton.core.header import VaultHeader
from crypton.sync.gdrive import GDriveSync, GDriveAuth, GDriveAuthError, GDriveSyncError

if sys.platform == "win32":
    from crypton.core.windows_mount import WindowsVaultMountService as VaultMountService
    FUSE = None
else:
    from crypton.core.fuse_vault import VaultMountService, FUSE

ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

# Bright Grass Green Theme Palette with Translucent Glassmorphism
THEME = {
    "bg": "#B8EBB8",             # Bright, fresh, luminous grass green
    "card_bg": "#D0F5D2",        # Light fresh grass container tint (no harsh white!)
    "card_border": "#7BC883",    # Clean grass border
    "text_dark": "#0B3314",      # Deep forest charcoal for high-contrast legible titles
    "text_muted": "#1B5226",     # Rich meadow grass for readable subtitles & labels
    "entry_bg": "#E2F9E4",       # Soft translucent light-mint grass input
    "entry_border": "#56BE63",   # Vibrant green input border
    "entry_placeholder": "#4C8E58",
    "primary": "#198754",        # Vibrant grass emerald (Unlock, Initialize, Save)
    "primary_hover": "#146c43",
    "secondary": "#246835",      # Deep meadow green (Dev, Change Drive, Refresh)
    "secondary_hover": "#1A4D27",
    "danger": "#D9534F",         # Coral / crimson (Lock & Close)
    "danger_hover": "#C9302C",
    "cloud": "#147A65",          # Deep sea-green (Sync)
    "cloud_hover": "#0E5848",
    "status_green": "#198754",
    "status_amber": "#D97706",
}


def apply_dark_title_bar(window):
    """Enable native dark mode title bar on Windows 10/11."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if hwnd == 0:
            hwnd = window.winfo_id()
        value = ctypes.c_int(2)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def _init_windows_dpi():
    """Enable high-DPI scaling on Windows."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


_init_windows_dpi()


def get_asset_path(filename: str) -> str:
    """Get absolute path to an asset, handling both development and PyInstaller bundles."""
    if hasattr(sys, "_MEIPASS"):
        p = os.path.join(sys._MEIPASS, "crypton", "assets", filename)
        if os.path.isfile(p):
            return p
        p_root = os.path.join(sys._MEIPASS, filename)
        if os.path.isfile(p_root):
            return p_root

    dev_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", filename)
    if os.path.isfile(dev_path):
        return dev_path

    root_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", filename)
    if os.path.isfile(root_path):
        return root_path

    return filename


def set_window_icon(window):
    """Set the application window icon across Windows and Linux with persistent reference."""
    try:
        if sys.platform == "win32":
            ico = get_asset_path("crypton.ico")
            if os.path.isfile(ico):
                window.iconbitmap(ico)
        png = get_asset_path("crypton.png")
        if os.path.isfile(png):
            from PIL import Image, ImageTk
            img = ImageTk.PhotoImage(Image.open(png))
            window._icon_photo = img
            window.iconphoto(True, img)
    except Exception:
        pass


def get_vault_logo_image(size=(58, 58)):
    """Return a CTkImage of the copper bank vault door logo with resilient fallback."""
    png = get_asset_path("crypton.png")
    if os.path.isfile(png):
        try:
            from PIL import Image
            pil_img = Image.open(png)
            return ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=size)
        except Exception:
            try:
                import tkinter as tk
                scale = max(1, int(round(512 / max(size[0], 1))))
                return tk.PhotoImage(file=png).subsample(scale, scale)
            except Exception:
                pass
    return None


class CryptonApp(ctk.CTk):
    def __init__(self, initial_dir: str = "."):
        super().__init__()
        self.title("Crypton - Secure USB Vault")
        self.geometry("560x450")
        self.minsize(520, 420)
        self.configure(fg_color=THEME["bg"])
        try:
            self.attributes("-alpha", 0.94)
        except Exception:
            pass
        apply_dark_title_bar(self)
        set_window_icon(self)

        self.drive_path = os.path.abspath(initial_dir)
        self.mvk = None
        self.mountpoint = None
        self.read_only = False
        self._poll_job = None
        self.gdrive_auth = GDriveAuth()

        # Clean exit hook: ensure virtual filesystem is unmounted when closing
        self.protocol("WM_DELETE_WINDOW", self.on_window_close)

        # Top Bar: Drive Selector
        self.top_frame = ctk.CTkFrame(
            self,
            corner_radius=10,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
        self.top_frame.pack(fill="x", padx=15, pady=10)

        self.lbl_path = ctk.CTkLabel(
            self.top_frame,
            text=f"Drive: {self.drive_path}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=THEME["text_dark"],
            anchor="w",
        )
        self.lbl_path.pack(side="left", padx=15, pady=10, expand=True, fill="x")

        self.btn_select_drive = ctk.CTkButton(
            self.top_frame,
            text="Change Drive",
            width=110,
            height=30,
            fg_color=THEME["secondary"],
            hover_color=THEME["secondary_hover"],
            text_color="#FFFFFF",
            command=self.change_drive,
        )
        self.btn_select_drive.pack(side="right", padx=10, pady=10)

        # Dynamic Content Container
        self.content_container = ctk.CTkFrame(
            self,
            corner_radius=10,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
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
        logo = get_vault_logo_image((54, 54))
        if logo:
            logo_lbl = ctk.CTkLabel(self.content_container, image=logo, text="")
            logo_lbl.pack(pady=(18, 4))

        title = ctk.CTkLabel(
            self.content_container,
            text="Set Up Crypton Vault",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=THEME["text_dark"],
        )
        title.pack(pady=(0 if logo else 25, 4))

        desc = ctk.CTkLabel(
            self.content_container,
            text="Set a master password to encrypt and password-protect this drive.",
            font=ctk.CTkFont(size=12),
            text_color=THEME["text_muted"],
        )
        desc.pack(pady=(0, 15))

        self.init_pwd = ctk.CTkEntry(
            self.content_container,
            placeholder_text="Enter Master Password",
            show="*",
            width=320,
            height=38,
            fg_color=THEME["entry_bg"],
            border_color=THEME["entry_border"],
            text_color=THEME["text_dark"],
            placeholder_text_color=THEME["entry_placeholder"],
        )
        self.init_pwd.pack(pady=6)

        self.init_confirm = ctk.CTkEntry(
            self.content_container,
            placeholder_text="Confirm Master Password",
            show="*",
            width=320,
            height=38,
            fg_color=THEME["entry_bg"],
            border_color=THEME["entry_border"],
            text_color=THEME["text_dark"],
            placeholder_text_color=THEME["entry_placeholder"],
        )
        self.init_confirm.pack(pady=6)

        self.lbl_init_status = ctk.CTkLabel(
            self.content_container, text="", font=ctk.CTkFont(size=12)
        )
        self.lbl_init_status.pack(pady=3)

        self.btn_init = ctk.CTkButton(
            self.content_container,
            text="Initialize & Protect Drive",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42,
            width=260,
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            text_color="#FFFFFF",
            command=self.handle_init,
        )
        self.btn_init.pack(pady=8)

        btn_cloud_restore = ctk.CTkButton(
            self.content_container,
            text="Restore from Google Drive",
            font=ctk.CTkFont(size=12),
            fg_color=THEME["cloud"],
            hover_color=THEME["cloud_hover"],
            text_color="#FFFFFF",
            height=34,
            width=260,
            command=self.handle_gdrive_sync,
        )
        btn_cloud_restore.pack(pady=3)

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
        self.lbl_init_status.configure(text="Deriving Argon2id keys...", text_color=THEME["text_muted"])

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
                    self.lbl_init_status.configure(text=f"Error: {err}", text_color=THEME["danger"]),
                    messagebox.showerror("Initialization Failed", str(err)),
                ))

        threading.Thread(target=worker, daemon=True).start()

    # ================= VIEW 2: VAULT LOCKED =================
    def render_locked_view(self):
        logo = get_vault_logo_image((58, 58))
        if logo:
            logo_lbl = ctk.CTkLabel(self.content_container, image=logo, text="")
            logo_lbl.pack(pady=(22, 6))

        title = ctk.CTkLabel(
            self.content_container,
            text="Crypton Vault Locked",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=THEME["text_dark"],
        )
        title.pack(pady=(0 if logo else 30, 4))

        sub = ctk.CTkLabel(
            self.content_container,
            text="Enter master password to access encrypted files.",
            font=ctk.CTkFont(size=13),
            text_color=THEME["text_muted"],
        )
        sub.pack(pady=(0, 16))

        self.entry_unlock_pwd = ctk.CTkEntry(
            self.content_container,
            placeholder_text="Enter Master Password",
            show="*",
            width=320,
            height=40,
            fg_color=THEME["entry_bg"],
            border_color=THEME["entry_border"],
            text_color=THEME["text_dark"],
            placeholder_text_color=THEME["entry_placeholder"],
        )
        self.entry_unlock_pwd.pack(pady=8)
        self.entry_unlock_pwd.bind("<Return>", lambda e: self.handle_unlock())

        self.var_read_only = ctk.BooleanVar(value=False)
        self.chk_read_only = ctk.CTkCheckBox(
            self.content_container,
            text="Mount as Read-Only (Paranoia Mode)",
            variable=self.var_read_only,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=THEME["text_dark"],
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            border_color=THEME["entry_border"],
        )
        self.chk_read_only.pack(pady=(2, 6))

        self.lbl_unlock_status = ctk.CTkLabel(
            self.content_container, text="", font=ctk.CTkFont(size=12)
        )
        self.lbl_unlock_status.pack(pady=4)

        self.btn_unlock = ctk.CTkButton(
            self.content_container,
            text="Unlock & Open Drive",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42,
            width=260,
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            text_color="#FFFFFF",
            command=self.handle_unlock,
        )
        self.btn_unlock.pack(pady=8)

        btn_cloud = ctk.CTkButton(
            self.content_container,
            text="Cloud Backup & Restore",
            font=ctk.CTkFont(size=12),
            fg_color=THEME["cloud"],
            hover_color=THEME["cloud_hover"],
            text_color="#FFFFFF",
            height=34,
            width=260,
            command=self.handle_gdrive_sync,
        )
        btn_cloud.pack(pady=3)

    def handle_unlock(self):
        pwd = self.entry_unlock_pwd.get()
        if not pwd:
            return

        read_only = bool(self.var_read_only.get()) if hasattr(self, "var_read_only") else False
        self.btn_unlock.configure(state="disabled")
        self.lbl_unlock_status.configure(
            text="Unlocking & verifying vault...", text_color=THEME["text_muted"]
        )

        def worker():
            try:
                # 1. Unlock MVK
                mvk = VaultManager.unlock_vault(self.drive_path, pwd)

                # 2. Automatic Self-Healing: clean any broken records silently
                VaultManager.verify_and_repair_vault(self.drive_path, mvk)

                # 3. Mount transparent filesystem (with optional read-only paranoia mode)
                mountpoint, _ = VaultMountService.mount(self.drive_path, mvk, read_only=read_only)

                self.after(0, lambda: self.on_unlock_success(mvk, mountpoint, read_only=read_only))
            except InvalidPasswordError:
                self.after(0, self.on_unlock_bad_password)
            except Exception as e:
                self.after(0, lambda err=e: self.on_unlock_error(str(err)))

        threading.Thread(target=worker, daemon=True).start()

    def on_unlock_success(self, mvk: bytes, mountpoint: str, read_only: bool = False):
        self.mvk = mvk
        self.mountpoint = mountpoint
        self.read_only = bool(read_only)
        self.refresh_state()
        # Note: Do not auto-open file manager on unlock per user preference

    def on_unlock_bad_password(self):
        self.btn_unlock.configure(state="normal")
        self.lbl_unlock_status.configure(text="Incorrect password. Access denied.", text_color=THEME["danger"])
        messagebox.showerror("Access Denied", "Incorrect master password.")

    def on_unlock_error(self, err_msg):
        self.btn_unlock.configure(state="normal")
        self.lbl_unlock_status.configure(text=f"Error: {err_msg}", text_color=THEME["danger"])
        messagebox.showerror("Unlock Failed", err_msg)

    # ================= VIEW 3: VAULT UNLOCKED =================
    def render_unlocked_view(self):
        logo = get_vault_logo_image((52, 52))
        if logo:
            logo_lbl = ctk.CTkLabel(self.content_container, image=logo, text="")
            logo_lbl.pack(pady=(16, 4))

        title = ctk.CTkLabel(
            self.content_container,
            text="● Vault Unlocked & Active",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=THEME["status_green"],
        )
        title.pack(pady=(0 if logo else 20, 2))

        if getattr(self, "read_only", False):
            badge_ro = ctk.CTkLabel(
                self.content_container,
                text="🛡️ READ-ONLY MODE ACTIVE (PARANOIA PROTECTION)",
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#D97706",
                text_color="#FFFFFF",
                corner_radius=6,
                height=24,
                width=320,
            )
            badge_ro.pack(pady=(2, 6))

        path_lbl = ctk.CTkLabel(
            self.content_container,
            text=f"Mounted: {self.mountpoint}",
            font=ctk.CTkFont(size=12),
            text_color=THEME["text_muted"],
        )
        path_lbl.pack(pady=(0, 6))

        # Real-time Write-Back Flush Progress & USB Safe-to-Unplug Telemetry
        self.flush_frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        self.flush_frame.pack(fill="x", padx=40, pady=(2, 6))

        self.lbl_flush_status = ctk.CTkLabel(
            self.flush_frame,
            text="✔ All Data Flushed to USB — Safe to Lock / Unplug",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=THEME["status_green"],
        )
        self.lbl_flush_status.pack(pady=(0, 2))

        self.progress_flush = ctk.CTkProgressBar(
            self.flush_frame,
            width=260,
            height=8,
            fg_color=THEME["entry_bg"],
            progress_color=THEME["status_green"],
        )
        self.progress_flush.set(1.0)
        self.progress_flush.pack(pady=(0, 2))

        self._start_flush_polling()

        tip = ctk.CTkLabel(
            self.content_container,
            text="Use your file manager to drag & drop, view, or edit files.\nEverything is encrypted transparently on the fly.",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_muted"],
            justify="center",
        )
        tip.pack(pady=(0, 12))

        # Main Actions (Minimalist: Open Folder + Lock Drive)
        btn_open = ctk.CTkButton(
            self.content_container,
            text="Open in File Manager",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            text_color="#FFFFFF",
            height=40,
            width=260,
            command=self.open_file_manager,
        )
        btn_open.pack(pady=4)

        self.btn_lock = ctk.CTkButton(
            self.content_container,
            text="Lock & Safely Close",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=THEME["danger"],
            hover_color=THEME["danger_hover"],
            text_color="#FFFFFF",
            height=40,
            width=260,
            command=self.handle_lock,
        )
        self.btn_lock.pack(pady=4)

        # Subtle Optional Cloud Sync
        btn_gdrive = ctk.CTkButton(
            self.content_container,
            text="Sync with Google Drive (Optional)",
            font=ctk.CTkFont(size=12),
            fg_color=THEME["cloud"],
            hover_color=THEME["cloud_hover"],
            text_color="#FFFFFF",
            height=34,
            width=260,
            command=self.handle_gdrive_sync,
        )
        btn_gdrive.pack(pady=(8, 6))

    def open_file_manager(self):
        if self.mountpoint and os.path.exists(self.mountpoint):
            try:
                if sys.platform == "win32":
                    os.startfile(self.mountpoint)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", self.mountpoint])
                else:
                    subprocess.Popen(["xdg-open", self.mountpoint])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file manager: {e}")

    def _start_flush_polling(self):
        if self._poll_job:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None
        self._poll_flush_status()

    def _poll_flush_status(self):
        if self.mvk is None:
            return

        try:
            status = VaultMountService.get_flush_status()
            if status.get("is_flushing", False):
                pct = status.get("progress_pct", 0.0)
                pending = status.get("pending_chunks", 0)
                if hasattr(self, "progress_flush") and self.progress_flush.winfo_exists():
                    self.progress_flush.configure(progress_color=THEME["danger"])
                    self.progress_flush.set(pct / 100.0)
                if hasattr(self, "lbl_flush_status") and self.lbl_flush_status.winfo_exists():
                    self.lbl_flush_status.configure(
                        text=f"⚡ Syncing to USB: {pct}% ({pending} chunks left) — DO NOT UNPLUG",
                        text_color=THEME["danger"],
                    )
            else:
                if hasattr(self, "progress_flush") and self.progress_flush.winfo_exists():
                    self.progress_flush.configure(progress_color=THEME["status_green"])
                    self.progress_flush.set(1.0)
                if hasattr(self, "lbl_flush_status") and self.lbl_flush_status.winfo_exists():
                    self.lbl_flush_status.configure(
                        text="✔ All Data Flushed to USB — Safe to Lock / Unplug",
                        text_color=THEME["status_green"],
                    )
        except Exception:
            pass

        self._poll_job = self.after(150, self._poll_flush_status)

    def handle_lock(self):
        try:
            if hasattr(self, "btn_lock") and self.btn_lock.winfo_exists():
                self.btn_lock.configure(state="disabled", text="Locking & Securing...")

            if self._poll_job:
                try:
                    self.after_cancel(self._poll_job)
                except Exception:
                    pass
                self._poll_job = None

            if hasattr(self, "lbl_flush_status") and self.lbl_flush_status.winfo_exists():
                self.lbl_flush_status.configure(
                    text="Safely unmounting filesystem and purging keys...",
                    text_color=THEME.get("status_amber", "#D97706"),
                )

            def _worker():
                try:
                    # Drain any active background flushes up to 15s
                    for _ in range(100):
                        st = VaultMountService.get_flush_status()
                        if not st.get("is_flushing", False):
                            break
                        time.sleep(0.15)

                    # Unmount transparent filesystem
                    if self.mountpoint:
                        VaultMountService.unmount(self.mountpoint)
                        self.mountpoint = None

                    if hasattr(self, "gdrive_auth") and self.gdrive_auth:
                        self.gdrive_auth.wipe_credentials()

                    self.mvk = None
                    self.read_only = False
                except Exception as e:
                    print(f"[Crypton Lock Error] {e}", file=sys.stderr)
                finally:
                    self.after(0, self._on_lock_complete)

            threading.Thread(target=_worker, daemon=True).start()
        except Exception as e:
            print(f"[Crypton Handle Lock Error] {e}", file=sys.stderr)
            self._on_lock_complete()

    def _on_lock_complete(self):
        self.refresh_state()
        messagebox.showinfo("Vault Locked", "Your files have been safely encrypted and unmounted.")

    def handle_gdrive_sync(self):
        GDriveSyncDialog(self, self.drive_path, self.gdrive_auth)

    def open_dev_settings(self):
        DeveloperSettingsDialog(self, self.drive_path)

    def on_window_close(self):
        if self.mountpoint:
            VaultMountService.unmount(self.mountpoint)
        if hasattr(self, "gdrive_auth") and self.gdrive_auth:
            self.gdrive_auth.wipe_credentials()
        self.destroy()


class DeveloperSettingsDialog(ctk.CTkToplevel):
    """Developer & Performance Tuning Modal for RAM buffer settings."""

    def __init__(self, master, drive_path: str):
        super().__init__(master)
        self.title("Developer & Performance Settings")
        self.geometry("490x420")
        self.resizable(False, False)
        self.configure(fg_color=THEME["bg"])
        try:
            self.attributes("-alpha", 0.95)
        except Exception:
            pass
        self.transient(master)
        self.grab_set()
        apply_dark_title_bar(self)
        set_window_icon(self)

        self.drive_path = drive_path
        self.settings = VaultManager.get_settings(drive_path)
        current_limit = self.settings.get("ram_limit_mb", 32)

        # Header
        title = ctk.CTkLabel(
            self,
            text="RAM Staging & Performance",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=THEME["text_dark"],
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
            text_color=THEME["text_muted"],
            justify="center",
        )
        desc.pack(padx=20, pady=(0, 15))

        # System RAM info frame
        info_frame = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
        info_frame.pack(fill="x", padx=25, pady=5)

        shm_main = "PC Fast RAM Cache: Not available"
        shm_sub = ""
        if sys.platform == "win32":
            try:
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                free_mb = stat.ullAvailPhys / (1024 * 1024)
                total_mb = stat.ullTotalPhys / (1024 * 1024)
                shm_main = f"System RAM: {free_mb:,.0f} MB available"
                shm_sub = f"Allocated from your PC's ~{round(total_mb/1024)} GB memory (NOT pendrive space)"
            except Exception:
                shm_main = "System RAM: Available"
        elif os.path.isdir("/dev/shm"):
            try:
                st = os.statvfs("/dev/shm")
                free_mb = (st.f_bavail * st.f_frsize) / (1024 * 1024)
                total_mb = (st.f_blocks * st.f_frsize) / (1024 * 1024)
                shm_main = f"PC Fast RAM Cache (/dev/shm): {free_mb:,.0f} MB free"
                shm_sub = f"Allocated from your PC's ~{round(total_mb*2/1024)} GB memory (NOT pendrive space)"
            except Exception:
                shm_main = "PC Fast RAM Cache: Available"

        lbl_shm = ctk.CTkLabel(
            info_frame,
            text=shm_main,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=THEME["text_dark"],
        )
        lbl_shm.pack(padx=15, pady=(8, 2 if shm_sub else 8))

        if shm_sub:
            lbl_sub = ctk.CTkLabel(
                info_frame,
                text=shm_sub,
                font=ctk.CTkFont(size=10),
                text_color=THEME["text_muted"],
            )
            lbl_sub.pack(padx=15, pady=(0, 8))

        # Setting options frame
        setting_frame = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
        setting_frame.pack(fill="x", padx=25, pady=12)

        # Active Setting Badge
        cur_row = ctk.CTkFrame(setting_frame, fg_color="transparent")
        cur_row.pack(fill="x", padx=15, pady=(12, 6))

        lbl_cur_title = ctk.CTkLabel(
            cur_row,
            text="Currently Active Limit:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=THEME["text_dark"],
        )
        lbl_cur_title.pack(side="left")

        self.lbl_active_val = ctk.CTkLabel(
            cur_row,
            text=f"{current_limit} MB",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=THEME["status_green"],
        )
        self.lbl_active_val.pack(side="left", padx=8)

        # Dropdown selection
        lbl_limit = ctk.CTkLabel(
            setting_frame,
            text="Change Limit to:",
            font=ctk.CTkFont(size=12),
            text_color=THEME["text_muted"],
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
            fg_color=THEME["card_bg"],
            button_color=THEME["secondary"],
            button_hover_color=THEME["secondary_hover"],
            text_color=THEME["text_dark"],
            dropdown_fg_color=THEME["card_bg"],
            dropdown_text_color=THEME["text_dark"],
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
            text="Save & Apply",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=140,
            height=36,
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            text_color="#FFFFFF",
            command=self.save_settings,
        )
        btn_save.pack(side="left", padx=(0, 10))

        btn_close = ctk.CTkButton(
            btn_frame,
            text="Close",
            fg_color=THEME["secondary"],
            hover_color=THEME["secondary_hover"],
            text_color="#FFFFFF",
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
            text=f"Saved! Limit updated to {limit_mb} MB.",
            text_color=THEME["status_green"],
        )


class GDriveSyncDialog(ctk.CTkToplevel):
    """Zero-Knowledge Google Drive Cloud Backup, Restore, and Two-Way Sync Modal."""

    def __init__(self, master, drive_path: str, auth: GDriveAuth):
        super().__init__(master)
        self.title("Google Drive Cloud Backup & Sync")
        self.geometry("560x530")
        self.resizable(False, False)
        self.configure(fg_color=THEME["bg"])
        try:
            self.attributes("-alpha", 0.95)
        except Exception:
            pass
        self.transient(master)
        self.grab_set()
        apply_dark_title_bar(self)
        set_window_icon(self)

        self.master_app = master
        self.drive_path = drive_path
        self.auth = auth
        self.sync_engine = GDriveSync(auth=auth)
        self._is_busy = False

        # Header
        title = ctk.CTkLabel(
            self,
            text="End-to-End Encrypted Cloud Sync",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=THEME["text_dark"],
        )
        title.pack(pady=(14, 2))

        desc = ctk.CTkLabel(
            self,
            text=(
                "• Zero-Knowledge: Google only sees AES-256-GCM ciphertext chunks.\n"
                "• Zero-Footprint: OAuth tokens remain strictly in RAM and are wiped on exit."
            ),
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_muted"],
            justify="center",
        )
        desc.pack(padx=20, pady=(0, 8))

        # Credentials / OAuth Config Card
        self.creds_frame = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
        self.creds_frame.pack(fill="x", padx=20, pady=(0, 8))

        self.lbl_creds = ctk.CTkLabel(
            self.creds_frame,
            text="",
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.lbl_creds.pack(side="left", padx=12, pady=6)

        self.btn_load_creds = ctk.CTkButton(
            self.creds_frame,
            text="Load client_secrets.json",
            width=160,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=THEME["secondary"],
            hover_color=THEME["secondary_hover"],
            text_color="#FFFFFF",
            command=self.load_credentials_file,
        )
        self.btn_load_creds.pack(side="right", padx=10, pady=6)

        # Storage Status Card
        status_card = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
        status_card.pack(fill="x", padx=20, pady=(0, 8))

        row1 = ctk.CTkFrame(status_card, fg_color="transparent")
        row1.pack(fill="x", padx=12, pady=(8, 2))

        self.lbl_local_info = ctk.CTkLabel(
            row1,
            text="USB Pendrive: Scanning...",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=THEME["text_dark"],
        )
        self.lbl_local_info.pack(side="left")

        self.lbl_cloud_info = ctk.CTkLabel(
            row1,
            text="Google Drive: Checking...",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=THEME["text_dark"],
        )
        self.lbl_cloud_info.pack(side="right")

        row2 = ctk.CTkFrame(status_card, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(2, 8))

        self.lbl_delta_info = ctk.CTkLabel(
            row2,
            text="Pending: 0 to upload | 0 to download",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_muted"],
        )
        self.lbl_delta_info.pack(side="left")

        self.btn_refresh = ctk.CTkButton(
            row2,
            text="Scan",
            width=65,
            height=24,
            font=ctk.CTkFont(size=10),
            fg_color=THEME["secondary"],
            hover_color=THEME["secondary_hover"],
            text_color="#FFFFFF",
            command=self.refresh_cloud_status,
        )
        self.btn_refresh.pack(side="right")

        # Progress / Activity Frame
        activity_frame = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=THEME["card_bg"],
            border_width=1,
            border_color=THEME["card_border"],
        )
        activity_frame.pack(fill="x", padx=20, pady=4)

        self.lbl_step = ctk.CTkLabel(
            activity_frame,
            text="Ready to synchronize with Google Drive.",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=THEME["primary"],
            wraplength=500,
        )
        self.lbl_step.pack(padx=15, pady=(8, 4))

        self.progress_bar = ctk.CTkProgressBar(activity_frame, width=480, height=12)
        self.progress_bar.set(0)
        self.progress_bar.pack(padx=15, pady=(0, 6))

        self.lbl_details = ctk.CTkLabel(
            activity_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=THEME["text_muted"],
        )
        self.lbl_details.pack(padx=15, pady=(0, 6))

        # Action Buttons Frame: Exactly Two Directional Sync Buttons
        btn_action_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_action_frame.pack(fill="x", padx=20, pady=(6, 2))

        self.btn_sync_local = ctk.CTkButton(
            btn_action_frame,
            text="Sync with Local Data",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=THEME["secondary"],
            hover_color=THEME["secondary_hover"],
            text_color="#FFFFFF",
            height=40,
            command=self.start_sync_with_local,
        )
        self.btn_sync_local.pack(side="left", padx=(0, 6), expand=True, fill="x")

        self.btn_sync_cloud = ctk.CTkButton(
            btn_action_frame,
            text="Sync with Cloud Data",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=THEME["primary"],
            hover_color=THEME["primary_hover"],
            text_color="#FFFFFF",
            height=40,
            command=self.start_sync_with_cloud,
        )
        self.btn_sync_cloud.pack(side="left", padx=(6, 0), expand=True, fill="x")

        # Explanatory helper row beneath the buttons
        hints_frame = ctk.CTkFrame(self, fg_color="transparent")
        hints_frame.pack(fill="x", padx=20, pady=(0, 6))

        lbl_hint_local = ctk.CTkLabel(
            hints_frame,
            text="USB is Master (Push to Cloud)",
            font=ctk.CTkFont(size=10),
            text_color=THEME["text_muted"],
        )
        lbl_hint_local.pack(side="left", padx=10)

        lbl_hint_cloud = ctk.CTkLabel(
            hints_frame,
            text="Cloud is Master (Pull to USB)",
            font=ctk.CTkFont(size=10),
            text_color=THEME["text_muted"],
        )
        lbl_hint_cloud.pack(side="right", padx=10)

        # Footer Frame
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.pack(fill="x", padx=20, pady=(4, 12))

        self.btn_close = ctk.CTkButton(
            footer_frame,
            text="Close",
            fg_color=THEME["secondary"],
            hover_color=THEME["secondary_hover"],
            text_color="#FFFFFF",
            width=100,
            height=32,
            command=self.destroy,
        )
        self.btn_close.pack(side="right")

        self.update_creds_display()
        self.after(200, self.refresh_cloud_status)

    def update_creds_display(self):
        if self.auth.has_valid_client_config():
            self.lbl_creds.configure(
                text="Google OAuth App Configured",
                text_color=THEME["status_green"],
            )
            self.btn_load_creds.configure(text="Change JSON", width=100)
            if not self._is_busy:
                self.btn_sync_local.configure(state="normal")
                self.btn_sync_cloud.configure(state="normal")
        else:
            self.lbl_creds.configure(
                text="client_secrets.json needed",
                text_color="#D97706",
            )
            self.btn_load_creds.configure(text="Load client_secrets.json", width=170)
            self.btn_sync_local.configure(state="disabled")
            self.btn_sync_cloud.configure(state="disabled")

    def _set_busy(self, is_busy: bool, active_btn=None, active_text=""):
        self._is_busy = is_busy
        state = "disabled" if is_busy else "normal"
        self.btn_sync_local.configure(state=state)
        self.btn_sync_cloud.configure(state=state)
        self.btn_refresh.configure(state=state)
        self.btn_close.configure(state=state)
        self.btn_load_creds.configure(state=state)

        if is_busy and active_btn:
            active_btn.configure(text=active_text)
        elif not is_busy:
            self.btn_sync_local.configure(text="Sync with Local Data")
            self.btn_sync_cloud.configure(text="Sync with Cloud Data")

    def load_credentials_file(self):
        chosen = filedialog.askopenfilename(
            title="Select Google OAuth client_secrets.json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if chosen:
            if self.auth.set_client_config_from_file(chosen):
                try:
                    crypton_dir = VaultManager.get_crypton_dir(self.drive_path)
                    os.makedirs(crypton_dir, exist_ok=True)
                    dest = os.path.join(crypton_dir, "client_secrets.json")
                    shutil.copy2(chosen, dest)
                except Exception:
                    pass
                self.update_creds_display()
                self.lbl_step.configure(
                    text="✔ Credentials loaded! Ready to connect to Google Drive.",
                    text_color="#2ecc71",
                )
                self.refresh_cloud_status()
            else:
                messagebox.showerror(
                    "Invalid Credentials File",
                    "The selected JSON file does not appear to be a valid Google OAuth client secrets file.\n"
                    "Make sure it is downloaded from Google Cloud Console with 'installed' or 'web' keys.",
                )

    def refresh_cloud_status(self):
        if self._is_busy:
            return

        def worker():
            try:
                local_dir = VaultManager.get_data_dir(self.drive_path)
                local_chunks = GDriveSync.get_all_local_chunks(local_dir)
                local_count = len(local_chunks)
                self.after(0, lambda: self.lbl_local_info.configure(text=f"💾 USB Pendrive: {local_count} chunks"))

                if self.auth.is_authenticated():
                    status = self.sync_engine.get_sync_status(self.drive_path)
                    self.after(0, lambda s=status: (
                        self.lbl_cloud_info.configure(text=f"☁️ Google Drive: {s['cloud_chunks']} chunks"),
                        self.lbl_delta_info.configure(
                            text=f"Pending: {s['pending_upload']} to upload | {s['pending_download']} to download ({s['in_sync']} synced)"
                        ),
                    ))
                elif self.auth.has_valid_client_config():
                    self.after(0, lambda: (
                        self.lbl_cloud_info.configure(text="☁️ Google Drive: Ready to connect"),
                        self.lbl_delta_info.configure(text="Click an action button to sync with Google Drive."),
                    ))
                else:
                    self.after(0, lambda: (
                        self.lbl_cloud_info.configure(text="☁️ Google Drive: Not configured"),
                        self.lbl_delta_info.configure(text="Load client_secrets.json above to enable cloud sync."),
                    ))
            except Exception as e:
                self.after(0, lambda err=e: self.lbl_delta_info.configure(text=f"Status: {err}"))

        threading.Thread(target=worker, daemon=True).start()

    def _update_progress(self, message: str, current: int, total: int):
        pct = current / max(1, total)
        self.after(0, lambda msg=message, p=pct: (
            self.lbl_step.configure(text=msg),
            self.progress_bar.set(p),
        ))

    def start_sync_with_local(self):
        self._set_busy(True, self.btn_sync_local, "⏳ Syncing to Cloud...")
        self.lbl_step.configure(
            text="Syncing with Local Data (mirroring USB to Google Drive)...",
            text_color="#f39c12",
        )
        self.progress_bar.set(0.05)

        def worker():
            try:
                stats = self.sync_engine.sync_with_local(
                    self.drive_path,
                    progress_callback=self._update_progress,
                )
                self.after(0, lambda s=stats: (
                    self.lbl_step.configure(text="✔ Local sync complete! Google Drive matches USB.", text_color="#2ecc71"),
                    self.lbl_details.configure(
                        text=f"Uploaded: {s['uploaded_chunks']} chunks | Removed from cloud: {s['deleted_remote_chunks']} chunks"
                    ),
                    self.progress_bar.set(1.0),
                    self._set_busy(False),
                    self.refresh_cloud_status(),
                ))
            except Exception as e:
                self.after(0, lambda err=e: (
                    self.lbl_step.configure(text=f"✖ Sync failed: {err}", text_color="#e74c3c"),
                    self._set_busy(False),
                ))

        threading.Thread(target=worker, daemon=True).start()

    def start_sync_with_cloud(self):
        self._set_busy(True, self.btn_sync_cloud, "⏳ Syncing to USB...")
        self.lbl_step.configure(
            text="Syncing with Cloud Data (mirroring Google Drive to USB)...",
            text_color="#f39c12",
        )
        self.progress_bar.set(0.05)

        def worker():
            try:
                stats = self.sync_engine.sync_with_cloud(
                    self.drive_path,
                    progress_callback=self._update_progress,
                )
                self.after(0, lambda s=stats: (
                    self.lbl_step.configure(text="✔ Cloud sync complete! USB matches Google Drive.", text_color="#2ecc71"),
                    self.lbl_details.configure(
                        text=f"Downloaded: {s['downloaded_chunks']} chunks | Removed from USB: {s['deleted_local_chunks']} chunks"
                    ),
                    self.progress_bar.set(1.0),
                    self._set_busy(False),
                    self.refresh_cloud_status(),
                    getattr(self.master_app, "refresh_state", lambda: None)(),
                ))
            except Exception as e:
                self.after(0, lambda err=e: (
                    self.lbl_step.configure(text=f"✖ Sync failed: {err}", text_color="#e74c3c"),
                    self._set_busy(False),
                ))

        threading.Thread(target=worker, daemon=True).start()



def launch_gui(initial_dir: str = "."):
    app = CryptonApp(initial_dir)
    app.mainloop()
