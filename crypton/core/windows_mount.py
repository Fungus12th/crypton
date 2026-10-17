import os
import sys
import time
import uuid
import shutil
import hashlib
import threading
import subprocess
from typing import Dict, Any, Optional, Tuple

from crypton.core.vault import VaultManager
from crypton.core.crypto import derive_file_key, encrypt_file, decrypt_file


def get_available_drive_letter() -> str:
    """Find the highest available unused drive letter on Windows (prefer Z:, Y:, X:, etc.)."""
    if sys.platform != "win32":
        return "Z:"

    import ctypes
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    existing = set()
    for i in range(26):
        if bitmask & (1 << i):
            existing.add(f"{chr(65 + i)}:")

    for letter in ["Z:", "Y:", "X:", "W:", "V:", "U:", "T:", "S:"]:
        if letter not in existing:
            return letter
    return "Z:"


class WindowsVaultFS:
    """Zero-privilege transparent virtual drive filesystem for Windows using subst + real-time sync."""

    def __init__(self, drive_path: str, mvk: bytes, ram_limit_mb: Optional[int] = None):
        self.drive_path = os.path.abspath(drive_path)
        self.mvk = mvk

        if ram_limit_mb is None:
            settings = VaultManager.get_settings(drive_path)
            ram_limit_mb = settings.get("ram_limit_mb", 32)
        self.ram_limit = int(ram_limit_mb) * 1024 * 1024

        drive_hash = hashlib.sha256(self.drive_path.encode()).hexdigest()[:10]
        self.staging_dir = os.path.join(
            os.environ.get("TEMP", os.environ.get("LOCALAPPDATA", "C:\\Temp")),
            f"crypton_vault_{drive_hash}_{uuid.uuid4().hex[:6]}",
        )
        os.makedirs(self.staging_dir, exist_ok=True)

        self.manifest = VaultManager._load_manifest(self.drive_path, self.mvk)
        self._file_state: Dict[str, Tuple[int, float, str]] = {}  # rel_path -> (size, mtime, sha256)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sync_thread: Optional[threading.Thread] = None
        self.mountpoint: Optional[str] = None

    def update_ram_limit(self, limit_mb: int):
        self.ram_limit = int(limit_mb) * 1024 * 1024

    def populate_initial_state(self):
        """Decrypt existing files from vault into staging directory."""
        for rel_path, rec in list(self.manifest.items()):
            target_file = os.path.join(self.staging_dir, *rel_path.split("/"))
            os.makedirs(os.path.dirname(target_file), exist_ok=True)

            file_id = rec["file_id"]
            enc_rel = rec.get("enc_rel_path", file_id)
            enc_path = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)

            if not os.path.isfile(enc_path):
                flat_path = os.path.join(VaultManager.get_data_dir(self.drive_path), file_id)
                if os.path.isfile(flat_path):
                    enc_path = flat_path

            if os.path.isfile(enc_path):
                file_key = derive_file_key(self.mvk, file_id)
                try:
                    decrypt_file(enc_path, target_file, file_key)
                    mtime = rec.get("mtime", time.time())
                    try:
                        os.utime(target_file, (mtime, mtime))
                    except OSError:
                        pass

                    sha = rec.get("sha256")
                    if not sha and os.path.isfile(target_file):
                        sha = self._compute_hash(target_file)
                    self._file_state[rel_path] = (
                        rec.get("size", os.path.getsize(target_file)),
                        os.path.getmtime(target_file),
                        sha or "",
                    )
                except Exception as e:
                    print(f"[Crypton Warning] Failed to decrypt {rel_path}: {e}", file=sys.stderr)

    @staticmethod
    def _compute_hash(path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _set_drive_label(drive_letter: str, label: str = "Crypton Vault"):
        if sys.platform != "win32":
            return
        letter = drive_letter.strip(":\\/ ").upper()
        if not letter or len(letter) != 1:
            return
        try:
            import winreg
            import ctypes
            key_path = rf"Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\{letter}\DefaultLabel"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, label)

            # Notify Windows Explorer of the new drive name
            ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0005, f"{letter}:\\", None)
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        except Exception:
            pass

    @staticmethod
    def _remove_drive_label(drive_letter: str):
        if sys.platform != "win32":
            return
        letter = drive_letter.strip(":\\/ ").upper()
        if not letter or len(letter) != 1:
            return
        try:
            import winreg
            import ctypes
            key_base = rf"Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\{letter}"
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"{key_base}\DefaultLabel")
            except OSError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"{key_base}\DefaultIcon")
            except OSError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_base)
            except OSError:
                pass
            ctypes.windll.shell32.SHChangeNotify(0x00080000, 0x0005, f"{letter}:\\", None)
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        except Exception:
            pass

    def start(self, drive_letter: str):
        """Mount the drive letter via subst and launch background sync."""
        self.mountpoint = drive_letter.rstrip("\\")
        if not self.mountpoint.endswith(":"):
            self.mountpoint = f"{self.mountpoint}:"

        self.populate_initial_state()

        # Detach any previous mapping on this drive letter
        self._unsubst(self.mountpoint)

        # Map virtual drive letter
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(["subst", self.mountpoint, self.staging_dir], check=True, creationflags=flags)

        # Set customized drive label in Explorer (e.g. 'Crypton Vault (Z:)')
        self._set_drive_label(self.mountpoint, "Crypton Vault")

        self._stop_event.clear()
        self._sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self._sync_thread.start()

    def _sync_worker(self):
        """Background thread monitoring the staging folder for file modifications, creations, deletions."""
        while not self._stop_event.is_set():
            try:
                self.sync_changes()
            except Exception as e:
                print(f"[Crypton Sync Error] {e}", file=sys.stderr)
            self._stop_event.wait(timeout=1.0)

    def sync_changes(self, force: bool = False):
        """Detect modified, new, or deleted files in staging and flush encrypted blocks to USB."""
        if not os.path.isdir(self.staging_dir):
            return

        with self._lock:
            manifest_dirty = False
            current_files = set()

            # 1. Scan staging folder
            for root, dirs, files in os.walk(self.staging_dir):
                # Ignore Windows system/hidden metadata files if needed
                for f in files:
                    if f.lower() in ("desktop.ini", "thumbs.db"):
                        continue

                    full_path = os.path.join(root, f)
                    rel_path = os.path.relpath(full_path, self.staging_dir).replace("\\", "/")
                    current_files.add(rel_path)

                    try:
                        stat_info = os.stat(full_path)
                    except OSError:
                        continue

                    # File might be actively written to; check if changed
                    known = self._file_state.get(rel_path)
                    size = stat_info.st_size
                    mtime = stat_info.st_mtime

                    needs_sync = False
                    if known is None:
                        needs_sync = True
                    elif known[0] != size or abs(known[1] - mtime) > 0.1:
                        needs_sync = True

                    if needs_sync:
                        try:
                            # Try opening file to verify write handle is released
                            sha = self._compute_hash(full_path)
                        except (PermissionError, OSError):
                            # File currently locked by another application (e.g. Explorer copy in progress)
                            continue

                        # Encrypt file to USB vault storage
                        file_id = uuid.uuid4().hex
                        enc_rel = VaultManager._get_encrypted_rel_path(self.mvk, rel_path, file_id)
                        dst_enc = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)
                        os.makedirs(os.path.dirname(dst_enc), exist_ok=True)
                        file_key = derive_file_key(self.mvk, file_id)

                        try:
                            encrypt_file(full_path, dst_enc, file_key)
                        except Exception as e:
                            print(f"[Crypton Encrypt Error] {rel_path}: {e}", file=sys.stderr)
                            continue

                        # Clean old block if updating existing file
                        if rel_path in self.manifest:
                            old_rec = self.manifest[rel_path]
                            old_enc = os.path.join(
                                VaultManager.get_data_dir(self.drive_path),
                                old_rec.get("enc_rel_path", old_rec.get("file_id", "")),
                            )
                            if os.path.isfile(old_enc) and old_enc != dst_enc:
                                try:
                                    os.remove(old_enc)
                                except OSError:
                                    pass

                        self.manifest[rel_path] = {
                            "file_id": file_id,
                            "enc_rel_path": enc_rel,
                            "rel_path": rel_path,
                            "size": size,
                            "mtime": mtime,
                            "sha256": sha,
                            "encrypted_at": time.time(),
                        }
                        self._file_state[rel_path] = (size, mtime, sha)
                        manifest_dirty = True

            # 2. Check for deleted files
            deleted_files = set(self._file_state.keys()) - current_files
            for rel_path in deleted_files:
                if rel_path in self.manifest:
                    rec = self.manifest.pop(rel_path)
                    old_enc = os.path.join(
                        VaultManager.get_data_dir(self.drive_path),
                        rec.get("enc_rel_path", rec.get("file_id", "")),
                    )
                    if os.path.isfile(old_enc):
                        try:
                            os.remove(old_enc)
                        except OSError:
                            pass
                    manifest_dirty = True
                self._file_state.pop(rel_path, None)

            # 3. Save manifest if changed or forced
            if manifest_dirty or force:
                VaultManager._save_manifest(self.drive_path, self.mvk, self.manifest)

    @classmethod
    def _unsubst(cls, drive_letter: str):
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            subprocess.run(["subst", drive_letter, "/D"], capture_output=True, creationflags=flags)
        except Exception:
            pass
        cls._remove_drive_label(drive_letter)

    def stop(self):
        """Stop worker, flush all data, unmount drive letter, and wipe staging folder."""
        self._stop_event.set()
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=3.0)

        # Final synchronous sync
        self.sync_changes(force=True)

        # Unsubst
        if self.mountpoint:
            self._unsubst(self.mountpoint)
            self.mountpoint = None

        # Securely clean staging directory
        if os.path.isdir(self.staging_dir):
            try:
                shutil.rmtree(self.staging_dir, ignore_errors=True)
            except OSError:
                pass


class WindowsVaultMountService:
    """Windows-specific mount service providing transparent drive letter mounting."""

    _active_fs: Optional[WindowsVaultFS] = None

    @classmethod
    def update_ram_limit(cls, limit_mb: int):
        if cls._active_fs:
            cls._active_fs.update_ram_limit(limit_mb)

    @staticmethod
    def get_default_mountpoint(drive_path: str) -> str:
        letter = get_available_drive_letter()
        return f"{letter}\\"

    @classmethod
    def mount(cls, drive_path: str, mvk: bytes, mountpoint: Optional[str] = None) -> Tuple[str, threading.Thread]:
        if not mountpoint:
            mountpoint = cls.get_default_mountpoint(drive_path)

        drive_letter = mountpoint.rstrip("\\")
        if not drive_letter.endswith(":"):
            drive_letter = f"{drive_letter}:"

        fs = WindowsVaultFS(drive_path, mvk)
        cls._active_fs = fs

        fs.start(drive_letter)

        # Dummy thread for interface compatibility
        t = threading.Thread(target=lambda: None)
        t.daemon = True
        t.start()

        display_mount = f"{drive_letter}\\"
        return display_mount, t

    @classmethod
    def unmount(cls, mountpoint: str) -> bool:
        if cls._active_fs:
            try:
                cls._active_fs.stop()
            except Exception as e:
                print(f"[Crypton Unmount Error] {e}", file=sys.stderr)
            cls._active_fs = None

        drive_letter = mountpoint.rstrip("\\")
        if not drive_letter.endswith(":"):
            drive_letter = f"{drive_letter}:"
        WindowsVaultFS._unsubst(drive_letter)
        return True
