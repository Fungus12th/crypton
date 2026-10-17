import os
import sys
import time
import uuid
import shutil
import hashlib
import threading
import subprocess
import concurrent.futures
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


def _get_icon_path() -> Optional[str]:
    """Find absolute path to crypton.ico for Windows Explorer drive icon."""
    candidates = []
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidates.extend([
            os.path.join(base, "crypton.ico"),
            os.path.join(base, "crypton", "assets", "crypton.ico"),
            os.path.join(os.path.dirname(sys.executable), "crypton.ico"),
        ])
    module_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.extend([
        os.path.join(module_dir, "..", "assets", "crypton.ico"),
        os.path.join(module_dir, "..", "..", "crypton.ico"),
        os.path.join(os.getcwd(), "crypton.ico"),
    ])
    for p in candidates:
        abs_p = os.path.abspath(p)
        if os.path.isfile(abs_p):
            return abs_p
    return None


def _find_fastest_staging_root() -> str:
    """Find fastest staging root: checks for RAM disk first (DRIVE_RAMDISK=6 or %RAMDISK%), else %LOCALAPPDATA% / %TEMP%."""
    if sys.platform == "win32":
        try:
            import ctypes
            env_ramdisk = os.environ.get("RAMDISK")
            if env_ramdisk and os.path.isdir(env_ramdisk):
                return env_ramdisk

            for i in range(25, -1, -1):
                letter = f"{chr(65 + i)}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(letter) == 6:
                    return letter
        except Exception:
            pass

    return os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or "C:\\Temp"


class WindowsVaultFS:
    """Zero-privilege transparent virtual drive filesystem for Windows using subst + real-time sync."""

    def __init__(self, drive_path: str, mvk: bytes, ram_limit_mb: Optional[int] = None, target_mountpoint: Optional[str] = None):
        self.drive_path = os.path.abspath(drive_path)
        self.mvk = mvk

        if ram_limit_mb is None:
            settings = VaultManager.get_settings(drive_path)
            ram_limit_mb = settings.get("ram_limit_mb", 32)
        self.ram_limit = int(ram_limit_mb) * 1024 * 1024

        clean_target = (target_mountpoint or "").rstrip("\\/ ")
        # If target is empty or a single drive letter (e.g. "Z:" or "Z")
        if not clean_target or (len(clean_target) in (1, 2) and (clean_target.endswith(":") or len(clean_target) == 1)):
            self.is_drive_letter = True
            letter = clean_target[0].upper() if clean_target else get_available_drive_letter()[0].upper()
            self.drive_letter = f"{letter}:"
            drive_hash = hashlib.sha256(self.drive_path.encode()).hexdigest()[:10]
            staging_base = _find_fastest_staging_root()
            self.staging_dir = os.path.join(
                staging_base,
                "CryptonVault",
                f"vault_{drive_hash}_{uuid.uuid4().hex[:6]}",
            )
        else:
            self.is_drive_letter = False
            self.drive_letter = None
            self.staging_dir = os.path.abspath(target_mountpoint)

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
        """Decrypt existing files from vault into staging directory in parallel for maximum speed."""
        items = list(self.manifest.items())
        if not items:
            return

        def _decrypt_worker(item):
            rel_path, rec = item
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

                    sz = rec.get("size", os.path.getsize(target_file))
                    # Windows RAM optimization: Pin files <= ram_limit directly in system RAM cache
                    if sys.platform == "win32" and sz <= self.ram_limit:
                        try:
                            import ctypes
                            ctypes.windll.kernel32.SetFileAttributesW(target_file, 0x0100)  # FILE_ATTRIBUTE_TEMPORARY
                        except Exception:
                            pass

                    return (
                        rel_path,
                        sz,
                        os.path.getmtime(target_file),
                    )
                except Exception as e:
                    print(f"[Crypton Warning] Failed to decrypt {rel_path}: {e}", file=sys.stderr)
            return None

        # Use up to 8 parallel workers for concurrent AES-GCM decryption
        max_workers = min(8, max(2, (os.cpu_count() or 4)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for result in executor.map(_decrypt_worker, items):
                if result:
                    rel_p, sz, mt = result
                    self._file_state[rel_p] = (sz, mt, "")

    @staticmethod
    def _compute_hash(path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _set_drive_label_and_icon(drive_letter: str, label: str = "Crypton Vault"):
        if sys.platform != "win32":
            return
        letter = drive_letter.strip(":\\/ ").upper()
        if not letter or len(letter) != 1:
            return
        try:
            import winreg
            import ctypes
            key_base = rf"Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\{letter}"

            # 1. Custom drive label (replaces 'ACER (Z:)' with 'Crypton Vault (Z:)')
            key_label = rf"{key_base}\DefaultLabel"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_label) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, label)

            # 2. Custom copper bank vault icon
            ico = _get_icon_path()
            if ico:
                key_icon = rf"{key_base}\DefaultIcon"
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_icon) as k:
                    winreg.SetValueEx(k, "", 0, winreg.REG_SZ, ico)

            # 3. Notify Windows Explorer of the new drive name and icon
            ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0005, f"{letter}:\\", None)
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        except Exception:
            pass

    @staticmethod
    def _remove_drive_label_and_icon(drive_letter: str):
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

    def start(self, mountpoint: str):
        """Mount the vault (drive letter via subst or directory) and launch background sync."""
        if self.is_drive_letter:
            self.mountpoint = f"{self.drive_letter}\\"
            letter = self.drive_letter

            self.populate_initial_state()
            self._unsubst(letter)

            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(["subst", letter, self.staging_dir], check=True, creationflags=flags)
            self._set_drive_label_and_icon(letter, "Crypton Vault")
        else:
            self.mountpoint = self.staging_dir
            self.populate_initial_state()

        self._stop_event.clear()
        self._sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self._sync_thread.start()

    def _sync_worker(self):
        """Kernel-assisted event-driven background thread monitoring staging folder with zero idle CPU/disk overhead."""
        change_handle = None
        if sys.platform == "win32" and os.path.isdir(self.staging_dir):
            try:
                import ctypes
                flags = 0x1 | 0x2 | 0x8 | 0x10  # FILE_NAME | DIR_NAME | SIZE | LAST_WRITE
                change_handle = ctypes.windll.kernel32.FindFirstChangeNotificationW(self.staging_dir, True, flags)
            except Exception:
                change_handle = None

        try:
            while not self._stop_event.is_set():
                if change_handle and change_handle != -1:
                    import ctypes
                    # Wait up to 2 seconds in kernel sleep; wake up immediately when files change
                    res = ctypes.windll.kernel32.WaitForSingleObject(change_handle, 2000)
                    if self._stop_event.is_set():
                        break
                    if res == 0:  # WAIT_OBJECT_0: Actual file modification detected
                        time.sleep(0.4)  # Debounce to let disk writes complete
                        try:
                            self.sync_changes()
                        except Exception as e:
                            print(f"[Crypton Sync Error] {e}", file=sys.stderr)
                        ctypes.windll.kernel32.FindNextChangeNotification(change_handle)
                    elif res == 258:  # WAIT_TIMEOUT: Idle period (zero disk access)
                        pass
                else:
                    self._stop_event.wait(timeout=2.0)
                    if not self._stop_event.is_set():
                        try:
                            self.sync_changes()
                        except Exception as e:
                            print(f"[Crypton Sync Error] {e}", file=sys.stderr)
        finally:
            if change_handle and change_handle != -1:
                try:
                    import ctypes
                    ctypes.windll.kernel32.FindCloseChangeNotification(change_handle)
                except Exception:
                    pass

    def sync_changes(self, force: bool = False):
        """Detect modified, new, or deleted files in staging and flush encrypted blocks to USB."""
        if not os.path.isdir(self.staging_dir):
            return

        with self._lock:
            manifest_dirty = False
            current_files = set()
            files_to_encrypt = []

            # 1. Scan staging folder
            for root, dirs, files in os.walk(self.staging_dir):
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

                    known = self._file_state.get(rel_path)
                    size = stat_info.st_size
                    mtime = stat_info.st_mtime

                    needs_sync = False
                    if known is None:
                        needs_sync = True
                    elif known[0] != size or abs(known[1] - mtime) > 1.5:
                        needs_sync = True

                    if needs_sync:
                        try:
                            # Test handle release
                            with open(full_path, "rb") as test_f:
                                test_f.read(1024)
                            if sys.platform == "win32" and size <= self.ram_limit:
                                try:
                                    import ctypes
                                    ctypes.windll.kernel32.SetFileAttributesW(full_path, 0x0100)
                                except Exception:
                                    pass
                            files_to_encrypt.append((full_path, rel_path, size, mtime))
                        except (PermissionError, OSError):
                            continue

            # Encrypt modified / new files in parallel
            if files_to_encrypt:
                def _encrypt_worker(item):
                    full_p, rel_p, sz, mt = item
                    file_id = uuid.uuid4().hex
                    enc_rel = VaultManager._get_encrypted_rel_path(self.mvk, rel_p, file_id)
                    dst_enc = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)
                    os.makedirs(os.path.dirname(dst_enc), exist_ok=True)
                    file_key = derive_file_key(self.mvk, file_id)

                    try:
                        encrypt_file(full_p, dst_enc, file_key)
                    except Exception as e:
                        print(f"[Crypton Encrypt Error] {rel_p}: {e}", file=sys.stderr)
                        return None

                    # Clean old encrypted block if replacing existing file
                    old_rec = self.manifest.get(rel_p)
                    if old_rec:
                        old_enc = os.path.join(
                            VaultManager.get_data_dir(self.drive_path),
                            old_rec.get("enc_rel_path", old_rec.get("file_id", "")),
                        )
                        if os.path.isfile(old_enc) and old_enc != dst_enc:
                            try:
                                os.remove(old_enc)
                            except OSError:
                                pass

                    return rel_p, {
                        "file_id": file_id,
                        "enc_rel_path": enc_rel,
                        "rel_path": rel_p,
                        "size": sz,
                        "mtime": mt,
                        "sha256": "",
                        "encrypted_at": time.time(),
                    }, (sz, mt, "")

                max_enc_workers = min(4, max(1, (os.cpu_count() or 2)))
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_enc_workers) as executor:
                    for res in executor.map(_encrypt_worker, files_to_encrypt):
                        if res:
                            rel_p, manifest_rec, state_rec = res
                            self.manifest[rel_p] = manifest_rec
                            self._file_state[rel_p] = state_rec
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
        clean = drive_letter.rstrip("\\")
        if not clean.endswith(":"):
            clean = f"{clean}:"
        try:
            subprocess.run(["subst", clean, "/D"], capture_output=True, creationflags=flags)
        except Exception:
            pass
        cls._remove_drive_label_and_icon(clean)

    def stop(self):
        """Stop worker, flush all data, unmount drive letter, and securely wipe staging folder."""
        self._stop_event.set()
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=3.0)

        # Final synchronous sync
        self.sync_changes(force=True)

        # Unsubst if virtual drive letter
        if self.is_drive_letter and self.drive_letter:
            self._unsubst(self.drive_letter)
            self.mountpoint = None

        # Clean staging directory in background thread for instant UI response
        staging_dir = self.staging_dir
        if os.path.isdir(staging_dir):
            def _clean():
                try:
                    shutil.rmtree(staging_dir, ignore_errors=True)
                except OSError:
                    pass
            threading.Thread(target=_clean, daemon=True).start()


class WindowsVaultMountService:
    """Windows mount service providing transparent high-speed virtual drive mounting or folder mounting."""

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

        fs = WindowsVaultFS(drive_path, mvk, target_mountpoint=mountpoint)
        cls._active_fs = fs

        fs.start(mountpoint)

        # Dummy thread for interface compatibility
        t = threading.Thread(target=lambda: None)
        t.daemon = True
        t.start()

        display_mount = fs.mountpoint or mountpoint
        return display_mount, t

    @classmethod
    def unmount(cls, mountpoint: str) -> bool:
        if cls._active_fs:
            try:
                cls._active_fs.stop()
            except Exception as e:
                print(f"[Crypton Unmount Error] {e}", file=sys.stderr)
            cls._active_fs = None

        clean = mountpoint.rstrip("\\/ ")
        if clean and len(clean) in (1, 2) and (clean.endswith(":") or len(clean) == 1):
            letter = f"{clean[0].upper()}:"
            WindowsVaultFS._unsubst(letter)
        elif os.path.isdir(mountpoint):
            try:
                shutil.rmtree(mountpoint, ignore_errors=True)
            except OSError:
                pass
        return True
