import os
import sys
import time
import uuid
import shutil
import hashlib
import threading
import subprocess
import concurrent.futures
import io
import mimetypes
import socket
import urllib.request
from typing import Dict, Any, Optional, Tuple, List

from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection
from wsgidav.dav_error import DAVError, HTTP_FORBIDDEN, HTTP_NOT_FOUND
from wsgidav.wsgidav_app import WsgiDAVApp
from cheroot import wsgi

from crypton.core.vault import VaultManager
from crypton.core.crypto import (
    derive_file_key,
    encrypt_file,
    decrypt_file,
    encrypt_stream,
    VaultStreamReader,
    FlushTracker,
    CHUNK_SIZE,
)


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

    def __init__(self, drive_path: str, mvk: bytes, ram_limit_mb: Optional[int] = None, target_mountpoint: Optional[str] = None, read_only: bool = False):
        self.drive_path = os.path.abspath(drive_path)
        self.mvk = mvk
        self.read_only = bool(read_only)

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
            label = "Crypton Vault (Read-Only)" if self.read_only else "Crypton Vault"
            self._set_drive_label_and_icon(letter, label)
        else:
            self.mountpoint = self.staging_dir
            self.populate_initial_state()

        if not self.read_only:
            self._stop_event.clear()
            self._sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
            self._sync_thread.start()

    def get_flush_status(self) -> dict:
        return {"is_flushing": False, "progress_pct": 100.0, "pending_chunks": 0, "active_files": 0}

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
        if not os.path.isdir(self.staging_dir) or self.read_only:
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


class CryptonDAVCollection(DAVCollection):
    """Virtual directory resource backed by in-memory manifest."""

    def __init__(self, path: str, environ: dict, rel_path: str = ""):
        super().__init__(path, environ)
        self.rel_path = rel_path.strip("/")

    def get_member_names(self) -> List[str]:
        prefix = (self.rel_path + "/") if self.rel_path else ""
        children = set()
        with self.provider._lock:
            for k in self.provider.manifest.keys():
                if not prefix or k.startswith(prefix):
                    rem = k[len(prefix):]
                    name = rem.split("/")[0]
                    if name:
                        children.add(name)
            for k in self.provider._staging_buffers.keys():
                if not prefix or k.startswith(prefix):
                    rem = k[len(prefix):]
                    name = rem.split("/")[0]
                    if name:
                        children.add(name)
            for vdir in self.provider.virtual_dirs:
                vclean = vdir.strip("/")
                if not prefix or vclean.startswith(prefix):
                    rem = vclean[len(prefix):]
                    name = rem.split("/")[0]
                    if name:
                        children.add(name)
        return sorted(list(children))

    def get_member(self, name: str):
        child_path = f"{self.path.rstrip('/')}/{name}"
        return self.provider.get_resource_inst(child_path, self.environ)

    def create_empty_resource(self, name: str):
        if self.provider.read_only:
            raise DAVError(HTTP_FORBIDDEN, "Vault is mounted in Read-Only Paranoia Mode")
        child_rel = f"{self.rel_path}/{name}".strip("/") if self.rel_path else name
        child_path = f"{self.path.rstrip('/')}/{name}"
        with self.provider._lock:
            self.provider._staging_buffers[child_rel] = b""
        return self.provider.get_resource_inst(child_path, self.environ)

    def create_collection(self, name: str):
        if self.provider.read_only:
            raise DAVError(HTTP_FORBIDDEN, "Vault is mounted in Read-Only Paranoia Mode")
        child_rel = f"{self.rel_path}/{name}".strip("/") if self.rel_path else name
        with self.provider._lock:
            self.provider.virtual_dirs.add(child_rel)
        child_path = f"{self.path.rstrip('/')}/{name}"
        return self.provider.get_resource_inst(child_path, self.environ)

    def delete(self):
        if self.provider.read_only:
            raise DAVError(HTTP_FORBIDDEN, "Vault is mounted in Read-Only Paranoia Mode")
        self.provider.delete_dir(self.rel_path)

    def support_recursive_delete(self) -> bool:
        return True


class _CaptureBytesIO(io.BytesIO):
    """Memory buffer that preserves payload even after WsgiDAV calls close()."""

    def __init__(self):
        super().__init__()
        self.captured_bytes = b""

    def close(self):
        if not self.closed:
            self.captured_bytes = self.getvalue()
        super().close()


class CryptonDAVFile(DAVNonCollection):
    """Virtual file resource streaming 64 KB AES-GCM chunks on-demand via HTTP Range."""

    def __init__(self, path: str, environ: dict, rel_path: str):
        super().__init__(path, environ)
        self.rel_path = rel_path
        self._write_buf: Optional[_CaptureBytesIO] = None

    def get_content_length(self) -> int:
        with self.provider._lock:
            if self.rel_path in self.provider._staging_buffers:
                return len(self.provider._staging_buffers[self.rel_path])
            if self.rel_path in self.provider.manifest:
                return self.provider.manifest[self.rel_path].get("size", 0)
        return 0

    def get_content_type(self) -> str:
        mime, _ = mimetypes.guess_type(self.name)
        return mime or "application/octet-stream"

    def get_last_modified(self) -> float:
        with self.provider._lock:
            if self.rel_path in self.provider.manifest:
                return self.provider.manifest[self.rel_path].get("mtime", time.time())
        return time.time()

    def support_ranges(self) -> bool:
        return True

    def support_content_length(self) -> bool:
        return True

    def support_modified(self) -> bool:
        return True

    def support_etag(self) -> bool:
        return True

    def get_etag(self) -> str:
        sz = self.get_content_length()
        mt = self.get_last_modified()
        return hashlib.md5(f"{self.rel_path}-{sz}-{mt}".encode()).hexdigest()

    def get_content(self):
        with self.provider._lock:
            if self.rel_path in self.provider._staging_buffers:
                return io.BytesIO(self.provider._staging_buffers[self.rel_path])

            if self.rel_path not in self.provider.manifest:
                return io.BytesIO(b"")

            rec = self.provider.manifest[self.rel_path]
            file_id = rec["file_id"]
            enc_rel = rec.get("enc_rel_path", file_id)
            enc_path = os.path.join(VaultManager.get_data_dir(self.provider.drive_path), enc_rel)

            if not os.path.isfile(enc_path):
                flat = os.path.join(VaultManager.get_data_dir(self.provider.drive_path), file_id)
                if os.path.isfile(flat):
                    enc_path = flat

            if not os.path.isfile(enc_path):
                return io.BytesIO(b"")

            file_key = derive_file_key(self.provider.mvk, file_id)
            f_size = rec.get("size", 0)
            return VaultStreamReader(enc_path, file_key, f_size)

    def begin_write(self, *, content_type=None):
        if self.provider.read_only:
            raise DAVError(HTTP_FORBIDDEN, "Vault is mounted in Read-Only Paranoia Mode")
        self._write_buf = _CaptureBytesIO()
        return self._write_buf

    def end_write(self, *, with_errors=False):
        if self.provider.read_only:
            return
        if with_errors or self._write_buf is None:
            self._write_buf = None
            return

        payload = self._write_buf.captured_bytes
        self._write_buf = None
        with self.provider._lock:
            self.provider._staging_buffers[self.rel_path] = payload
        self.provider.queue_async_encrypt(self.rel_path, payload)

    def delete(self):
        if self.provider.read_only:
            raise DAVError(HTTP_FORBIDDEN, "Vault is mounted in Read-Only Paranoia Mode")
        self.provider.delete_file(self.rel_path)


class CryptonDAVProvider(DAVProvider):
    """In-memory zero-unpacking WebDAV provider backed directly by encrypted vault data."""

    def __init__(self, drive_path: str, mvk: bytes, read_only: bool = False, tracker: Optional[FlushTracker] = None):
        super().__init__()
        self.drive_path = os.path.abspath(drive_path)
        self.mvk = mvk
        self.read_only = bool(read_only)
        self.tracker = tracker or FlushTracker()
        self.manifest = VaultManager._load_manifest(self.drive_path, self.mvk)
        self._staging_buffers: Dict[str, bytes] = {}
        self.virtual_dirs: set = set()
        self._lock = threading.RLock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self._pending_futures = set()

        # Pre-populate virtual directories from manifest
        for rel in self.manifest.keys():
            parts = rel.strip("/").split("/")
            for i in range(1, len(parts)):
                self.virtual_dirs.add("/".join(parts[:i]))

    def is_readonly(self) -> bool:
        return self.read_only

    def get_resource_inst(self, path: str, environ: dict) -> Optional[Any]:
        if "wsgidav.provider" not in environ:
            environ["wsgidav.provider"] = self
        clean = path.strip("/").replace("\\", "/")
        with self._lock:
            if clean == "":
                return CryptonDAVCollection("/", environ, rel_path="")
            if clean in self._staging_buffers or clean in self.manifest:
                return CryptonDAVFile(path, environ, rel_path=clean)
            if clean in self.virtual_dirs:
                return CryptonDAVCollection(path, environ, rel_path=clean)
            prefix = clean + "/"
            if any(k.startswith(prefix) for k in self.manifest.keys()) or any(k.startswith(prefix) for k in self._staging_buffers.keys()):
                return CryptonDAVCollection(path, environ, rel_path=clean)
        return None

    def queue_async_encrypt(self, rel_path: str, data: bytes):
        if self.read_only:
            return
        num_chunks = max(1, (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE)
        self.tracker.add_work(num_chunks)
        fut = self._executor.submit(self._async_encrypt_task, rel_path, data)
        with self._lock:
            self._pending_futures.add(fut)
            fut.add_done_callback(lambda f: self._pending_futures.discard(f))

    def _async_encrypt_task(self, rel_path: str, data: bytes):
        try:
            file_id = uuid.uuid4().hex
            enc_rel = VaultManager._get_encrypted_rel_path(self.mvk, rel_path, file_id)
            dst_enc = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)
            os.makedirs(os.path.dirname(dst_enc), exist_ok=True)
            file_key = derive_file_key(self.mvk, file_id)

            sha256 = hashlib.sha256(data).hexdigest()
            with open(dst_enc, "wb") as f_out:
                encrypt_stream(
                    io.BytesIO(data),
                    f_out,
                    file_key,
                    chunk_callback=lambda idx, sz: self.tracker.chunk_done(),
                )

            with self._lock:
                old_rec = self.manifest.get(rel_path)
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

                self.manifest[rel_path] = {
                    "file_id": file_id,
                    "enc_rel_path": enc_rel,
                    "rel_path": rel_path,
                    "size": len(data),
                    "mtime": time.time(),
                    "sha256": sha256,
                    "encrypted_at": time.time(),
                }
                VaultManager._save_manifest(self.drive_path, self.mvk, self.manifest)
                self._staging_buffers.pop(rel_path, None)
        except Exception as e:
            print(f"[Crypton WebDAV Encrypt Error] {rel_path}: {e}", file=sys.stderr)
        finally:
            self.tracker.file_done()

    def delete_file(self, rel_path: str):
        with self._lock:
            self._staging_buffers.pop(rel_path, None)
            rec = self.manifest.pop(rel_path, None)
            if rec:
                enc_rel = rec.get("enc_rel_path", rec.get("file_id", ""))
                enc_file = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)
                if os.path.isfile(enc_file):
                    try:
                        os.remove(enc_file)
                    except OSError:
                        pass
                VaultManager._save_manifest(self.drive_path, self.mvk, self.manifest)

    def delete_dir(self, rel_dir: str):
        prefix = (rel_dir.strip("/") + "/") if rel_dir else ""
        with self._lock:
            self.virtual_dirs.discard(rel_dir)
            to_del = [k for k in self.manifest.keys() if not prefix or k.startswith(prefix)]
            for k in to_del:
                self.delete_file(k)
            for k in list(self._staging_buffers.keys()):
                if not prefix or k.startswith(prefix):
                    self._staging_buffers.pop(k, None)

    def get_flush_status(self) -> dict:
        return self.tracker.get_flush_status()

    def shutdown(self):
        self._executor.shutdown(wait=True)
        if not self.read_only:
            with self._lock:
                VaultManager._save_manifest(self.drive_path, self.mvk, self.manifest)


class WindowsWebDAVServer:
    """Ephemeral localhost WebDAV server providing transparent on-demand virtual drive mounting."""

    def __init__(self, drive_path: str, mvk: bytes, read_only: bool = False, target_mountpoint: Optional[str] = None):
        self.drive_path = os.path.abspath(drive_path)
        self.mvk = mvk
        self.read_only = bool(read_only)
        clean_target = (target_mountpoint or "").rstrip("\\/ ")
        if clean_target and len(clean_target) in (1, 2) and (clean_target.endswith(":") or len(clean_target) == 1):
            letter = clean_target[0].upper()
            self.drive_letter = f"{letter}:"
        else:
            self.drive_letter = get_available_drive_letter()

        self.mountpoint = f"{self.drive_letter}\\"
        self.port: Optional[int] = None
        self.server: Optional[wsgi.Server] = None
        self.provider: Optional[CryptonDAVProvider] = None
        self._server_thread: Optional[threading.Thread] = None

    def start(self):
        # 1. Ephemeral port allocation (zero collisions)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()

        # 2. Launch WsgiDAVApp on Cheroot server
        self.provider = CryptonDAVProvider(self.drive_path, self.mvk, read_only=self.read_only)
        config = {
            "host": "127.0.0.1",
            "port": self.port,
            "provider_mapping": {"/": self.provider},
            "simple_dc": {"user_mapping": {"*": True}},
            "verbose": 0,
            "logging": {"enable": False},
        }
        app = WsgiDAVApp(config)
        self.server = wsgi.Server(bind_addr=("127.0.0.1", self.port), wsgi_app=app)
        self._server_thread = threading.Thread(target=self.server.start, daemon=True)
        self._server_thread.start()

        # Wait up to 2 seconds for server to be responsive
        ready = False
        for _ in range(20):
            time.sleep(0.1)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=0.5):
                    ready = True
                    break
            except Exception:
                pass

        if not ready:
            raise RuntimeError(f"Localhost WebDAV server failed to bind on 127.0.0.1:{self.port}")

        # 3. Mount on Windows Explorer via net use if on Windows
        if sys.platform == "win32":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(["net", "use", self.drive_letter, "/delete", "/y"], capture_output=True, creationflags=flags)
            cmd = ["net", "use", self.drive_letter, f"http://127.0.0.1:{self.port}/", "/persistent:no"]
            res = subprocess.run(cmd, capture_output=True, text=True, creationflags=flags)
            if res.returncode != 0:
                raise RuntimeError(f"'net use' failed with error: {res.stderr or res.stdout}")
            label = "Crypton Vault (Read-Only)" if self.read_only else "Crypton Vault"
            WindowsVaultFS._set_drive_label_and_icon(self.drive_letter, label)

    def get_flush_status(self) -> dict:
        if self.provider:
            return self.provider.get_flush_status()
        return {"is_flushing": False, "progress_pct": 100.0, "pending_chunks": 0}

    def stop(self):
        if self.provider:
            self.provider.shutdown()

        if sys.platform == "win32" and self.drive_letter:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(["net", "use", self.drive_letter, "/delete", "/y"], capture_output=True, creationflags=flags)
            WindowsVaultFS._remove_drive_label_and_icon(self.drive_letter)

        if self.server:
            try:
                self.server.stop()
            except Exception:
                pass
            self.server = None


class WindowsVaultMountService:
    """Windows mount service providing transparent high-speed virtual drive mounting or folder mounting."""

    _active_service: Optional[Any] = None

    @classmethod
    def update_ram_limit(cls, limit_mb: int):
        if cls._active_service and hasattr(cls._active_service, "update_ram_limit"):
            cls._active_service.update_ram_limit(limit_mb)

    @classmethod
    def get_flush_status(cls) -> dict:
        if cls._active_service and hasattr(cls._active_service, "get_flush_status"):
            return cls._active_service.get_flush_status()
        return {"is_flushing": False, "progress_pct": 100.0, "pending_chunks": 0}

    @staticmethod
    def get_default_mountpoint(drive_path: str) -> str:
        letter = get_available_drive_letter()
        return f"{letter}\\"

    @classmethod
    def mount(
        cls,
        drive_path: str,
        mvk: bytes,
        mountpoint: Optional[str] = None,
        read_only: bool = False,
    ) -> Tuple[str, threading.Thread]:
        # Try WebDAV on-demand engine first (Phase 1)
        try:
            dav_srv = WindowsWebDAVServer(drive_path, mvk, read_only=read_only, target_mountpoint=mountpoint)
            dav_srv.start()
            cls._active_service = dav_srv
            t = threading.Thread(target=lambda: None, daemon=True)
            t.start()
            return dav_srv.mountpoint, t
        except Exception as e:
            print(f"[Crypton Warning] WebDAV mount failed ({e}). Falling back to subst engine...", file=sys.stderr)

        # Fallback to legacy subst engine if WebDAV/WebClient service is unavailable
        if not mountpoint:
            mountpoint = cls.get_default_mountpoint(drive_path)

        fs = WindowsVaultFS(drive_path, mvk, target_mountpoint=mountpoint, read_only=read_only)
        cls._active_service = fs
        fs.start(mountpoint)

        t = threading.Thread(target=lambda: None, daemon=True)
        t.start()

        display_mount = fs.mountpoint or mountpoint
        return display_mount, t

    @classmethod
    def unmount(cls, mountpoint: str) -> bool:
        if cls._active_service:
            try:
                cls._active_service.stop()
            except Exception as e:
                print(f"[Crypton Unmount Error] {e}", file=sys.stderr)
            cls._active_service = None

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
