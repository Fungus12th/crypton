import os
import sys
import errno
import time
import uuid
import stat
import shutil
import hashlib
import threading
import subprocess
from typing import Dict, Any, Optional

try:
    from fuse import FUSE, FuseOSError, Operations
except ImportError:
    FUSE = None
    FuseOSError = Exception
    Operations = object

from crypton.core.vault import VaultManager, VaultError
from crypton.core.crypto import derive_file_key, encrypt_file, decrypt_file


DEFAULT_RAM_LIMIT_MB = 32


class CryptonFS(Operations):
    """Transparent on-the-fly FUSE filesystem for Crypton Vault."""

    def __init__(self, drive_path: str, mvk: bytes, ram_limit_mb: Optional[int] = None):
        self.drive_path = drive_path
        self.mvk = mvk
        self.tmp_dir = os.path.join(drive_path, ".crypton", "tmp")
        os.makedirs(self.tmp_dir, exist_ok=True)

        if ram_limit_mb is None:
            settings = VaultManager.get_settings(drive_path)
            ram_limit_mb = settings.get("ram_limit_mb", DEFAULT_RAM_LIMIT_MB)
        self.ram_limit = int(ram_limit_mb) * 1024 * 1024

        # Fast RAM-based staging (/dev/shm) for files < ram_limit to eliminate USB double-writes
        self.ram_dir = None
        if os.path.isdir("/dev/shm"):
            self.ram_dir = f"/dev/shm/crypton_{hashlib.sha256(drive_path.encode()).hexdigest()[:10]}"
            os.makedirs(self.ram_dir, exist_ok=True)

        self.manifest = VaultManager._load_manifest(drive_path, mvk)
        self.virtual_dirs = set()
        self._init_virtual_dirs()

        self._fh_counter = 1
        self._open_handles = {}  # fh -> dict(fd=..., path=..., mode=..., tmp_path=...)
        self._lock = threading.Lock()

        # Debounced manifest writes
        self._manifest_dirty = False
        self._last_manifest_save = time.time()
        self._manifest_write_count = 0

    def update_ram_limit(self, limit_mb: int):
        """Update RAM staging threshold dynamically."""
        self.ram_limit = int(limit_mb) * 1024 * 1024

    def _get_staging_path(self, estimated_size: int = 0) -> str:
        """Return a RAM staging path if under ram_limit, otherwise disk staging path."""
        base_dir = self.tmp_dir
        if self.ram_dir and estimated_size <= self.ram_limit:
            try:
                statvfs = os.statvfs(self.ram_dir)
                free_shm = statvfs.f_bavail * statvfs.f_frsize
                if free_shm > 64 * 1024 * 1024:
                    base_dir = self.ram_dir
            except OSError:
                pass
        return os.path.join(base_dir, f"stg_{uuid.uuid4().hex}")

    def flush_manifest(self, force: bool = False):
        """Debounced flush of manifest to flash storage."""
        with self._lock:
            if not self._manifest_dirty:
                return
            now = time.time()
            if force or self._manifest_write_count >= 15 or (now - self._last_manifest_save > 1.5):
                VaultManager._save_manifest(self.drive_path, self.mvk, self.manifest)
                self._manifest_dirty = False
                self._last_manifest_save = now
                self._manifest_write_count = 0

    def cleanup(self):
        """Flush pending changes and clean RAM directory."""
        self.flush_manifest(force=True)
        if self.ram_dir and os.path.isdir(self.ram_dir):
            try:
                shutil.rmtree(self.ram_dir, ignore_errors=True)
            except OSError:
                pass

    def _init_virtual_dirs(self):
        """Pre-populate virtual directories from existing manifest file paths."""
        for rel in self.manifest.keys():
            parts = rel.strip("/").split("/")
            for i in range(1, len(parts)):
                self.virtual_dirs.add("/" + "/".join(parts[:i]))

    def _clean_path(self, path: str) -> str:
        return path.lstrip("/")

    # ================= FILESYSTEM METADATA =================
    def getattr(self, path: str, fh=None):
        if path == "/" or path in self.virtual_dirs:
            return {
                "st_mode": stat.S_IFDIR | 0o755,
                "st_nlink": 2,
                "st_size": 4096,
                "st_ctime": time.time(),
                "st_mtime": time.time(),
                "st_atime": time.time(),
            }

        rel = self._clean_path(path)

        # Check if file is currently open (being created/written)
        with self._lock:
            for h_info in self._open_handles.values():
                if h_info["path"] == rel:
                    try:
                        size = os.path.getsize(h_info["tmp_path"])
                    except OSError:
                        size = 0
                    return {
                        "st_mode": stat.S_IFREG | 0o644,
                        "st_nlink": 1,
                        "st_size": size,
                        "st_ctime": time.time(),
                        "st_mtime": time.time(),
                        "st_atime": time.time(),
                    }

        if rel in self.manifest:
            rec = self.manifest[rel]
            mtime = rec.get("mtime", time.time())
            size = rec.get("size", 0)
            return {
                "st_mode": stat.S_IFREG | 0o644,
                "st_nlink": 1,
                "st_size": size,
                "st_ctime": mtime,
                "st_mtime": mtime,
                "st_atime": mtime,
            }

        # Check if path is a parent directory of any manifest file
        prefix = rel.rstrip("/") + "/"
        if any(k.startswith(prefix) for k in self.manifest.keys()):
            return {
                "st_mode": stat.S_IFDIR | 0o755,
                "st_nlink": 2,
                "st_size": 4096,
                "st_ctime": time.time(),
                "st_mtime": time.time(),
                "st_atime": time.time(),
            }

        raise FuseOSError(errno.ENOENT)

    def readdir(self, path: str, fh):
        dirents = [".", ".."]
        clean = self._clean_path(path)
        prefix = clean + "/" if clean else ""

        seen_children = set()
        for rel in self.manifest.keys():
            if not prefix or rel.startswith(prefix):
                remainder = rel[len(prefix):]
                parts = remainder.split("/")
                first_part = parts[0]
                if first_part not in seen_children:
                    seen_children.add(first_part)
                    dirents.append(first_part)

        for vdir in self.virtual_dirs:
            vclean = self._clean_path(vdir)
            if not prefix or vclean.startswith(prefix):
                remainder = vclean[len(prefix):]
                parts = remainder.split("/")
                first_part = parts[0]
                if first_part and first_part not in seen_children:
                    seen_children.add(first_part)
                    dirents.append(first_part)

        return dirents

    def mkdir(self, path: str, mode):
        self.virtual_dirs.add(path)
        return 0

    def rmdir(self, path: str):
        rel = self._clean_path(path)
        self.virtual_dirs.discard(path)
        VaultManager.delete_path(self.drive_path, self.mvk, rel)
        self.manifest = VaultManager._load_manifest(self.drive_path, self.mvk)
        return 0

    def unlink(self, path: str):
        rel = self._clean_path(path)
        VaultManager.delete_path(self.drive_path, self.mvk, rel)
        self.manifest = VaultManager._load_manifest(self.drive_path, self.mvk)
        return 0

    def rename(self, old: str, new: str):
        old_rel = self._clean_path(old)
        new_rel = self._clean_path(new)

        if old_rel in self.manifest:
            rec = self.manifest.pop(old_rel)
            rec["rel_path"] = new_rel
            self.manifest[new_rel] = rec
            VaultManager._save_manifest(self.drive_path, self.mvk, self.manifest)
        return 0

    # ================= FILE READ / WRITE OPERATIONS =================
    def open(self, path: str, flags):
        rel = self._clean_path(path)
        est_size = self.manifest[rel].get("size", 0) if rel in self.manifest else 0
        tmp_file = self._get_staging_path(est_size)

        if rel in self.manifest:
            # Decrypt existing file to staging cache
            rec = self.manifest[rel]
            file_id = rec["file_id"]
            enc_rel = rec.get("enc_rel_path", file_id)
            enc_path = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)

            if not os.path.isfile(enc_path):
                flat_path = os.path.join(VaultManager.get_data_dir(self.drive_path), file_id)
                if os.path.isfile(flat_path):
                    enc_path = flat_path

            if os.path.isfile(enc_path):
                file_key = derive_file_key(self.mvk, file_id)
                decrypt_file(enc_path, tmp_file, file_key)
            else:
                open(tmp_file, "wb").close()
        else:
            open(tmp_file, "wb").close()

        fd = os.open(tmp_file, flags)
        with self._lock:
            fh = self._fh_counter
            self._fh_counter += 1
            self._open_handles[fh] = {
                "fd": fd,
                "path": rel,
                "tmp_path": tmp_file,
                "writing": bool(flags & (os.O_WRONLY | os.O_RDWR)),
            }
        return fh

    def create(self, path: str, mode, fi=None):
        rel = self._clean_path(path)
        tmp_file = self._get_staging_path(0)
        fd = os.open(tmp_file, os.O_RDWR | os.O_CREAT | os.O_TRUNC, mode)

        with self._lock:
            fh = self._fh_counter
            self._fh_counter += 1
            self._open_handles[fh] = {
                "fd": fd,
                "path": rel,
                "tmp_path": tmp_file,
                "writing": True,
            }
        return fh

    def read(self, path: str, size: int, offset: int, fh: int):
        with self._lock:
            h_info = self._open_handles.get(fh)
        if not h_info:
            raise FuseOSError(errno.EBADF)
        os.lseek(h_info["fd"], offset, os.SEEK_SET)
        return os.read(h_info["fd"], size)

    def write(self, path: str, data: bytes, offset: int, fh: int):
        with self._lock:
            h_info = self._open_handles.get(fh)
        if not h_info:
            raise FuseOSError(errno.EBADF)
        h_info["writing"] = True
        os.lseek(h_info["fd"], offset, os.SEEK_SET)
        return os.write(h_info["fd"], data)

    def truncate(self, path: str, length: int, fh=None):
        if fh is not None:
            with self._lock:
                h_info = self._open_handles.get(fh)
            if h_info:
                os.ftruncate(h_info["fd"], length)
                return 0
        return 0

    def release(self, path: str, fh: int):
        with self._lock:
            h_info = self._open_handles.pop(fh, None)
        if not h_info:
            return 0

        os.close(h_info["fd"])
        tmp_file = h_info["tmp_path"]
        rel = h_info["path"]

        try:
            if h_info["writing"] and os.path.isfile(tmp_file):
                # Encrypt modified file into vault data storage
                file_id = uuid.uuid4().hex
                enc_rel = VaultManager._get_encrypted_rel_path(self.mvk, rel, file_id)
                dst_enc = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)
                os.makedirs(os.path.dirname(dst_enc), exist_ok=True)
                file_key = derive_file_key(self.mvk, file_id)

                sha256 = hashlib.sha256()
                with open(tmp_file, "rb") as f:
                    while chunk := f.read(65536):
                        sha256.update(chunk)

                f_size = os.path.getsize(tmp_file)
                f_mtime = os.path.getmtime(tmp_file)
                encrypt_file(tmp_file, dst_enc, file_key)

                # Clean old block if updating existing file
                if rel in self.manifest:
                    old_rec = self.manifest[rel]
                    old_enc = os.path.join(
                        VaultManager.get_data_dir(self.drive_path),
                        old_rec.get("enc_rel_path", old_rec.get("file_id", "")),
                    )
                    if os.path.isfile(old_enc) and old_enc != dst_enc:
                        try:
                            os.remove(old_enc)
                        except OSError:
                            pass

                self.manifest[rel] = {
                    "file_id": file_id,
                    "enc_rel_path": enc_rel,
                    "rel_path": rel,
                    "size": f_size,
                    "mtime": f_mtime,
                    "sha256": sha256.hexdigest(),
                    "encrypted_at": time.time(),
                }
                self._manifest_dirty = True
                self._manifest_write_count += 1
                self.flush_manifest(force=False)
        finally:
            if os.path.isfile(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass

        return 0


class VaultMountService:
    """Manages background FUSE mount lifecycle."""

    _active_fs: Optional[CryptonFS] = None

    @classmethod
    def update_ram_limit(cls, limit_mb: int):
        """Update active filesystem RAM threshold if mounted."""
        if cls._active_fs:
            cls._active_fs.update_ram_limit(limit_mb)

    @staticmethod
    def get_default_mountpoint(drive_path: str) -> str:
        # On Linux, create a clean mountpoint folder on the USB or in user's home
        mount_dir = os.path.join(drive_path, "Vault_Unlocked")
        return mount_dir

    @classmethod
    def mount(cls, drive_path: str, mvk: bytes, mountpoint: Optional[str] = None) -> tuple[str, threading.Thread]:
        if FUSE is None:
            raise RuntimeError("FUSE is not installed on this system.")

        if not mountpoint:
            mountpoint = cls.get_default_mountpoint(drive_path)

        os.makedirs(mountpoint, exist_ok=True)

        fs = CryptonFS(drive_path, mvk)
        cls._active_fs = fs

        def runner():
            try:
                FUSE(fs, mountpoint, foreground=True, nothreads=True)
            except Exception as e:
                print(f"[Crypton FUSE Error] {e}", file=sys.stderr)

        t = threading.Thread(target=runner, daemon=True)
        t.start()

        # Wait up to 3 seconds for mount to appear
        for _ in range(30):
            time.sleep(0.1)
            if os.path.ismount(mountpoint):
                break

        return mountpoint, t

    @classmethod
    def unmount(cls, mountpoint: str) -> bool:
        if cls._active_fs:
            try:
                cls._active_fs.cleanup()
            except Exception:
                pass
            cls._active_fs = None

        if not os.path.exists(mountpoint):
            return True

        # Try fusermount3, fusermount, umount
        for cmd in [["fusermount3", "-u", mountpoint], ["fusermount", "-u", mountpoint], ["umount", mountpoint]]:
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=5)
                if res.returncode == 0:
                    break
            except (subprocess.SubprocessError, FileNotFoundError):
                continue

        # Clean empty mountpoint folder
        try:
            if os.path.isdir(mountpoint) and not os.listdir(mountpoint):
                os.rmdir(mountpoint)
        except OSError:
            pass

        return True
