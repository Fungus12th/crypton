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
import concurrent.futures
from typing import Dict, Any, Optional

try:
    from fuse import FUSE, FuseOSError, Operations
except ImportError:
    FUSE = None
    FuseOSError = Exception
    Operations = object

from crypton.core.vault import VaultManager, VaultError
from crypton.core.crypto import derive_file_key, encrypt_file, decrypt_file, FlushTracker, CHUNK_SIZE


DEFAULT_RAM_LIMIT_MB = 32


class CryptonFS(Operations):
    """High-speed transparent on-the-fly FUSE filesystem for Crypton Vault."""

    def __init__(self, drive_path: str, mvk: bytes, ram_limit_mb: Optional[int] = None, read_only: bool = False):
        self.drive_path = drive_path
        self.mvk = mvk
        self.read_only = bool(read_only)
        self.tracker = FlushTracker()
        self.tmp_dir = os.path.join(drive_path, ".crypton", "tmp")
        os.makedirs(self.tmp_dir, exist_ok=True)

        if ram_limit_mb is None:
            settings = VaultManager.get_settings(drive_path)
            ram_limit_mb = settings.get("ram_limit_mb", DEFAULT_RAM_LIMIT_MB)
        self.ram_limit = int(ram_limit_mb) * 1024 * 1024

        drive_hash = hashlib.sha256(drive_path.encode()).hexdigest()[:10]
        # High-speed RAM staging cache (/dev/shm) to eliminate USB flash bottlenecks
        if os.path.isdir("/dev/shm"):
            self.staging_dir = f"/dev/shm/crypton_{drive_hash}"
        else:
            self.staging_dir = os.path.join(self.tmp_dir, f"stg_{drive_hash}")
        os.makedirs(self.staging_dir, exist_ok=True)

        self.manifest = VaultManager._load_manifest(drive_path, mvk)
        self.virtual_dirs = set()
        self._init_virtual_dirs()

        self._fh_counter = 1
        self._open_handles = {}  # fh -> dict(fd=..., path=..., mode=..., staging_path=...)
        self._lock = threading.RLock()

        # Multi-threaded background encryption pool to write to USB without stalling user I/O
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self._pending_tasks = set()

        # Debounced manifest writes
        self._manifest_dirty = False
        self._last_manifest_save = time.time()
        self._manifest_write_count = 0

    def update_ram_limit(self, limit_mb: int):
        """Update RAM staging threshold dynamically."""
        self.ram_limit = int(limit_mb) * 1024 * 1024

    def _clean_path(self, path: str) -> str:
        return path.lstrip("/")

    def _get_file_staging_path(self, rel: str) -> str:
        clean = self._clean_path(rel)
        target = os.path.join(self.staging_dir, *clean.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        return target

    def _get_all_active_files(self) -> set:
        active = set(self.manifest.keys())
        if os.path.isdir(self.staging_dir):
            for root, _, files in os.walk(self.staging_dir):
                for f in files:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, self.staging_dir).replace("\\", "/")
                    active.add(rel)
        return active

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
        """Wait for pending background encryptions, flush manifest, and clean staging cache."""
        # Wait for all background encryption tasks to complete
        self._executor.shutdown(wait=True)
        self.flush_manifest(force=True)
        if self.staging_dir and os.path.isdir(self.staging_dir):
            try:
                shutil.rmtree(self.staging_dir, ignore_errors=True)
            except OSError:
                pass

    def _init_virtual_dirs(self):
        """Pre-populate virtual directories from existing manifest file paths."""
        for rel in self.manifest.keys():
            parts = rel.strip("/").split("/")
            for i in range(1, len(parts)):
                self.virtual_dirs.add("/" + "/".join(parts[:i]))

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

        with self._lock:
            # Check staging cache first for immediate size/mtime updates
            stg = self._get_file_staging_path(rel)
            if os.path.isfile(stg):
                try:
                    st = os.stat(stg)
                    return {
                        "st_mode": stat.S_IFREG | 0o644,
                        "st_nlink": 1,
                        "st_size": st.st_size,
                        "st_ctime": st.st_ctime,
                        "st_mtime": st.st_mtime,
                        "st_atime": st.st_atime,
                    }
                except OSError:
                    pass

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

            # Check if path is a parent directory of any manifest file or staged file
            prefix = rel.rstrip("/") + "/"
            if any(k.startswith(prefix) for k in self._get_all_active_files()):
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

        with self._lock:
            seen_children = set()
            for rel in self._get_all_active_files():
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
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        with self._lock:
            self.virtual_dirs.add(path)
            stg = self._get_file_staging_path(self._clean_path(path))
            os.makedirs(stg, exist_ok=True)
        return 0

    def rmdir(self, path: str):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        rel = self._clean_path(path)
        with self._lock:
            self.virtual_dirs.discard(path)
            stg_dir = self._get_file_staging_path(rel)
            if os.path.isdir(stg_dir):
                try:
                    shutil.rmtree(stg_dir, ignore_errors=True)
                except OSError:
                    pass
            VaultManager.delete_path(self.drive_path, self.mvk, rel)
            prefix = rel + "/"
            for k in list(self.manifest.keys()):
                if k.startswith(prefix):
                    self.manifest.pop(k, None)
            self._manifest_dirty = True
            self.flush_manifest(force=True)
        return 0

    def unlink(self, path: str):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        rel = self._clean_path(path)
        with self._lock:
            stg = self._get_file_staging_path(rel)
            if os.path.isfile(stg):
                try:
                    os.remove(stg)
                except OSError:
                    pass
            VaultManager.delete_path(self.drive_path, self.mvk, rel)
            self.manifest.pop(rel, None)
            self._manifest_dirty = True
            self.flush_manifest(force=True)
        return 0

    def rename(self, old: str, new: str):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        old_rel = self._clean_path(old)
        new_rel = self._clean_path(new)

        with self._lock:
            old_stg = self._get_file_staging_path(old_rel)
            new_stg = self._get_file_staging_path(new_rel)
            if os.path.isfile(old_stg):
                os.makedirs(os.path.dirname(new_stg), exist_ok=True)
                try:
                    os.replace(old_stg, new_stg)
                except OSError:
                    pass

            if old_rel in self.manifest:
                rec = self.manifest.pop(old_rel)
                rec["rel_path"] = new_rel
                self.manifest[new_rel] = rec
                self._manifest_dirty = True
                self.flush_manifest(force=True)
        return 0

    # ================= FILE READ / WRITE OPERATIONS =================
    def open(self, path: str, flags):
        if self.read_only and (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)):
            raise FuseOSError(errno.EROFS)
        rel = self._clean_path(path)
        staging_path = self._get_file_staging_path(rel)

        with self._lock:
            # If not yet in staging cache, decrypt from vault once
            if not os.path.isfile(staging_path) and rel in self.manifest:
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
                    decrypt_file(enc_path, staging_path, file_key)
                    mtime = rec.get("mtime", time.time())
                    try:
                        os.utime(staging_path, (mtime, mtime))
                    except OSError:
                        pass
                else:
                    open(staging_path, "wb").close()
            elif not os.path.isfile(staging_path):
                open(staging_path, "wb").close()

            fd = os.open(staging_path, flags)
            fh = self._fh_counter
            self._fh_counter += 1
            self._open_handles[fh] = {
                "fd": fd,
                "path": rel,
                "staging_path": staging_path,
                "writing": bool(flags & (os.O_WRONLY | os.O_RDWR)),
            }
        return fh

    def create(self, path: str, mode, fi=None):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        rel = self._clean_path(path)
        staging_path = self._get_file_staging_path(rel)

        with self._lock:
            fd = os.open(staging_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, mode)
            fh = self._fh_counter
            self._fh_counter += 1
            self._open_handles[fh] = {
                "fd": fd,
                "path": rel,
                "staging_path": staging_path,
                "writing": True,
            }
            parts = rel.split("/")
            for i in range(1, len(parts)):
                self.virtual_dirs.add("/" + "/".join(parts[:i]))
        return fh

    def read(self, path: str, size: int, offset: int, fh: int):
        with self._lock:
            h_info = self._open_handles.get(fh)
        if not h_info:
            raise FuseOSError(errno.EBADF)
        os.lseek(h_info["fd"], offset, os.SEEK_SET)
        return os.read(h_info["fd"], size)

    def write(self, path: str, data: bytes, offset: int, fh: int):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        with self._lock:
            h_info = self._open_handles.get(fh)
        if not h_info:
            raise FuseOSError(errno.EBADF)
        h_info["writing"] = True
        os.lseek(h_info["fd"], offset, os.SEEK_SET)
        return os.write(h_info["fd"], data)

    def truncate(self, path: str, length: int, fh=None):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        with self._lock:
            if fh is not None and fh in self._open_handles:
                os.ftruncate(self._open_handles[fh]["fd"], length)
            else:
                rel = self._clean_path(path)
                stg = self._get_file_staging_path(rel)
                if os.path.isfile(stg):
                    with open(stg, "r+b") as f:
                        f.truncate(length)
        return 0

    def chmod(self, path: str, mode: int):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        return 0

    def chown(self, path: str, uid: int, gid: int):
        if self.read_only:
            raise FuseOSError(errno.EROFS)
        return 0

    def release(self, path: str, fh: int):
        with self._lock:
            h_info = self._open_handles.pop(fh, None)
        if not h_info:
            return 0

        os.close(h_info["fd"])
        rel = h_info["path"]
        staging_path = h_info["staging_path"]

        if h_info["writing"] and os.path.isfile(staging_path) and not self.read_only:
            try:
                f_size = os.path.getsize(staging_path)
                f_mtime = os.path.getmtime(staging_path)
            except OSError:
                f_size = 0
                f_mtime = time.time()

            # Asynchronous background encryption to USB: caller returns immediately at RAM speed
            num_chunks = max(1, (f_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
            self.tracker.add_work(num_chunks)
            try:
                task = self._executor.submit(self._async_encrypt_to_usb, rel, staging_path, f_size, f_mtime)
                with self._lock:
                    self._pending_tasks.add(task)
                    task.add_done_callback(lambda t: self._pending_tasks.discard(t))
            except RuntimeError:
                # Executor shutting down during unmount; flush synchronously
                self._async_encrypt_to_usb(rel, staging_path, f_size, f_mtime)

        return 0

    def _async_encrypt_to_usb(self, rel: str, staging_path: str, f_size: int, f_mtime: float):
        if not os.path.isfile(staging_path):
            self.tracker.file_done()
            return

        try:
            sha256 = hashlib.sha256()
            with open(staging_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            sha_hex = sha256.hexdigest()

            file_id = uuid.uuid4().hex
            enc_rel = VaultManager._get_encrypted_rel_path(self.mvk, rel, file_id)
            dst_enc = os.path.join(VaultManager.get_data_dir(self.drive_path), enc_rel)
            os.makedirs(os.path.dirname(dst_enc), exist_ok=True)
            file_key = derive_file_key(self.mvk, file_id)

            encrypt_file(
                staging_path,
                dst_enc,
                file_key,
                chunk_callback=lambda idx, sz: self.tracker.chunk_done(),
            )

            with self._lock:
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
                    "sha256": sha_hex,
                    "encrypted_at": time.time(),
                }
                self._manifest_dirty = True
                self._manifest_write_count += 1
                self.flush_manifest(force=False)
        except Exception as e:
            print(f"[Crypton FUSE Async Encrypt Error] {rel}: {e}", file=sys.stderr)
        finally:
            self.tracker.file_done()

    def get_flush_status(self) -> dict:
        return self.tracker.get_flush_status()


class VaultMountService:
    """Manages background FUSE mount lifecycle."""

    _active_fs: Optional[CryptonFS] = None

    @classmethod
    def update_ram_limit(cls, limit_mb: int):
        """Update active filesystem RAM threshold if mounted."""
        if cls._active_fs:
            cls._active_fs.update_ram_limit(limit_mb)

    @classmethod
    def get_flush_status(cls) -> dict:
        if cls._active_fs:
            return cls._active_fs.get_flush_status()
        return {"is_flushing": False, "progress_pct": 100.0, "pending_chunks": 0, "active_files": 0}

    @staticmethod
    def get_default_mountpoint(drive_path: str) -> str:
        mount_dir = os.path.join(drive_path, "Vault_Unlocked")
        return mount_dir

    @classmethod
    def mount(
        cls,
        drive_path: str,
        mvk: bytes,
        mountpoint: Optional[str] = None,
        read_only: bool = False,
    ) -> tuple[str, threading.Thread]:
        if FUSE is None:
            raise RuntimeError("FUSE is not installed on this system.")

        if not mountpoint:
            mountpoint = cls.get_default_mountpoint(drive_path)

        os.makedirs(mountpoint, exist_ok=True)

        fs = CryptonFS(drive_path, mvk, read_only=read_only)
        cls._active_fs = fs

        def runner():
            try:
                FUSE(fs, mountpoint, foreground=True, nothreads=True, ro=read_only)
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
            except Exception as e:
                print(f"[Crypton FUSE Cleanup Error] {e}", file=sys.stderr)
            cls._active_fs = None

        if not mountpoint or not os.path.exists(mountpoint):
            return True

        # Unmount commands: standard unmount followed by lazy unmount (-z) if busy
        cmds = [
            ["fusermount3", "-u", mountpoint],
            ["fusermount3", "-u", "-z", mountpoint],
            ["fusermount", "-u", mountpoint],
            ["fusermount", "-u", "-z", mountpoint],
            ["umount", mountpoint],
            ["umount", "-l", mountpoint],
        ]
        for cmd in cmds:
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=5)
                if res.returncode == 0:
                    break
            except (subprocess.SubprocessError, FileNotFoundError):
                continue

        # Wait up to 3 seconds for OS kernel to release the mount point
        for _ in range(30):
            if not os.path.ismount(mountpoint):
                break
            time.sleep(0.1)

        # Clean empty mountpoint folder with retry delay for kernel release
        for _ in range(15):
            try:
                if os.path.isdir(mountpoint) and not os.listdir(mountpoint):
                    os.rmdir(mountpoint)
                    break
            except OSError:
                pass
            time.sleep(0.1)

        return not os.path.ismount(mountpoint)
