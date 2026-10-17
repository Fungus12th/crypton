import json
import os
import time
import uuid
import hashlib
import hmac
import threading
from typing import Dict, Any, List, Optional, Callable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from crypton.core.crypto import (
    derive_kek,
    wrap_key,
    unwrap_key,
    derive_file_key,
    encrypt_file,
    decrypt_file,
    SALT_LEN,
    KEY_LEN,
    DEFAULT_TIME_COST,
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
)
from crypton.core.header import VaultHeader

CRYPTON_DIR = ".crypton"
HEADER_NAME = "vault.header"
DATA_DIR = "data"
MANIFEST_NAME = "manifest.enc"
README_NAME = "README_HOW_TO_UNLOCK.txt"

README_TEXT = """=============================================================
                  CRYPTON SECURE USB VAULT
=============================================================
This drive is protected with Crypton encryption.

To unlock your files:
- On Linux: Run './crypton-linux unlock .' or use the Crypton GUI.
- On Windows: Run 'crypton-windows.exe unlock .'
- On CLI: Use 'crypton unlock <mount_path>'

Your files are encrypted using Argon2id and AES-256-GCM.
Never delete the '.crypton' directory or your data will be lost!
=============================================================
"""


class VaultError(Exception):
    """Base exception for Crypton vault operations."""
    pass


class InvalidPasswordError(VaultError):
    """Raised when password verification fails."""
    pass


class VaultManager:
    @staticmethod
    def get_crypton_dir(drive_path: str) -> str:
        return os.path.join(drive_path, CRYPTON_DIR)

    @staticmethod
    def get_header_path(drive_path: str) -> str:
        return os.path.join(drive_path, CRYPTON_DIR, HEADER_NAME)

    @staticmethod
    def get_data_dir(drive_path: str) -> str:
        return os.path.join(drive_path, CRYPTON_DIR, DATA_DIR)

    @staticmethod
    def get_manifest_path(drive_path: str) -> str:
        return os.path.join(drive_path, CRYPTON_DIR, MANIFEST_NAME)

    @classmethod
    def is_vault(cls, drive_path: str) -> bool:
        """Check if the given directory contains a Crypton vault."""
        header_path = cls.get_header_path(drive_path)
        return os.path.isfile(header_path)

    @classmethod
    def get_settings(cls, drive_path: str) -> Dict[str, Any]:
        """Load user developer/performance settings from vault."""
        settings_path = os.path.join(cls.get_crypton_dir(drive_path), "settings.json")
        default_settings = {
            "ram_limit_mb": 32,
            "argon2_memory_kb": DEFAULT_MEMORY_COST,
            "argon2_time_cost": DEFAULT_TIME_COST,
        }
        if os.path.isfile(settings_path):
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    default_settings.update(data)
            except Exception:
                pass
        return default_settings

    @classmethod
    def save_settings(cls, drive_path: str, settings: Dict[str, Any]) -> None:
        """Persist user developer/performance settings to vault."""
        os.makedirs(cls.get_crypton_dir(drive_path), exist_ok=True)
        settings_path = os.path.join(cls.get_crypton_dir(drive_path), "settings.json")
        try:
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
        except Exception:
            pass

    @classmethod
    def init_vault(
        cls,
        drive_path: str,
        password: str,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> VaultHeader:
        """Initialize a new Crypton vault on the target drive."""
        header_path = cls.get_header_path(drive_path)
        if os.path.exists(header_path):
            raise VaultError("A Crypton vault already exists at this location.")

        data_dir = cls.get_data_dir(drive_path)
        os.makedirs(data_dir, exist_ok=True)

        # 1. Generate 256-bit Master Vault Key (MVK)
        mvk = os.urandom(KEY_LEN)

        # 2. Derive KEK via Argon2id
        salt = os.urandom(SALT_LEN)
        kek = derive_kek(password, salt, time_cost, memory_cost, parallelism)

        # 3. Wrap MVK with KEK
        mvk_nonce, wrapped_mvk = wrap_key(mvk, kek)

        header = VaultHeader(
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            mvk_nonce=mvk_nonce,
            wrapped_mvk=wrapped_mvk,
            created_at=time.time(),
        )

        # Save header
        with open(header_path, "wb") as f:
            f.write(header.serialize())

        # Write initial empty manifest
        cls._save_manifest(drive_path, mvk, {})

        # Write unlock instructions
        readme_path = os.path.join(drive_path, README_NAME)
        if not os.path.exists(readme_path):
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(README_TEXT)

        return header

    @classmethod
    def unlock_vault(cls, drive_path: str, password: str) -> bytes:
        """Verify password and return decrypted Master Vault Key (MVK) in RAM."""
        header_path = cls.get_header_path(drive_path)
        if not os.path.isfile(header_path):
            raise VaultError(f"No Crypton vault found at '{drive_path}'.")

        with open(header_path, "rb") as f:
            data = f.read()

        header = VaultHeader.deserialize(data)
        kek = derive_kek(
            password=password,
            salt=header.salt,
            time_cost=header.time_cost,
            memory_cost=header.memory_cost,
            parallelism=header.parallelism,
        )

        try:
            mvk = unwrap_key(header.mvk_nonce, header.wrapped_mvk, kek)
        except InvalidTag:
            raise InvalidPasswordError("Incorrect password or corrupted vault header.")

        return mvk

    @classmethod
    def change_password(cls, drive_path: str, old_password: str, new_password: str) -> None:
        """Instantly change password by re-wrapping the MVK (<100ms)."""
        mvk = cls.unlock_vault(drive_path, old_password)
        header_path = cls.get_header_path(drive_path)
        
        with open(header_path, "rb") as f:
            old_header = VaultHeader.deserialize(f.read())

        # Derive new KEK with fresh salt
        new_salt = os.urandom(SALT_LEN)
        new_kek = derive_kek(
            password=new_password,
            salt=new_salt,
            time_cost=old_header.time_cost,
            memory_cost=old_header.memory_cost,
            parallelism=old_header.parallelism,
        )

        new_nonce, new_wrapped_mvk = wrap_key(mvk, new_kek)
        new_header = VaultHeader(
            salt=new_salt,
            time_cost=old_header.time_cost,
            memory_cost=old_header.memory_cost,
            parallelism=old_header.parallelism,
            mvk_nonce=new_nonce,
            wrapped_mvk=new_wrapped_mvk,
            created_at=old_header.created_at,
            wrapped_cloud_token=old_header.wrapped_cloud_token,
        )

        # Atomic write for header
        tmp_header = header_path + ".tmp"
        with open(tmp_header, "wb") as f:
            f.write(new_header.serialize())
        os.replace(tmp_header, header_path)

    @classmethod
    def _manifest_key(cls, mvk: bytes) -> bytes:
        return derive_file_key(mvk, "crypton_vault_manifest_v1")

    @classmethod
    def _load_manifest(cls, drive_path: str, mvk: bytes) -> Dict[str, Any]:
        manifest_path = cls.get_manifest_path(drive_path)
        if not os.path.isfile(manifest_path):
            return {}

        with open(manifest_path, "rb") as f:
            data = f.read()

        if len(data) < 12:
            return {}

        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(cls._manifest_key(mvk))
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, json.JSONDecodeError):
            raise VaultError("Failed to decrypt or parse vault manifest.")

    @classmethod
    def _save_manifest(cls, drive_path: str, mvk: bytes, manifest: Dict[str, Any]) -> None:
        manifest_path = cls.get_manifest_path(drive_path)
        nonce = os.urandom(12)
        aesgcm = AESGCM(cls._manifest_key(mvk))
        plaintext = json.dumps(manifest, indent=2).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        tmp_path = manifest_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(nonce + ciphertext)
        os.replace(tmp_path, manifest_path)

    @classmethod
    def list_files(cls, drive_path: str, mvk: bytes) -> List[Dict[str, Any]]:
        """List all files recorded in the encrypted vault manifest."""
        manifest = cls._load_manifest(drive_path, mvk)
        return list(manifest.values())

    @classmethod
    def _hash_folder_name(cls, mvk: bytes, folder_name: str) -> str:
        """Derive an obfuscated directory name for disk storage."""
        h = hmac.new(mvk, folder_name.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()[:16]

    @classmethod
    def _get_encrypted_rel_path(cls, mvk: bytes, vault_rel_path: str, file_id: str) -> str:
        """Generate an obfuscated disk path preserving folder hierarchy."""
        parts = vault_rel_path.strip("/").split("/")
        if len(parts) > 1:
            hashed_dirs = [cls._hash_folder_name(mvk, p) for p in parts[:-1]]
            return os.path.join(*hashed_dirs, file_id)
        return file_id

    @classmethod
    def add_file(
        cls,
        drive_path: str,
        mvk: bytes,
        src_file_path: str,
        vault_rel_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Encrypt and import an external file into the vault."""
        if not os.path.isfile(src_file_path):
            raise FileNotFoundError(f"Source file not found: {src_file_path}")

        if not vault_rel_path:
            vault_rel_path = os.path.basename(src_file_path)

        # Standardize path separators
        vault_rel_path = vault_rel_path.replace("\\", "/").lstrip("/")

        file_id = uuid.uuid4().hex
        enc_rel = cls._get_encrypted_rel_path(mvk, vault_rel_path, file_id)
        dst_encrypted_path = os.path.join(cls.get_data_dir(drive_path), enc_rel)
        os.makedirs(os.path.dirname(dst_encrypted_path), exist_ok=True)

        # Derive unique file key
        file_key = derive_file_key(mvk, file_id)

        # Compute SHA-256 hash of original file for integrity / sync checking
        sha256 = hashlib.sha256()
        with open(src_file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)

        orig_size = os.path.getsize(src_file_path)
        orig_mtime = os.path.getmtime(src_file_path)

        # Encrypt with chunked AES-GCM
        encrypt_file(src_file_path, dst_encrypted_path, file_key)

        record = {
            "file_id": file_id,
            "enc_rel_path": enc_rel,
            "rel_path": vault_rel_path,
            "size": orig_size,
            "mtime": orig_mtime,
            "sha256": sha256.hexdigest(),
            "encrypted_at": time.time(),
        }

        # Update manifest
        manifest = cls._load_manifest(drive_path, mvk)
        manifest[vault_rel_path] = record
        cls._save_manifest(drive_path, mvk, manifest)

        return record

    @classmethod
    def extract_file(
        cls,
        drive_path: str,
        mvk: bytes,
        vault_rel_path: str,
        dest_path: str,
    ) -> None:
        """Decrypt a file from the vault to the destination path."""
        vault_rel_path = vault_rel_path.replace("\\", "/").lstrip("/")
        manifest = cls._load_manifest(drive_path, mvk)

        if vault_rel_path not in manifest:
            raise FileNotFoundError(f"File '{vault_rel_path}' not found in vault.")

        record = manifest[vault_rel_path]
        file_id = record["file_id"]
        enc_rel = record.get("enc_rel_path", file_id)
        encrypted_path = os.path.join(cls.get_data_dir(drive_path), enc_rel)

        if not os.path.isfile(encrypted_path):
            flat_path = os.path.join(cls.get_data_dir(drive_path), file_id)
            if os.path.isfile(flat_path):
                encrypted_path = flat_path
            else:
                raise VaultError(f"Corrupted vault: Encrypted data missing for '{vault_rel_path}'")

        file_key = derive_file_key(mvk, file_id)
        decrypt_file(encrypted_path, dest_path, file_key)

        # Restore original mtime if available
        if "mtime" in record:
            os.utime(dest_path, (record["mtime"], record["mtime"]))

    @classmethod
    def add_folder(
        cls,
        drive_path: str,
        mvk: bytes,
        src_dir_path: str,
        vault_base_rel: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str, int, int], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> List[Dict[str, Any]]:
        """Recursively encrypt and import an entire folder tree into the vault with live progress & cancellation."""
        if not os.path.isdir(src_dir_path):
            raise NotADirectoryError(f"Source folder not found: {src_dir_path}")

        src_dir_path = os.path.abspath(src_dir_path)
        base_parent = os.path.dirname(src_dir_path)

        # 1. Pre-scan total files and total bytes
        all_files = []
        total_bytes = 0
        for root, _, files in os.walk(src_dir_path):
            for file in files:
                full_src = os.path.join(root, file)
                try:
                    f_size = os.path.getsize(full_src)
                    all_files.append((full_src, f_size))
                    total_bytes += f_size
                except OSError:
                    continue

        total_files = len(all_files)
        manifest = cls._load_manifest(drive_path, mvk)
        records = []
        bytes_processed = 0

        for idx, (full_src, f_size) in enumerate(all_files, start=1):
            if cancel_event and cancel_event.is_set():
                break

            rel_to_parent = os.path.relpath(full_src, base_parent).replace("\\", "/").lstrip("/")
            vault_rel = os.path.join(vault_base_rel, rel_to_parent).replace("\\", "/").lstrip("/") if vault_base_rel else rel_to_parent

            if progress_callback:
                progress_callback(idx, total_files, vault_rel, bytes_processed, total_bytes)

            file_id = uuid.uuid4().hex
            enc_rel = cls._get_encrypted_rel_path(mvk, vault_rel, file_id)
            dst_encrypted_path = os.path.join(cls.get_data_dir(drive_path), enc_rel)
            os.makedirs(os.path.dirname(dst_encrypted_path), exist_ok=True)
            file_key = derive_file_key(mvk, file_id)

            sha256 = hashlib.sha256()
            with open(full_src, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)

            orig_mtime = os.path.getmtime(full_src)
            encrypt_file(full_src, dst_encrypted_path, file_key)

            record = {
                "file_id": file_id,
                "enc_rel_path": enc_rel,
                "rel_path": vault_rel,
                "size": f_size,
                "mtime": orig_mtime,
                "sha256": sha256.hexdigest(),
                "encrypted_at": time.time(),
            }
            manifest[vault_rel] = record
            records.append(record)
            bytes_processed += f_size

            # Incremental checkpoint: save manifest every 10 files (or final) so interruptions don't lose work
            if idx % 10 == 0:
                cls._save_manifest(drive_path, mvk, manifest)

        cls._save_manifest(drive_path, mvk, manifest)
        return records

    @classmethod
    def extract_path(
        cls,
        drive_path: str,
        mvk: bytes,
        vault_rel_path: str,
        dest_dir: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> tuple[int, List[str]]:
        """Extract a single file OR an entire folder hierarchy. Returns (extracted_count, missing_files)."""
        vault_rel_path = vault_rel_path.replace("\\", "/").lstrip("/")
        manifest = cls._load_manifest(drive_path, mvk)

        target_files = []
        if vault_rel_path in manifest:
            target_files = [(vault_rel_path, os.path.join(dest_dir, os.path.basename(vault_rel_path)))]
        else:
            prefix = vault_rel_path.rstrip("/") + "/"
            matching = [f for f in manifest.keys() if f.startswith(prefix)]
            if not matching:
                raise FileNotFoundError(f"No file or folder matching '{vault_rel_path}' found in vault.")
            for rel in matching:
                sub_rel = rel[len(prefix):]
                target_out = os.path.join(dest_dir, os.path.basename(vault_rel_path.rstrip("/")), sub_rel)
                target_files.append((rel, target_out))

        total = len(target_files)
        count = 0
        missing = []

        for idx, (rel, out_path) in enumerate(target_files, start=1):
            if cancel_event and cancel_event.is_set():
                break

            if progress_callback:
                progress_callback(idx, total, rel)

            try:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                cls.extract_file(drive_path, mvk, rel, out_path)
                count += 1
            except VaultError as e:
                missing.append(rel)

        return count, missing

    @classmethod
    def delete_path(cls, drive_path: str, mvk: bytes, vault_rel_path: str) -> int:
        """Delete a file or entire folder from the vault and disk cleanly."""
        vault_rel_path = vault_rel_path.replace("\\", "/").lstrip("/")
        manifest = cls._load_manifest(drive_path, mvk)

        to_delete = []
        if vault_rel_path in manifest:
            to_delete = [vault_rel_path]
        else:
            prefix = vault_rel_path.rstrip("/") + "/"
            to_delete = [f for f in manifest.keys() if f.startswith(prefix)]

        if not to_delete:
            return 0

        data_dir = cls.get_data_dir(drive_path)
        deleted_count = 0

        for rel in to_delete:
            record = manifest.pop(rel, None)
            if record:
                enc_rel = record.get("enc_rel_path", record.get("file_id"))
                enc_file = os.path.join(data_dir, enc_rel)
                if os.path.isfile(enc_file):
                    try:
                        os.remove(enc_file)
                    except OSError:
                        pass
                # Check legacy flat path
                flat_file = os.path.join(data_dir, record.get("file_id", ""))
                if os.path.isfile(flat_file):
                    try:
                        os.remove(flat_file)
                    except OSError:
                        pass
                deleted_count += 1

        cls._save_manifest(drive_path, mvk, manifest)
        cls._clean_empty_dirs(data_dir)
        return deleted_count

    @classmethod
    def verify_and_repair_vault(cls, drive_path: str, mvk: bytes) -> Dict[str, Any]:
        """Self-heal the vault by removing manifest entries whose encrypted data blocks are missing."""
        manifest = cls._load_manifest(drive_path, mvk)
        data_dir = cls.get_data_dir(drive_path)

        cleaned_records = []
        for rel_path, record in list(manifest.items()):
            file_id = record.get("file_id", "")
            enc_rel = record.get("enc_rel_path", file_id)
            enc_path = os.path.join(data_dir, enc_rel)
            flat_path = os.path.join(data_dir, file_id)

            if not os.path.isfile(enc_path) and not os.path.isfile(flat_path):
                cleaned_records.append(rel_path)
                del manifest[rel_path]

        if cleaned_records:
            cls._save_manifest(drive_path, mvk, manifest)

        cls._clean_empty_dirs(data_dir)
        return {
            "cleaned_count": len(cleaned_records),
            "cleaned_records": cleaned_records,
            "remaining_files": len(manifest),
        }

    @classmethod
    def _clean_empty_dirs(cls, directory: str) -> None:
        """Recursively remove empty subdirectories."""
        for root, dirs, _ in os.walk(directory, topdown=False):
            for d in dirs:
                full_d = os.path.join(root, d)
                try:
                    if not os.listdir(full_d):
                        os.rmdir(full_d)
                except OSError:
                    pass


