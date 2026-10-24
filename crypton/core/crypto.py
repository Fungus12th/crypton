import io
import os
import struct
import threading
from typing import BinaryIO, Tuple, Optional, Callable
import argon2
from argon2.low_level import Type as ArgonType
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Constants for Argon2id parameters
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 65536  # 64 MB
DEFAULT_PARALLELISM = 4
KEY_LEN = 32  # 256 bits
SALT_LEN = 16
NONCE_LEN = 12
CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


def derive_kek(
    password: str,
    salt: bytes,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    """Derive a 256-bit Key Encryption Key (KEK) using Argon2id."""
    return argon2.low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=ArgonType.ID,
    )


def wrap_key(master_key: bytes, kek: bytes) -> Tuple[bytes, bytes]:
    """Wrap (encrypt) the Master Vault Key with the KEK using AES-256-GCM.
    
    Returns:
        (nonce: 12 bytes, wrapped_key_with_tag: 48 bytes)
    """
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(kek)
    wrapped = aesgcm.encrypt(nonce, master_key, None)
    return nonce, wrapped


def unwrap_key(nonce: bytes, wrapped_key: bytes, kek: bytes) -> bytes:
    """Unwrap (decrypt) the Master Vault Key. Raises InvalidTag if password is wrong."""
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, wrapped_key, None)


def derive_file_key(master_key: bytes, file_id: str) -> bytes:
    """Derive an independent 256-bit File Encryption Key (FEK) using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=file_id.encode("utf-8"),
    )
    return hkdf.derive(master_key)


def _make_chunk_nonce(base_nonce: bytes, chunk_idx: int) -> bytes:
    """Combine 8-byte base prefix with 4-byte chunk index for a unique 12-byte IV."""
    return base_nonce[:8] + struct.pack(">I", chunk_idx)


def encrypt_stream(
    in_file: BinaryIO,
    out_file: BinaryIO,
    file_key: bytes,
    chunk_size: int = CHUNK_SIZE,
    chunk_callback: Optional[Callable[[int, int], None]] = None,
) -> int:
    """Encrypt in_file to out_file using chunked AES-256-GCM.
    
    File layout:
      [8-byte base nonce prefix]
      Repeat:
        [4-byte chunk_idx][1-byte is_last][4-byte payload_len]
        [ciphertext + 16-byte tag]
    
    Returns:
        Total bytes of plaintext encrypted.
    """
    aesgcm = AESGCM(file_key)
    base_nonce = os.urandom(8)
    out_file.write(base_nonce)

    chunk_idx = 0
    total_plaintext_bytes = 0
    current_chunk = in_file.read(chunk_size)

    while True:
        total_plaintext_bytes += len(current_chunk)
        next_chunk = in_file.read(chunk_size)
        is_last = 1 if not next_chunk else 0

        chunk_nonce = _make_chunk_nonce(base_nonce, chunk_idx)
        aad = struct.pack(">IB", chunk_idx, is_last)
        encrypted_chunk = aesgcm.encrypt(chunk_nonce, current_chunk, aad)

        out_file.write(struct.pack(">IBI", chunk_idx, is_last, len(encrypted_chunk)))
        out_file.write(encrypted_chunk)

        if chunk_callback:
            try:
                chunk_callback(chunk_idx, len(encrypted_chunk))
            except Exception:
                pass

        if is_last:
            break

        current_chunk = next_chunk
        chunk_idx += 1

    return total_plaintext_bytes


def decrypt_stream(in_file: BinaryIO, out_file: BinaryIO, file_key: bytes) -> int:
    """Decrypt in_file to out_file using chunked AES-256-GCM.
    
    Verifies chunk indices and prevents truncation/reordering attacks.
    Returns:
        Total bytes of plaintext written.
    """
    aesgcm = AESGCM(file_key)
    base_nonce = in_file.read(8)
    if len(base_nonce) < 8:
        raise ValueError("Invalid or corrupted encrypted file: missing header.")

    expected_chunk_idx = 0
    total_plaintext_bytes = 0

    while True:
        header = in_file.read(9)  # 4-byte chunk_idx, 1-byte is_last, 4-byte length
        if not header:
            raise ValueError("Corrupted encrypted file: unexpected EOF before final chunk.")
        if len(header) < 9:
            raise ValueError("Corrupted encrypted file: truncated chunk header.")

        chunk_idx, is_last, chunk_len = struct.unpack(">IBI", header)
        if chunk_idx != expected_chunk_idx:
            raise ValueError(f"Chunk order violation! Expected {expected_chunk_idx}, got {chunk_idx}")

        encrypted_chunk = in_file.read(chunk_len)
        if len(encrypted_chunk) < chunk_len:
            raise ValueError("Corrupted encrypted file: truncated chunk payload.")

        chunk_nonce = _make_chunk_nonce(base_nonce, chunk_idx)
        aad = struct.pack(">IB", chunk_idx, is_last)
        plaintext_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, aad)

        out_file.write(plaintext_chunk)
        total_plaintext_bytes += len(plaintext_chunk)

        expected_chunk_idx += 1
        if is_last:
            break

    return total_plaintext_bytes


def encrypt_file(
    src_path: str,
    dst_path: str,
    file_key: bytes,
    chunk_callback: Optional[Callable[[int, int], None]] = None,
) -> int:
    """Encrypt a file from src_path to dst_path with 256KB buffer."""
    os.makedirs(os.path.dirname(os.path.abspath(dst_path)), exist_ok=True)
    with open(src_path, "rb", buffering=256 * 1024) as f_in, open(dst_path, "wb", buffering=256 * 1024) as f_out:
        return encrypt_stream(f_in, f_out, file_key, chunk_callback=chunk_callback)


def decrypt_file(src_path: str, dst_path: str, file_key: bytes) -> int:
    """Decrypt a file from src_path to dst_path with 256KB buffer."""
    os.makedirs(os.path.dirname(os.path.abspath(dst_path)), exist_ok=True)
    with open(src_path, "rb", buffering=256 * 1024) as f_in, open(dst_path, "wb", buffering=256 * 1024) as f_out:
        return decrypt_stream(f_in, f_out, file_key)


def decrypt_chunk(in_file: BinaryIO, file_key: bytes, chunk_idx: int) -> bytes:
    """Decrypt a specific 64 KB chunk directly with O(1) seek."""
    in_file.seek(0)
    base_nonce = in_file.read(8)
    if len(base_nonce) < 8:
        raise ValueError("Invalid encrypted file: missing nonce prefix")

    frame_offset = 8 + chunk_idx * (9 + CHUNK_SIZE + 16)
    in_file.seek(frame_offset)
    hdr = in_file.read(9)
    if len(hdr) < 9:
        return b""

    c_idx, is_last, chunk_len = struct.unpack(">IBI", hdr)
    encrypted_chunk = in_file.read(chunk_len)
    if len(encrypted_chunk) < chunk_len:
        return b""

    chunk_nonce = _make_chunk_nonce(base_nonce, c_idx)
    aad = struct.pack(">IB", c_idx, is_last)
    aesgcm = AESGCM(file_key)
    return aesgcm.decrypt(chunk_nonce, encrypted_chunk, aad)


class VaultStreamReader(io.RawIOBase):
    """Seekable on-demand decrypting reader over a chunked AES-256-GCM file.
    
    Streams bytes to WSGI / HTTP Range requests without unpacking the whole file.
    """

    def __init__(self, enc_path: str, file_key: bytes, file_size: int):
        super().__init__()
        self.enc_path = enc_path
        self.file_key = file_key
        self.file_size = int(file_size)
        self._pos = 0
        self._f = open(enc_path, "rb")
        self._f.seek(0)
        self._base_nonce = self._f.read(8)
        self._aesgcm = AESGCM(file_key)
        self._cached_chunk_idx: Optional[int] = None
        self._cached_chunk_data: bytes = b""

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == os.SEEK_END:
            new_pos = self.file_size + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")
        self._pos = max(0, min(self.file_size, new_pos))
        return self._pos

    def _get_chunk(self, chunk_idx: int) -> bytes:
        if self._cached_chunk_idx == chunk_idx:
            return self._cached_chunk_data

        frame_offset = 8 + chunk_idx * (9 + CHUNK_SIZE + 16)
        self._f.seek(frame_offset)
        hdr = self._f.read(9)
        if len(hdr) < 9:
            return b""
        c_idx, is_last, chunk_len = struct.unpack(">IBI", hdr)
        encrypted_chunk = self._f.read(chunk_len)
        if len(encrypted_chunk) < chunk_len:
            return b""

        chunk_nonce = _make_chunk_nonce(self._base_nonce, c_idx)
        aad = struct.pack(">IB", c_idx, is_last)
        decrypted = self._aesgcm.decrypt(chunk_nonce, encrypted_chunk, aad)

        self._cached_chunk_idx = chunk_idx
        self._cached_chunk_data = decrypted
        return decrypted

    def readinto(self, b) -> int:
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self.file_size:
            return b""

        if size is None or size < 0:
            bytes_to_read = self.file_size - self._pos
        else:
            bytes_to_read = min(size, self.file_size - self._pos)

        if bytes_to_read <= 0:
            return b""

        out = bytearray()
        remaining = bytes_to_read

        while remaining > 0 and self._pos < self.file_size:
            chunk_idx = self._pos // CHUNK_SIZE
            offset_in_chunk = self._pos % CHUNK_SIZE
            chunk_data = self._get_chunk(chunk_idx)
            if not chunk_data or offset_in_chunk >= len(chunk_data):
                break

            take = min(remaining, len(chunk_data) - offset_in_chunk)
            out.extend(chunk_data[offset_in_chunk : offset_in_chunk + take])
            self._pos += take
            remaining -= take

        return bytes(out)

    def close(self):
        try:
            if hasattr(self, "_f") and self._f and not self._f.closed:
                self._f.close()
        finally:
            super().close()


class FlushTracker:
    """Thread-safe write queue tracker for real-time USB flush status telemetry."""

    def __init__(self):
        self._lock = threading.RLock()
        self.total_chunks_queued = 0
        self.chunks_completed = 0
        self.active_files_pending = 0

    def add_work(self, num_chunks: int):
        with self._lock:
            self.total_chunks_queued += max(1, num_chunks)
            self.active_files_pending += 1

    def chunk_done(self):
        with self._lock:
            self.chunks_completed += 1
            if self.chunks_completed >= self.total_chunks_queued and self.active_files_pending == 0:
                self.reset()

    def file_done(self):
        with self._lock:
            self.active_files_pending = max(0, self.active_files_pending - 1)
            if self.chunks_completed >= self.total_chunks_queued and self.active_files_pending == 0:
                self.reset()

    def reset(self):
        with self._lock:
            self.total_chunks_queued = 0
            self.chunks_completed = 0
            self.active_files_pending = 0

    def get_flush_status(self) -> dict:
        with self._lock:
            pending = max(0, self.total_chunks_queued - self.chunks_completed)
            is_flushing = pending > 0 or self.active_files_pending > 0
            if not is_flushing or self.total_chunks_queued == 0:
                return {
                    "is_flushing": False,
                    "progress_pct": 100.0,
                    "pending_chunks": 0,
                    "active_files": 0,
                }
            pct = round((self.chunks_completed / max(1, self.total_chunks_queued)) * 100, 1)
            return {
                "is_flushing": True,
                "progress_pct": min(99.9, pct),
                "pending_chunks": pending,
                "active_files": self.active_files_pending,
            }
