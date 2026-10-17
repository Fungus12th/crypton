import os
import struct
from typing import BinaryIO, Tuple
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


def encrypt_file(src_path: str, dst_path: str, file_key: bytes) -> int:
    """Encrypt a file from src_path to dst_path with 256KB buffer."""
    os.makedirs(os.path.dirname(os.path.abspath(dst_path)), exist_ok=True)
    with open(src_path, "rb", buffering=256 * 1024) as f_in, open(dst_path, "wb", buffering=256 * 1024) as f_out:
        return encrypt_stream(f_in, f_out, file_key)


def decrypt_file(src_path: str, dst_path: str, file_key: bytes) -> int:
    """Decrypt a file from src_path to dst_path with 256KB buffer."""
    os.makedirs(os.path.dirname(os.path.abspath(dst_path)), exist_ok=True)
    with open(src_path, "rb", buffering=256 * 1024) as f_in, open(dst_path, "wb", buffering=256 * 1024) as f_out:
        return decrypt_stream(f_in, f_out, file_key)
